import logging
import os
import sys
import errno
import time
import heapq
from itertools import groupby

from elliptics_recovery.utils.misc import dump_key_data, load_key_data_from_file

import elliptics

log = logging.getLogger()


class BucketsManager(object):
    '''
    BucketsManager is a single repository of bucket files. It is used by ServerSendRecovery.
    '''
    def __init__(self, ctx):
        self.ctx = ctx
        self.bucket_index = -1
        self.buckets = {}

    def get_next_bucket(self):
        '''
        Every call returns BucketKeys object from buckets list in a round-robin manner starting with the 1st.
        The buckets list contains BucketKeys objects sorted by amount of keys in appropriate bucket.
        '''
        if not self.ctx.bucket_order:
            return None

        self.bucket_index = (self.bucket_index + 1) % len(self.ctx.bucket_order)
        group_id = self.ctx.bucket_order[self.bucket_index]
        log.info("Get next bucket: index: {0}, group_id: {1}, bucket_order: {2}".format(self.bucket_index, group_id, self.ctx.bucket_order))
        return self._get_bucket(group_id)

    def on_server_send_fail(self, key, original_key_infos, next_group_id):
        '''
        This method used on failure of recovery of a single @key.
        If @next_group_id is defined, then @key with @original_key_infos moved
        to the bucket corresponding to the @next_group_id, otherwise move them to the
        'rest_keys' bucket that will be used by old recovery process (see dc_recovery.py).
        '''
        if next_group_id >= 0:
            b = self._get_bucket(next_group_id)
            b.add_key(key, original_key_infos)
        else:
            self.move_to_rest_bucket(key, original_key_infos)

    def move_to_rest_bucket(self, key, key_infos):
        '''
        Dumps key to 'rest_keys' bucket.
        '''
        log.info("Moving key to rest keys bucket: {0}".format(key))
        key_data = (key, key_infos)
        dump_key_data(key_data, self.ctx.rest_file)

    def _get_bucket(self, group_id):
        '''
        Returns BucketKeys object for the corresponding @group_id
        '''
        if group_id not in self.buckets:
            if group_id not in self.ctx.bucket_files:
                filename = os.path.join(self.ctx.tmp_dir, 'bucket_%d' % (group_id))
                self.ctx.bucket_files[group_id] = open(filename, 'wb+')
                self.ctx.bucket_order.append(group_id)
            self.buckets[group_id] = BucketKeys(self.ctx.bucket_files[group_id], group_id)
        return self.buckets[group_id]


class BucketKeys(object):
    '''
    BucketKeys provides simple container-like interface to a bucket file.
    '''
    def __init__(self, bucket_file, group_id):
        log.debug("Create bucket: group_id: {0}, bucket: {1}".format(group_id, bucket_file.name))
        self.bucket_file = bucket_file
        self.group_id = group_id

    def sort_by_physical_order(self):
        chunk_files = []
        try:
            log.info("Sort bucket: phase 1: sort chunks: group_id: {0}, bucket: {1}"
                     .format(self.group_id, self.bucket_file.name))
            max_chunks_size = 500 * 1024 * 1024 # 500 Mb

            chunk = []
            chunk_size = 0

            self.bucket_file.seek(0)
            for key_data in load_key_data_from_file(self.bucket_file):
                chunk_size += sys.getsizeof(key_data) + sys.getsizeof(key_data[0]) + sys.getsizeof(key_data[1]) + \
                              sum(sys.getsizeof(info) for info in key_data[1])
                chunk.append((self._get_physical_position(key_data), key_data))
                if chunk_size > max_chunks_size:
                    chunk_size = 0
                    self._sort_chunk(chunk, chunk_files)
            if chunk:
                self._sort_chunk(chunk, chunk_files)

            log.info("Sort bucket: phase 2: merge chunks: group_id: {0}, bucket: {1}"
                     .format(self.group_id, self.bucket_file.name))
            class MergeDataWrapper(object):
                def __init__(self, gen, outer):
                    self.gen = gen
                    self.outer = outer
                    self.next()

                def __cmp__(self, other):
                    return cmp(self.physical_position, other.physical_position)

                def next(self):
                    try:
                        self.key_data = self.gen.next()
                        self.physical_position = self.outer._get_physical_position(self.key_data)
                    except StopIteration:
                        return False
                    return True

            heap = []
            for chunk in chunk_files:
                chunk.seek(0)
                heapq.heappush(heap, MergeDataWrapper(load_key_data_from_file(chunk), self))

            self.bucket_file.seek(0)
            self.bucket_file.truncate()
            while len(heap):
                wrapper = heapq.heappop(heap)
                dump_key_data(wrapper.key_data, self.bucket_file)
                if wrapper.next():
                    heapq.heappush(heap, wrapper)
        finally:
            for f in chunk_files:
                os.unlink(f.name)

    def _get_physical_position(self, key_data):
        for key_info in key_data[1]:
            if key_info.group_id == self.group_id:
                return key_info.blob_id, key_info.data_offset

    def _sort_chunk(self, chunk, chunk_files):
        filename = "{}.{}".format(self.bucket_file.name, len(chunk_files))
        chunk_file = open(filename, 'wb+')
        chunk_files.append(chunk_file)

        chunk.sort(key=lambda k: k[0])

        for _, key_data in chunk:
            dump_key_data(key_data, chunk_file)

        del chunk[:]

    def get_keys(self, max_keys_num):
        '''
        Yields bunch of keys from the bucket file.
        @max_keys_num defines max number of keys in the bunch.
        '''
        self.bucket_file.seek(0)
        for _, batch in groupby(enumerate(load_key_data_from_file(self.bucket_file)),
                                key=lambda x: x[0] / max_keys_num):
            yield [item[1] for item in batch]

    def get_group_id(self):
        return self.group_id

    def clear(self):
        '''
        Truncates bucket file.
        '''
        log.debug("Clear bucket: group_id: {0}, bucket: {1}".format(self.group_id, self.bucket_file.name))
        self.bucket_file.seek(0)
        self.bucket_file.truncate()

    def add_key(self, key, key_infos):
        '''
        Dumps key to the bucket file.
        '''
        log.debug("Append key to bucket: group_id: {0}, bucket: {1}".format(self.group_id, self.bucket_file.name))
        key_data = (key, key_infos)
        dump_key_data(key_data, self.bucket_file)


class ServerSendRecovery(object):
    '''
    ServerSendRecovery uses server_send operation for efficient recovering of small/medium keys.
    '''
    def __init__(self, ctx, node):
        self.ctx = ctx
        self.stats = ctx.stats['recover']
        self.stats_cmd = ctx.stats['commands']
        self.node = node
        self.buckets = BucketsManager(ctx)

        self.session = elliptics.newapi.Session(node)
        self.session.trace_id = ctx.trace_id
        self.session.exceptions_policy = elliptics.exceptions_policy.no_exceptions
        self.session.timeout = 60

        self.remove_session = self.session.clone()
        self.remove_session.set_filter(elliptics.filters.all_final)
        self.remove_session.ioflags |= elliptics.io_flags.cas_timestamp
        self.remove_session.timestamp = ctx.prepare_timeout

        self.result = True

        # next vars are used just for optimization
        self.groups_set = frozenset(ctx.groups)

    def recover(self):
        progress = True
        while progress:
            bucket = self.buckets.get_next_bucket()
            if bucket is None:
                break
            bucket.sort_by_physical_order()
            group_id = bucket.get_group_id()
            progress = False
            for keys in bucket.get_keys(self.ctx.batch_size):
                progress = True
                self._server_send(keys, group_id)
            bucket.clear()
        return self.result

    def _server_send(self, keys, group_id):
        '''
        Recovers bunch of newest @keys from replica with appropriate @group_id to other replicas via server-send.
        '''
        log.info("Server-send bucket: source group_id: {0}, num keys: {1}".format(group_id, len(keys)))
        keys_bunch = {}  # (tuple of remote groups) -> [list of newest keys]
        for key, key_infos in keys:
            unprocessed_key_infos = self._get_unprocessed_key_infos(key_infos, group_id)

            dest_groups = self._get_dest_groups(key_infos)
            index = frozenset(dest_groups)
            if index not in keys_bunch:
                keys_bunch[index] = []
            keys_bunch[index].append((key, key_infos, unprocessed_key_infos[0].size))

        for b in keys_bunch.iteritems():
            remote_groups = b[0]
            newest_keys = []
            key_infos_map = {}
            batch_size = 0
            for key, key_infos, key_size in b[1]:
                log.debug("Prepare server-send key: {0}, group_id: {1}".format(key, key.group_id))
                newest_keys.append(key)
                key_infos_map[str(key)] = key_infos
                batch_size += key_size

            self.session.timeout = max(60, batch_size / self.ctx.data_flow_rate)
            timeouted_keys = None
            for i in range(self.ctx.attempts):
                if newest_keys:
                    self.stats.counter('server_send' if i == 0 else 'server_send_retry', 1)
                    if i > 0:
                        self.ctx.stats.counter('retry_recover_keys', len(timeouted_keys))
                    log.info("Server-send: group_id: %s, remote_groups: %s, num_keys: %s", group_id, remote_groups,
                             len(newest_keys))
                    dst_groups = []
                    for group in remote_groups:
                        if group in self.ctx.ro_groups:
                            self.stats.counter('skip_server_send_to_ro_group', len(newest_keys))
                            continue
                        dst_groups.append(group)
                    if not dst_groups:
                        # if all remote_groups are readonly, skip server_send at all
                        break
                    iterator = self.session.server_send(keys=newest_keys,
                                                        flags=0,
                                                        chunk_size=self.ctx.chunk_size,
                                                        src_group=group_id,
                                                        dst_groups=dst_groups,
                                                        chunk_write_timeout=self.ctx.chunk_write_timeout,
                                                        chunk_commit_timeout=self.ctx.chunk_commit_timeout,
                                                        chunk_retry_count=self.ctx.attempts - 1,
                                                        )
                    timeouted_keys, corrupted_keys = self._check_server_send_results(iterator, key_infos_map, group_id)
                    newest_keys = timeouted_keys
                    if corrupted_keys:
                        self._remove_corrupted_keys(corrupted_keys, group_id)

            if timeouted_keys:
                self._on_server_send_timeout(timeouted_keys, key_infos_map, group_id)

    def _check_server_send_results(self, iterator, key_infos_map, group_id):
        '''
        Check result of remote sending for every key.
        Returns lists of timeouted keys and corrupted keys.
        '''
        start_time = time.time()
        recovers_in_progress = len(key_infos_map)

        timeouted_keys = []
        corrupted_keys = []
        succeeded_keys = set()
        index = 0
        for index, result in enumerate(iterator, 1):
            status = result.status
            self._update_stats(start_time, index, recovers_in_progress, status)

            key = result.key
            if status < 0:
                key_infos = key_infos_map[str(key)]
                self._on_server_send_fail(status, key, key_infos, timeouted_keys, corrupted_keys, group_id)
                continue
            elif status == 0:
                succeeded_keys.add(str(key))
                log.debug("Recovered key: %s, status %d", result.key, status)

        if index < recovers_in_progress:
            log.error("Server-send operation failed: group_id: %d, received results: %d, expected: %d, error: %s",
                      group_id, index, recovers_in_progress, iterator.error())
            self._update_stats(start_time, index, recovers_in_progress, iterator.error().code)
            timeouted_keys = [elliptics.Id(k) for k in key_infos_map.iterkeys() if k not in succeeded_keys]

        return timeouted_keys, corrupted_keys

    def _on_server_send_timeout(self, keys, key_infos_map, group_id):
        '''
        @keys - is a list of keys that were not recovered due to timeout.
        Moves keys to next bucket, if appropriate bucket meta is identical to current meta,
        because less relevant replica (e.g. with older timestamp) should not be used for
        recovery due to temporary unavailability of relevant replica during recovery process.
        '''
        same_meta = lambda lhs, rhs: (lhs.timestamp, lhs.size, lhs.user_flags) == (rhs.timestamp, rhs.size, rhs.user_flags)
        num_failed_keys = 0
        for key in keys:
            key_infos = key_infos_map[str(key)]
            filtered_key_infos = self._get_unprocessed_key_infos(key_infos, group_id)
            if len(filtered_key_infos) > 1:
                current_meta = filtered_key_infos[0]
                next_meta = filtered_key_infos[1]
                if same_meta(current_meta, next_meta):
                    self.buckets.on_server_send_fail(key, key_infos, next_meta.group_id)
                    continue
            num_failed_keys += 1
            log.error("Key: {0} is not recovered".format(key))

        if num_failed_keys > 0:
            self.result = False
            self._update_timeouted_keys_stats(num_failed_keys)

    def _on_server_send_fail(self, status, key, key_infos, timeouted_keys, corrupted_keys, group_id):
        '''
        Handle single failed @key.
        Timeouted or corrupted @key is added to the corresponding container for further processing.
        If @key is not timeouted, then try to move it to the next bucket without modifying its
        list of meta (@key_infos). Timeouted keys are handled at _on_server_send_timeout().
        '''
        log.error("Failed to server-send key: {0}, group_id: {1}, error: {2}".format(key, group_id, status))

        if status == -errno.ENXIO:
            self.buckets.on_server_send_fail(key, key_infos, -1)
        elif status == -errno.ETIMEDOUT:
            timeouted_keys.append(key)
        else:
            next_group_id = self._get_next_group_id(key_infos, group_id)
            if status in {-errno.EILSEQ, -errno.ERANGE}:
                corrupted_keys.append(key)
                self.ctx.corrupted_keys.write('{key} {group}\n'.format(key=key, group=group_id))
                # forget about corrupted key_info, so this group will be used as a destination for future server-send
                key_infos = [key_info for key_info in key_infos if key_info.group_id != group_id]
            if next_group_id >= 0:
                self.buckets.on_server_send_fail(key, key_infos, next_group_id)
            else:
                log.error("Key: {0} is not recovered".format(key))
                self.result = False

    def _remove_corrupted_keys(self, keys, group_id):
        '''
        Removes invalid keys with invalid checksum.
        '''
        if self.ctx.safe:
            return

        if group_id in self.ctx.ro_groups:
            self.stats.counter('skip_remove_corrupted_key_from_ro_group', 1)
            return

        self.remove_session.groups = [group_id]

        for attempt in range(self.ctx.attempts):
            if not keys:
                break

            results = [self.remove_session.remove(key) for key in keys]

            timeouted_keys = []
            for i, r in enumerate(results):
                status = r.get()[0].status
                log.info('Removed corrupted key: %s, status: %s, attempts: %s/%s',
                         keys[i], status, attempt, self.ctx.attempts)
                if status == 0:
                    self.stats.counter("removed_corrupted_keys", 1)
                elif status in (-errno.ETIMEDOUT, -errno.ENXIO):
                    timeouted_keys.append(keys[i])
            keys = timeouted_keys

    def _get_dest_groups(self, key_infos):
        '''
        Returns list of destination/remote groups to which key must be recovered.
        '''
        missed_groups = list(self.groups_set.difference([k.group_id for k in key_infos]))

        same_meta = lambda lhs, rhs: (lhs.timestamp, lhs.size, lhs.user_flags) == (rhs.timestamp, rhs.size, rhs.user_flags)
        diff_groups = [info.group_id for info in key_infos if not same_meta(info, key_infos[0])]

        missed_groups.extend(diff_groups)
        return missed_groups

    def _get_unprocessed_key_infos(self, original_key_infos, group_id):
        '''
        Each element of @original_key_infos describes key's metadata for a particular group.
        Recovery process successively iterates over elements of @original_key_infos.
        This method returns elements from @original_key_infos that were not processed by
        previous recovery iterations.
        '''
        for i, k in enumerate(original_key_infos):
            if k.group_id == group_id:
                return original_key_infos[i:]
        return []

    def _get_next_group_id(self, key_infos, group_id):
        '''
        Returns group_id among groups that hasn't been used for recovery yet.
        '''
        key_infos = self._get_unprocessed_key_infos(key_infos, group_id)
        if len(key_infos) > 1:
            return key_infos[1].group_id
        return -1

    def _update_stats(self, start_time, processed_keys, recovers_in_progress, status):
        speed = processed_keys / (time.time() - start_time)
        recovers_in_progress -= processed_keys
        self.stats.set_counter('recovery_speed', round(speed, 2))
        self.stats.set_counter('recovers_in_progress', recovers_in_progress)
        if status != -errno.ETIMEDOUT:
            self.stats.counter('recovered_keys', 1 if status == 0 else -1)
            self.ctx.stats.counter('recovered_keys', 1 if status == 0 else -1)
        if status != 0:
            self.stats_cmd.counter('server_send.{0}'.format(status), 1)

    def _update_timeouted_keys_stats(self, num_timeouted_keys):
        self.stats.counter('recovered_keys', -num_timeouted_keys)
        self.ctx.stats.counter('recovered_keys', -num_timeouted_keys)
