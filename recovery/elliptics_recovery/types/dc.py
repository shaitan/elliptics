# =============================================================================
# 2013+ Copyright (c) Kirill Smorodinnikov <shaitkir@gmail.com>
# 2013+ Copyright (c) Alexey Ivanov <rbtz@ph34r.me>
# All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# =============================================================================

import logging
from itertools import groupby
from collections import defaultdict
from ..utils.misc import elliptics_create_node, dump_key_data, KeyInfo, load_key_data
from ..range import IdRange
from ..etime import Time
from ..iterator import Iterator, MergeData, IteratorResult
from ..dc_recovery import recover

import os
import errno
import traceback

import elliptics

log = logging.getLogger(__name__)


def iterate_node(arg):
    ctx, address, backend_id, ranges = arg
    elog = elliptics.Logger(ctx.log_file, int(ctx.log_level), True)
    stats = ctx.stats["iterate"][str(address)][str(backend_id)]
    stats_cmd = ctx.stats['commands']
    stats.timer('process', 'started')
    log.info("Running iterator on node: {0}/{1}".format(address, backend_id))
    log.debug("Ranges:")
    for range in ranges:
        log.debug(repr(range))
    stats.timer('process', 'iterate')

    node_id = ctx.routes.get_address_backend_route_id(address, backend_id)

    node = elliptics_create_node(address=address,
                                 elog=elog,
                                 wait_timeout=ctx.iteration_timeout,
                                 flags=elliptics.config_flags.no_route_list,
                                 net_thread_num=1,
                                 io_thread_num=1)

    try:
        flags = elliptics.iterator_flags.key_range
        timestamp_range = ctx.timestamp.to_etime(), Time.time_max().to_etime()
        if ctx.no_meta:
            flags |= elliptics.iterator_flags.no_meta
        else:
            flags |= elliptics.iterator_flags.ts_range

        log.debug("Running iterator on node: {0}/{1}".format(address, backend_id))
        iterator = Iterator(node, node_id.group_id, separately=True, trace_id=ctx.trace_id)
        results, results_len = iterator.iterate_with_stats(
            eid=node_id,
            timestamp_range=timestamp_range,
            key_ranges=ranges,
            tmp_dir=ctx.tmp_dir,
            address=address,
            backend_id=backend_id,
            group_id=node_id.group_id,
            batch_size=ctx.batch_size,
            stats=stats,
            stats_cmd=stats_cmd,
            flags=flags,
            leave_file=True)

        if results is None:
            return None
        elif results_len == 0:
            return []

    except Exception as e:
        log.error("Iteration failed for node {0}/{1}: {2}, traceback: {3}"
                  .format(address, backend_id, repr(e), traceback.format_exc()))
        return None

    log.debug("Iterator for node {0}/{1} obtained: {2} record(s)"
              .format(address, backend_id, results_len))

    stats.timer('process', 'sort')
    for range_id in results:
        results[range_id].sort()

    stats.timer('process', 'finished')
    return [(range_id, container.filename, container.address, container.backend_id, container.group_id)
            for range_id, container in results.items()]


def transpose_results(results):
    log.debug("Transposing iteration results from all nodes")
    result_tree = defaultdict(list)

    # for each address iterator results
    for iter_result in results:
        # for each range
        for range_id, filepath, address, backend_id, group_id in iter_result:
            # add iterator result to tree
            result_tree[range_id].append((filepath, address, backend_id, group_id))

    return result_tree


def skip_key_data(ctx, key_data):
    '''
    Checks that all groups are presented in key_data and
    all key_datas have equal timestamp and user_flags
    '''
    if ctx.user_flags_set and all(info.user_flags not in ctx.user_flags_set for info in key_data[1]):
        return True

    committed = lambda info: not info.flags & elliptics.record_flags.uncommitted
    count = sum(map(committed, key_data[1]))
    if count < len(ctx.groups):
        return False
    assert count == len(ctx.groups)

    first = key_data[1][0]

    same_meta = lambda lhs, rhs: (lhs.timestamp, lhs.size, lhs.user_flags) == (rhs.timestamp, rhs.size, rhs.user_flags)
    return all(same_meta(info, first) for info in key_data[1])


def merged_results(ctx, results):
    import heapq
    results = [IteratorResult.load_filename(filename=r[0],
                                            address=r[1],
                                            backend_id=r[2],
                                            group_id=r[3],
                                            is_sorted=True,
                                            tmp_dir=ctx.tmp_dir)
               for r in results]

    heap = []
    for r in results:
        try:
            heapq.heappush(heap, MergeData(r, None))
        except StopIteration:
            pass

    while len(heap):
        min_data = heapq.heappop(heap)
        key_data = (min_data.key, [min_data.key_info])
        same_datas = [min_data]
        while len(heap) and min_data.key == heap[0].key:
            key_data[1].append(heap[0].key_info)
            same_datas.append(heapq.heappop(heap))

        # skip keys that already exist and equal in all groups
        if not skip_key_data(ctx, key_data):
            yield key_data

        for i in same_datas:
            try:
                i.next()
                heapq.heappush(heap, i)
            except StopIteration:
                pass


class MergedKeys(object):
    def __init__(self, filename, uncommitted_filename, dump_filename, prepare_timeout, safe, dump_keys):
        self.filename = filename
        self.uncommitted_filename = uncommitted_filename
        self.dump_filename = dump_filename
        self.prepare_timeout = prepare_timeout
        self.safe = safe
        self.dump_keys = dump_keys
        self.newest_key_stats = defaultdict(int)

    def on_key_data(self, key_data, merged_file, uncommitted_file, dump_file):
        if self.dump_keys:
            dump_file.write('{0}\n'.format(key_data[0]))

        key_infos = key_data[1]

        has_uncommitted = False
        for info in key_infos:
            if info.flags & elliptics.record_flags.uncommitted:
                has_uncommitted = True
                if info.timestamp >= self.prepare_timeout:
                    return

        if self.safe and has_uncommitted:
            has_uncommitted = False
            key_infos = [info for info in key_infos if not info.flags & elliptics.record_flags.uncommitted]
            if not key_infos:
                return

        if has_uncommitted:
            dump_key_data(key_data, uncommitted_file)
        else:
            dump_key_data(key_data, merged_file)
            newest_key_group = key_infos[0].group_id
            self.newest_key_stats[newest_key_group] += 1


def merge_results(arg):
    ctx, range_id, results = arg
    log.debug("Merging iteration results of range: {0}".format(range_id))

    filename = os.path.join(ctx.tmp_dir, 'merge_%d' % (range_id))
    uncommitted_filename = os.path.join(ctx.tmp_dir, 'uncommitted_%d' % (range_id))
    dump_filename = os.path.join(ctx.tmp_dir, 'dump_%d' % (range_id))
    merged_keys = MergedKeys(filename, uncommitted_filename, dump_filename,
                             ctx.prepare_timeout, ctx.safe, ctx.dump_keys)

    counter = 0
    with open(filename, 'w') as merged_file, open(uncommitted_filename, 'w') as uncommitted_file, \
         open(dump_filename, 'w') as dump_file:
        for key_data in merged_results(ctx, results):
            counter += 1
            merged_keys.on_key_data(key_data, merged_file, uncommitted_file, dump_file)

    ctx.stats.counter("total_keys", counter)
    return merged_keys


def get_ranges(ctx):
    routes = ctx.routes.filter_by_groups(ctx.groups)
    addresses = dict()
    groups_number = len(routes.groups())
    prev_id = None
    ranges = []
    for i in range(groups_number):
        route = routes[i]
        addresses[route.id.group_id] = (route.address, route.backend_id)
        prev_id = route.id

    for i in range(groups_number, len(routes) - groups_number + 1):
        route = routes[i]
        ranges.append((prev_id, routes[i].id, addresses.values()))
        prev_id = route.id
        addresses[route.id.group_id] = (route.address, route.backend_id)

    def contains(addresses_with_backends, address, backend_id):
        for addr, bid in addresses_with_backends:
            if addr == address and (backend_id is None or backend_id == bid):
                return True
        return False

    if ctx.one_node:
        ranges = [x for x in ranges if contains(x[2], ctx.address, ctx.backend_id)]

    address_range = dict()

    for i, rng in enumerate(ranges):
        for addr in rng[2]:
            val = IdRange(rng[0], rng[1], range_id=i)
            if addr not in address_range:
                address_range[addr] = []
            address_range[addr].append(val)
    return address_range


def process_uncommitted(ctx, results):
    '''
    Removes uncommitted keys. If a key has any committed replicas, then this key is
    appended to the file containing committed keys.
    If an uncommitted key's replica hasn't exceeded prepare timeout, then skip recovering of the key,
    because the key is under writing and can be committed in the nearest future.
    '''
    if ctx.dry_run or ctx.safe:
        return

    node = elliptics.create_node(log_file=ctx.log_file,
                                 log_level=int(ctx.log_level),
                                 log_watched=True,
                                 wait_timeout=ctx.wait_timeout,
                                 flags=elliptics.config_flags.no_route_list,
                                 net_thread_num=1,
                                 io_thread_num=1,
                                 remotes=ctx.remotes)
    session = elliptics.newapi.Session(node)
    session.trace_id = ctx.trace_id
    session.exceptions_policy = elliptics.exceptions_policy.no_exceptions
    session.set_filter(elliptics.filters.all_final)
    session.ioflags |= elliptics.io_flags.cas_timestamp
    session.timestamp = ctx.prepare_timeout

    stats = ctx.stats['recover']
    stats_cmd = ctx.stats['commands']

    for r in results:
        with open(r.filename, 'ab') as f:
            for _, batch in groupby(enumerate(load_key_data(r.uncommitted_filename)),
                                    key=lambda x: x[0] / ctx.batch_size):
                batch = [item[1] for item in batch]
                tasks = []
                statuses = {}  # (key, group_id) -> status

                for key, key_infos in batch:
                    for info in key_infos:
                        if info.flags & elliptics.record_flags.uncommitted:
                            if info.group_id in ctx.ro_groups:
                                stats.counter('skip_remove_uncommitted_key_from_ro_group', 1)
                                statuses[(key, info.group_id)] = 0  # mark status as successful
                                continue
                            tasks.append((key, info.group_id, info.size))

                for attempt in range(ctx.attempts):
                    if not tasks:
                        break

                    if attempt > 0:
                        stats.counter('remove_retries', len(tasks))

                    batch_sizes = defaultdict(int) # group_id -> batch_size
                    for _, group_id, key_size in tasks:
                        batch_sizes[group_id] += key_size

                    timeouts = {group_id: max(60, batch_size / ctx.data_flow_rate)
                                for group_id, batch_size in batch_sizes.iteritems()}

                    responses = []
                    for key, group_id, _ in tasks:
                        session.groups = [group_id]
                        session.timeout = timeouts[group_id]
                        responses.append(session.remove(key))

                    failed_tasks = []
                    for i, r in enumerate(responses):
                        key, group_id, _ = tasks[i]
                        status = r.get()[0].status
                        log.info('Removed uncommitted key: %s, group: %s, status: %s, attempts: %s/%s',
                                 key, group_id, status, attempt, ctx.attempts)
                        statuses[(key, group_id)] = status

                        if status == 0:
                            stats.counter('removed_uncommitted_keys', 1)
                        else:
                            stats_cmd.counter('remove.{0}'.format(status), 1)

                        if status not in (0, -errno.ENOENT, -errno.EBADFD):
                            failed_tasks.append(tasks[i])
                    tasks = failed_tasks

                for key, key_infos in batch:
                    # Filter uncommitted replicas, then append a key to the 'merged' file for recovery.
                    # If an uncommitted replica hasn't exceeded prepare timeout,
                    # then removal status is EBADFD and this key must be skipped.
                    infos = []
                    for info in key_infos:
                        if info.flags & elliptics.record_flags.uncommitted:
                            status = statuses[(key, info.group_id)]
                            if status == -errno.EBADFD:
                                stats.counter('skipped_uncommitted_keys', 1)
                                infos = None
                                break
                        else:
                            infos.append(info)

                    if infos:
                        dump_key_data((key, infos), f)


def merge_dump_files(ctx, results):
    import shutil

    dump_filename = os.path.join(ctx.tmp_dir, 'dump')
    with open(dump_filename, 'wb') as df:
        for r in results:
            if r.dump_filename:
                shutil.copyfileobj(open(r.dump_filename, 'rb'), df)
                os.remove(r.dump_filename)

    log.debug("merge_dump_files: address: %s, groups: %s, tmp_dir: %s",
              ctx.address, ctx.groups, ctx.tmp_dir)


def dump_key(ctx, key, key_infos, newest_key_group):
    if key_infos[0].group_id != newest_key_group:
        for i, info in enumerate(key_infos):
            if info.group_id == newest_key_group:
                tmp = list(key_infos)
                tmp[0], tmp[i] = tmp[i], tmp[0]
                key_infos = tuple(tmp)
                break

    key_info = key_infos[0]
    if key_info.timestamp < ctx.prepare_timeout:
        is_all_uncommitted = True
        same_ts = lambda lhs, rhs: lhs.timestamp == rhs.timestamp
        for info in key_infos:
            if not (info.flags & elliptics.record_flags.uncommitted and same_ts(info, key_info)):
                is_all_uncommitted = False
                break
    else:
        is_all_uncommitted = False

    key_data = (key, key_infos)
    log.debug("Dumping key: {0}, group: {1}".format(key, newest_key_group))
    if ctx.no_server_send or is_all_uncommitted:
        dump_key_data(key_data, ctx.rest_file)
    else:
        if newest_key_group not in ctx.bucket_files:
            filename = os.path.join(ctx.tmp_dir, 'bucket_{}'.format(newest_key_group))
            ctx.bucket_files[newest_key_group] = open(filename, 'wb+')
        dump_key_data(key_data, ctx.bucket_files[newest_key_group])


def fill_buckets(ctx, results):
    '''
    This function distributes keys among multiple files (buckets).
    One bucket is 'rest_keys' and other buckets are 'bucket_xx', where xx == group_id.
    'bucket_xx' contains newest keys that should be recovered from group xx to other groups
    via server_send. If a key could not be recovered with server_send it is placed to 'rest_keys'.

    Also this function prepares bucket_order array. The array contains group_id's sorted by amount
    of keys in appropriate bucket. This array will be used by server_send recovery process.
    '''
    newest_key_stats = defaultdict(int)
    for r in results:
        for group, count in r.newest_key_stats.iteritems():
            newest_key_stats[group] += count
    log.debug("Fill buckets: newest_key_stats (group -> count): {}".format(newest_key_stats))

    bucket = newest_key_stats.items()
    bucket.sort(key=lambda t: t[1], reverse=True)

    rest_keys_filename = os.path.join(ctx.tmp_dir, 'rest_keys')
    ctx.rest_file = open(rest_keys_filename, 'wb')
    ctx.bucket_files = {}
    ctx.bucket_order = [b[0] for b in bucket]
    log.debug("Fill buckets: order: {}".format(ctx.bucket_order))

    for r in results:
        for key, key_infos in load_key_data(r.filename):
            same_meta = lambda lhs, rhs: (lhs.timestamp, lhs.size, lhs.user_flags) == (rhs.timestamp, rhs.size, rhs.user_flags)
            same_info_groups = [info.group_id for info in key_infos if same_meta(info, key_infos[0])]

            for group in ctx.bucket_order:
                if group in same_info_groups:
                    dump_key(ctx, key, key_infos, group)
                    break


def cleanup(results):
    for r in results:
        os.remove(r.filename)
        os.remove(r.uncommitted_filename)


def process_merged_keys(ctx, results):
    ctx.stats.timer('main', 'process_uncommitted')
    log.info("Processing uncommitted keys")
    process_uncommitted(ctx, results)

    ctx.stats.timer('main', 'merge_dump_files')
    log.info("merge dump files")
    merge_dump_files(ctx, results)

    ctx.stats.timer('main', 'fill_buckets')
    log.info("Filling buckets")
    fill_buckets(ctx, results)

    cleanup(results)


def main(ctx):
    ctx.stats.timer('main', 'started')
    ret = True
    if len(ctx.routes.groups()) < 2:
        log.error("There is only one group in route list: {0}. "
                  "sdc recovery could not be made."
                  .format(ctx.routes.groups()))
        return False

    ranges = get_ranges(ctx)
    log.debug("Ranges: {0}".format(ranges))

    results = []
    try:
        ctx.stats.timer('main', 'iterating')
        log.info("Start iterating {0} nodes in the pool".format(len(ranges)))
        async = ctx.pool.map_async(iterate_node, ((ctx.portable(), addr[0], addr[1], ranges[addr]) for addr in ranges))
        for result in async.get(timeout=ctx.iteration_timeout):
            if result is None:
                log.error('Some iteration has been failed. Terminating.')
                ctx.stats.timer('main', 'finished')
                return False
            results.append(result)
    except Exception:
        log.exception("Failed to iterate nodes")
        ctx.stats.timer('main', 'finished')
        return False
    except KeyboardInterrupt:
        log.error("Caught Ctrl+C. Terminating.")
        ctx.stats.timer('main', 'finished')
        return False

    ctx.stats.timer('main', 'transpose')
    log.info("Transposing iteration results")
    results = transpose_results(results)
    ctx.stats.timer('main', 'merge')

    try:
        log.info("Merging iteration results from different nodes")
        async = ctx.pool.map_async(merge_results, ((ctx.portable(), ) + x for x in results.items()))
        results = [r for r in async.get(timeout=ctx.wait_timeout * len(results)) if r]
    except KeyboardInterrupt:
        log.error("Caught Ctrl+C. Terminating.")
        ctx.stats.timer('main', 'finished')
        return False

    process_merged_keys(ctx, results)

    if ctx.dry_run:
        ctx.stats.timer('main', 'finished')
        return ret

    ctx.stats.timer('main', 'recover')
    log.info("Start recovering")
    if ctx.custom_recover == '':
        ret &= recover(ctx)
    else:
        import imp
        log.debug("Loading module: {0}".format(ctx.custom_recover))
        imp.acquire_lock()
        custom_recover = imp.load_source('custom_recover', ctx.custom_recover)
        imp.release_lock()
        ret &= custom_recover.recover(ctx)

    ctx.stats.timer('main', 'finished')
    return ret


def lookup_keys(ctx):
    log.info("Start looking up keys")
    stats = ctx.stats["lookup"]
    stats_cmd = ctx.stats['commands']
    stats.timer('process', 'started')
    elog = elliptics.Logger(ctx.log_file, int(ctx.log_level), True)
    node = elliptics_create_node(address=ctx.address,
                                 elog=elog,
                                 wait_timeout=ctx.wait_timeout,
                                 flags=elliptics.config_flags.no_route_list,
                                 net_thread_num=1,
                                 io_thread_num=1,
                                 remotes=ctx.remotes)
    session = elliptics.newapi.Session(node)
    session.trace_id = ctx.trace_id
    session.exceptions_policy = elliptics.exceptions_policy.no_exceptions
    session.set_filter(elliptics.filters.all_final)

    filename = os.path.join(ctx.tmp_dir, 'merged')
    uncommitted_filename = os.path.join(ctx.tmp_dir, 'uncommitted')
    merged_keys = MergedKeys(filename, uncommitted_filename, None,
                             ctx.prepare_timeout, ctx.safe, False)

    with open(ctx.dump_file, 'r') as dump_f, open(filename, 'w') as merged_file, \
         open(uncommitted_filename, 'w') as uncommitted_file:
        for str_id in dump_f:
            id = elliptics.Id(str_id)
            lookups = []
            for g in ctx.groups:
                session.groups = [g]
                lookups.append(session.lookup(id))
            key_infos = []

            for i, l in enumerate(lookups):
                result = l.get()[0]
                status = result.status
                if status == 0:
                    address = result.address
                    key_infos.append(KeyInfo(address,
                                             ctx.groups[i],
                                             result.record_info.data_timestamp,
                                             result.record_info.data_size,
                                             result.record_info.user_flags,
                                             result.record_info.record_flags,
                                             result.record_info.data_offset,
                                             0)) # blob_id
                else:
                    log.debug("Failed to lookup key: {0} in group: {1}: {2}"
                              .format(id, ctx.groups[i], status))
                    stats_cmd.counter('lookup.{0}'.format(status), 1)
                    stats.counter("lookups", -1)
            if len(key_infos) > 0:
                key_infos.sort(key=lambda x: (x.timestamp, x.size, x.user_flags), reverse=True)
                key_data = (id, key_infos)
                if not skip_key_data(ctx, key_data):
                    merged_keys.on_key_data(key_data, merged_file, uncommitted_file, None)
                stats.counter("lookups", len(key_infos))
            else:
                log.error("Key: {0} is missing in all specified groups: {1}. It won't be recovered."
                          .format(id, ctx.groups))

    stats.timer('process', 'finished')
    return merged_keys


def dump_main(ctx):
    ctx.stats.timer('main', 'started')
    ret = True
    if len(ctx.routes.groups()) < 2:
        log.error("There is only one group in route list: {0}. "
                  "sdc recovery could not be made."
                  .format(ctx.routes.groups()))
        return False

    try:
        merged_keys = lookup_keys(ctx)
    except KeyboardInterrupt:
        log.error("Caught Ctrl+C. Terminating.")
        ctx.stats.timer('main', 'finished')
        return False

    process_merged_keys(ctx, (merged_keys,))

    log.debug("Merged_filename: %s, address: %s, groups: %s, tmp_dir:%s",
              merged_keys.filename, ctx.address, ctx.groups, ctx.tmp_dir)

    if ctx.dry_run:
        return ret

    if ctx.custom_recover == '':
        recover(ctx)
    else:
        import imp
        log.debug("Loading module: {0}".format(ctx.custom_recover))
        imp.acquire_lock()
        custom_recover = imp.load_source('custom_recover', ctx.custom_recover)
        imp.release_lock()
        custom_recover.recover(ctx)

    ctx.stats.timer('main', 'finished')
    return ret
