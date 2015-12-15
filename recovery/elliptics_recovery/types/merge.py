# =============================================================================
# 2013+ Copyright (c) Kirill Smorodinnikov <shaitkir@gmail.com>
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

"""
Deep Merge recovery type - recovers keys in one hash ring (aka group)
by placing them to the node where they belong.

 * Iterate all node in the group for ranges which are not belong to it.
 * Get all keys which shouldn't be on the node:
 * Looks up keys meta info on the proper node
 * If the key on the proper node is missed or older
 * then moved it form the node to ther proper node
 * If the key is valid then just remove it from the node.
"""

import logging
import os
from itertools import groupby
import traceback
import threading
import errno
import time

from ..etime import Time
from ..utils.misc import elliptics_create_node
from ..route import RouteList
from ..iterator import MergeRecoveryIterator
from ..range import IdRange
import elliptics

log = logging.getLogger(__name__)


def iterate_node(ctx, node, address, backend_id, ranges, eid, stats):
    try:
        log.debug("Running iterator on node: {0}/{1}".format(address, backend_id))
        timestamp_range = ctx.timestamp.to_etime(), Time.time_max().to_etime()
        flags = elliptics.iterator_flags.key_range | elliptics.iterator_flags.ts_range
        key_ranges = [IdRange(r[0], r[1]) for r in ranges]
        iterator = MergeRecoveryIterator(node, eid.group_id, trace_id=ctx.trace_id)
        result, result_len = iterator.iterate_with_stats(eid=eid,
                                                         timestamp_range=timestamp_range,
                                                         key_ranges=key_ranges,
                                                         tmp_dir=ctx.tmp_dir,
                                                         address=address,
                                                         backend_id=backend_id,
                                                         group_id=eid.group_id,
                                                         batch_size=ctx.batch_size,
                                                         stats=stats,
                                                         flags=flags,
                                                         leave_file=False,)
        if result is None:
            return None
        log.info("Iterator {0}/{1} obtained: {2} record(s)"
                 .format(result.address, backend_id, result_len))
        return result
    except Exception as e:
        log.error("Iteration failed for: {0}/{1}: {2}, traceback: {3}"
                  .format(address, backend_id, repr(e), traceback.format_exc()))
        return None


def process_node_backend(ctx, address, backend_id, group, ranges):
    try:
        log.debug("Processing node: {0}/{1} from group: {2} for ranges: {3}"
                  .format(address, backend_id, group, ranges))
        stats = ctx.stats['node_{0}/{1}'.format(address, backend_id)]
        stats.timer('process', 'started')

        elog = elliptics.Logger(ctx.log_file, int(ctx.log_level))
        node = elliptics_create_node(address=ctx.address,
                                     elog=elog,
                                     wait_timeout=ctx.wait_timeout,
                                     remotes=ctx.remotes,
                                     io_thread_num=4)

        stats.timer('process', 'iterate')
        results = iterate_node(ctx=ctx,
                               node=node,
                               address=address,
                               backend_id=backend_id,
                               ranges=ranges,
                               eid=ctx.routes.get_address_backend_route_id(address, backend_id),
                               stats=stats)
        if results is None or len(results) == 0:
            log.warning('Iterator result is empty, skipping')
            return True

        stats.timer('process', 'dump_keys')
        dump_path = os.path.join(ctx.tmp_dir, 'dump_{0}.{1}'.format(address, backend_id))
        log.debug("Dump iterated keys to file: {0}".format(dump_path))
        with open(dump_path, 'w') as dump_f:
            for r in results:
                dump_f.write('{0}\n'.format(r.key))

        stats.timer('process', 'recover')
        ss_rec = ServerSendRecovery(ctx, node, group, stats, address, backend_id)
        ret = True
        for batch_id, batch in groupby(enumerate(results), key=lambda x: x[0] / ctx.batch_size):
            keys = [val.key for _, val in batch]
            ret &= ss_rec.recover(keys)
        stats.timer('process', 'finished')

        return ret
    except Exception as e:
        log.error("Processing node failed for: {0}/{1}: {2}, traceback: {3}"
                  .format(address, backend_id, repr(e), traceback.format_exc()))
        return False


def get_ranges(ctx, group):
    ranges = dict()
    routes = RouteList(ctx.routes.filter_by_group(group))

    ID_MIN = elliptics.Id([0] * 64, group)
    ID_MAX = elliptics.Id([255] * 64, group)

    addresses = None
    if ctx.one_node:
        if ctx.backend_id is None:
            if ctx.address not in routes.addresses():
                log.error("Address: {0} wasn't found at group: {1} route list".format(ctx.address, group))
                return None
            addresses = routes.filter_by_address(ctx.address).addresses_with_backends()
        else:
            if (ctx.address, ctx.backend_id) not in routes.addresses_with_backends():
                log.error("Address: {0}/{1} hasn't been found in group: {2}".format(ctx.address,
                                                                                    ctx.backend_id,
                                                                                    ctx.group))
                return None
            addresses = ((ctx.address, ctx.backend_id),)
    else:
        addresses = routes.addresses_with_backends()

    for addr, backend_id in addresses:
        addr_info = (addr, backend_id)
        addr_ranges = routes.get_address_backend_ranges(addr, backend_id)
        if addr_ranges is None or len(addr_ranges) == 0:
            log.warning("Address: {0}/{1} has no range in group: {2}".format(addr, backend_id, group))
            continue

        ranges[addr_info] = []
        if addr_ranges[0][0] != ID_MIN:
            ranges[addr_info].append((ID_MIN, addr_ranges[0][0]))

        for i in xrange(1, len(addr_ranges)):
            ranges[addr_info].append((addr_ranges[i - 1][1], addr_ranges[i][0]))

        if addr_ranges[-1][1] != ID_MAX:
            ranges[addr_info].append((addr_ranges[-1][1], ID_MAX))

    return ranges


def main(ctx):
    ctx.stats.timer('main', 'started')
    ret = True
    if ctx.one_node:
        if ctx.backend_id is None:
            ctx.groups = tuple(set(ctx.groups).intersection(ctx.routes.get_address_groups(ctx.address)))
        else:
            ctx.groups = tuple(set(ctx.groups).intersection((ctx.routes.get_address_backend_group(ctx.address,
                                                                                                  ctx.backend_id),)))
    for group in ctx.groups:
        log.warning("Processing group: {0}".format(group))
        group_stats = ctx.stats['group_{0}'.format(group)]
        group_stats.timer('group', 'started')

        group_routes = ctx.routes.filter_by_groups([group])
        if len(group_routes.addresses_with_backends()) < 2:
            log.warning("Group {0} hasn't enough nodes/backends for recovery: {1}"
                        .format(group, group_routes.addresses_with_backends()))
            group_stats.timer('group', 'finished')
            continue

        ranges = get_ranges(ctx, group)

        if ranges is None or not len(ranges):
            log.warning("There is no ranges in group: {0}, skipping this group".format(group))
            group_stats.timer('group', 'finished')
            continue

        pool_results = []

        log.debug("Processing nodes ranges: {0}".format(ranges))

        for range in ranges:
            pool_results.append(ctx.pool.apply_async(process_node_backend, (ctx.portable(),
                                                                            range[0],
                                                                            range[1],
                                                                            group,
                                                                            ranges[range])))

        try:
            log.info("Fetching results")
            # Use INT_MAX as timeout, so we can catch Ctrl+C
            timeout = 2147483647
            for p in pool_results:
                ret &= p.get(timeout)
        except KeyboardInterrupt:
            log.error("Caught Ctrl+C. Terminating.")
            group_stats.timer('group', 'finished')
            ctx.stats.timer('main', 'finished')
            return False
        except Exception as e:
            log.error("Caught unexpected exception: {0}, traceback: {1}"
                      .format(repr(e), traceback.format_exc()))
            group_stats.timer('group', 'finished')
            ctx.stats.timer('main', 'finished')
            return False

        group_stats.timer('group', 'finished')

    ctx.stats.timer('main', 'finished')
    return ret


class ServerSendRecovery(object):
    '''
    Special recovery class that tries to recover keys from backends that
    should not contain this keys to proper backend via server-send operation.
    '''
    def __init__(self, ctx, node, group, stats, address, backend_id=None):
        self.routes, self.backends = self._prepare_routes(ctx, group, address, backend_id)
        self.session = elliptics.Session(node)
        self.session.exceptions_policy = elliptics.exceptions_policy.no_exceptions
        self.session.set_filter(elliptics.filters.all)
        self.session.timeout = 60
        self.session.groups = [group]
        self.session.trace_id = ctx.trace_id
        self.remove_session = self.session.clone()
        self.remove_session.set_filter(elliptics.filters.all_final)
        self.ctx = ctx
        self.stats = stats

    def _prepare_routes(self, ctx, group, address, backend_id):
        '''
        Returns pair: route list of @group and list of pairs (address, backend)
        '''
        group_routes = ctx.routes.filter_by_groups([group])
        backends = []
        if backend_id is not None:
            backends.append((address, backend_id))
        elif ctx.one_node:
            if ctx.backend_id is not None:
                backends.append((address, ctx.backend_id))
            else:
                for backend_id in group_routes.get_address_backends(address):
                    backends.append((address, backend_id))
        else:
            backends = group_routes.addresses_with_backends()

        log.info("Server-send recovery: group: {0}, num backends: {1}".format(group, len(backends)))
        return group_routes, backends

    def recover(self, keys):
        '''
        Tries to recover keys from every backend via server-send. Then it
        removes keys with older timestamp or invalid checksum.
        Returns list of keys that was not recovered via server-send.
        '''
        log.info("Server-send bucket: num keys: {0}".format(len(keys)))

        def contain(address, backend_id, key):
            addr, _, backend = self.routes.get_id_routes(key)[0]
            return address == addr and backend_id == backend

        responses = {str(k): [] for k in keys} # key -> [list of responses]
        for addr, backend_id in self.backends:
            key_candidates = [k for k in keys if not contain(addr, backend_id, k)]
            for i in range(self.ctx.attempts):
                if key_candidates:
                    timeouted_keys = self._server_send(key_candidates, addr, backend_id, responses)
                    key_candidates = timeouted_keys

        self._remove_bad_keys(responses)
        return not self._has_unrecovered_keys(responses)

    def _server_send(self, keys, addr, backend_id, responses):
        '''
        Calls server-send with a given list of keys to the specific backend.
        '''
        log.debug("Server-send: address: {0}, backend: {1}, num keys: {2}".format(addr, backend_id, len(keys)))

        timeouted_keys = []
        if self.ctx.dry_run:
            return timeouted_keys

        start_time = time.time()
        recovers_in_progress = len(keys)

        self.session.set_direct_id(addr, backend_id)
        flags = 0 if self.ctx.safe else elliptics.iterator_flags.move
        iterator = self.session.server_send(keys, flags, list(self.session.groups))

        for index, result in enumerate(iterator):
            status = result.response.status
            self._update_stats(start_time, index + 1, recovers_in_progress, status)
            key = result.response.key
            log.debug("Server-send result: key: {0}, status: {1}".format(key, status))
            if status == -errno.ETIMEDOUT:
                timeouted_keys.append(key)
            else:
                r = (status, addr, backend_id)
                responses[str(key)].append(r)

        return timeouted_keys

    def _remove_bad_keys(self, responses):
        '''
        Removes invalid keys with older timestamp or invalid checksum.
        '''
        bad_keys = []
        for val in responses.iteritems():
            for response in val[1]:
                if self._check_bad_key(response):
                    key = val[0]
                    bad_keys.append((key, ) + response)

        results = []
        for k in bad_keys:
            key, _, addr, backend_id = k
            self.remove_session.set_direct_id(addr, backend_id)
            result = self.remove_session.remove(elliptics.Id(key))
            results.append(result)

        for i, r in enumerate(results):
            status = r.get()[0].status
            log.info("Removing key: {0}, status: ".format(bad_keys[i], status))

    def _check_bad_key(self, response):
        status = response[0]
        return status == -errno.EBADFD or status == -errno.EILSEQ

    def _has_unrecovered_keys(self, responses):
        '''
        Returns True, if some key was not recovered via server-send.
        '''
        for key_responses in responses.itervalues():
            if self._check_unrecovered_key(key_responses):
                return True
        return False

    def _check_unrecovered_key(self, responses):
        '''
        Returns True, if a valid key exists on the backend, but the key could not be recovered by any reason.
        '''
        for r in responses:
            status = r[0]
            if status < 0 and status != -errno.ENOENT and not self._check_bad_key(r):
                return True
        return False

    def _update_stats(self, start_time, processed_keys, recovers_in_progress, status):
        speed = processed_keys / (time.time() - start_time)
        recovers_in_progress -= processed_keys
        self.stats.set_counter('recovery_speed', round(speed, 2))
        self.stats.set_counter('recovers_in_progress', recovers_in_progress)
        self.stats.counter('recovered_keys', 1 if status == 0 else -1)
        self.ctx.stats.counter('recovered_keys', 1 if status == 0 else -1)


def dump_process_group((ctx, group)):
    try:
        log.debug("Processing group: {0}".format(group))
        stats = ctx.stats['group_{0}'.format(group)]
        stats.timer('process', 'started')
        if group not in ctx.routes.groups():
            log.error("Group: {0} is not presented in route list".format(group))
            return False
        elog = elliptics.Logger(ctx.log_file, int(ctx.log_level))
        node = elliptics_create_node(address=ctx.address,
                                     elog=elog,
                                     wait_timeout=ctx.wait_timeout,
                                     net_thread_num=1,
                                     io_thread_num=1,
                                     remotes=ctx.remotes)
        ret = True
        with open(ctx.dump_file, 'r') as dump:
            ss_rec = ServerSendRecovery(ctx, node, group, stats, ctx.address)
            # splits ids from dump file in batchs and recovers it
            for batch_id, batch in groupby(enumerate(dump), key=lambda x: x[0] / ctx.batch_size):
                keys = [elliptics.Id(val) for _, val in batch]
                ret &= ss_rec.recover(keys)
        stats.timer('process', 'finished')
        return ret
    except Exception as e:
        log.error("Processing group failed for: {0}, group: {1}: {2}, traceback: {3}"
                  .format(ctx.address, group, repr(e), traceback.format_exc()))
        return False


def dump_main(ctx):
    ctx.stats.timer('main', 'started')
    groups = ctx.groups
    if ctx.one_node:
        routes = ctx.routes.filter_by_groups(groups)
        if ctx.backend_id is None:
            if ctx.address not in routes.addresses():
                log.error("Address: {0} wasn't found at groups: {1} route list".format(ctx.address, groups))
                return False
            groups = routes.filter_by_address(ctx.address).groups()
        else:
            if (ctx.address, ctx.backend_id) not in routes.addresses_with_backends():
                log.error("Address: {0}/{1} hasn't been found in groups: {2}".format(ctx.address,
                                                                                     ctx.backend_id,
                                                                                     ctx.groups))
                return False
            groups = [routes.get_address_backend_group(ctx.address, ctx.backend_id)]

    ret = True

    try:
        # processes each group in separated process
        iresults = ctx.pool.imap(dump_process_group, ((ctx.portable(), g) for g in groups))
        results = list(iresults)
    except KeyboardInterrupt:
        log.error("Caught Ctrl+C. Terminating.")
        ctx.stats.timer('main', 'finished')
        return False

    ret = all(results)

    ctx.stats.timer('main', 'finished')
    return ret
