# =============================================================================
# 2013+ Copyright (c) Kirill Smorodinnikov <shaitkir@gmail.com>
# All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your optixon) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# =============================================================================

from resource import getpagesize


class Value(object):
    def __init__(self, stats, path=[]):
        self.__stats__ = stats
        self.__path__ = path

    def __getitem__(self, item):
        return Value(self.__stats__, self.__path__ + [item])

    def get(self, default=0):
        try:
            for path in self.__path__:
                self.__stats__ = self.__stats__[path]
        except:
            self.__stats__ = default

        self.__path__ = []
        return self.__stats__


class BaseView(object):
    def __init__(self, stats):
        self.__stats__ = stats


class HandyStatsView(BaseView):
    def __init__(self, stats):
        super(HandyStatsView, self).__init__(stats['stats'])

    @property
    def queue_size(self):
        return self.__stats__['handystats.message_queue.size']['moving-avg'].get()

    @property
    def process_rate(self):
        return self.__stats__['handystats.message_queue.pop_count']['rate'].get()


class EblobStatsView(BaseView):
    def __init__(self, stats, backend_id):
        super(EblobStatsView, self).__init__(stats)
        self.__id__ = backend_id

    @property
    def hash_time(self):
        return self.__stats__['stats']['eblob.{0}.hash'.format(self.__id__)]['moving-avg'].get()

    @property
    def disk_write_time(self):
        return self.__stats__['stats']['eblob.{0}.disk.write'.format(self.__id__)]['moving-avg'].get()

    @property
    def disk_index_lookup_time(self):
        return self.__stats__['stats']['eblob.{0}.disk.index.lookup'.format(self.__id__)]['moving-avg'].get()

    @property
    def cache_lookup_time(self):
        return self.__stats__['stats']['eblob.{0}.cache.lookup'.format(self.__id__)]['moving-avg'].get()


class BackendStatsView(BaseView):
    def __init__(self, stats, backend_id):
        super(BackendStatsView, self).__init__(stats)
        self.__id__ = backend_id

    @property
    def backend_id(self):
        return self.__id__

    @property
    def blocking_queue_size(self):
        return self.__stats__['pool.{0}.blocking.queue.size'.format(self.__id__)]['moving-avg'].get()

    @property
    def nonblocking_queue_size(self):
        return self.__stats__['pool.{0}.nonblocking.queue.size'.format(self.__id__)]['moving-avg'].get()

    @property
    def active_blocking_threads(self):
        return self.__stats__['pool.{0}.blocking.active_threads'.format(self.__id__)]['moving-avg'].get()

    @property
    def active_nonblocking_threads(self):
        return self.__stats__['pool.{0}.nonblocking.active_threads'.format(self.__id__)]['moving-avg'].get()

    @property
    def time(self):
        from datetime import datetime
        start_time = datetime.fromtimestamp(
            self.__stats__['backends'][self.__id__]['status']['last_start']['tv_sec'].get())
        return datetime.now() - start_time

    @property
    def commands(self):
        return CommandsStatsView(self.__stats__['backends'][self.__id__])

    @property
    def state(self):
        return self.__stats__['backends'][self.__id__]['status']['state'].get()

    @property
    def blocking_wait_time(self):
        return self.__stats__['stats']['pool.{0}.blocking.queue.wait_time'.format(self.__id__)]['moving-avg'].get()

    @property
    def nonblocking_wait_time(self):
        return self.__stats__['stats']['pool.{0}.nonblocking.queue.wait_time'.format(self.__id__)]['moving-avg'].get()

    @property
    def input_queue_size(self):
        return self.__stats__['stats']['io.input.queue.size']['moving-avg'].get()

    @property
    def output_queue_size(self):
        return self.__stats__['stats']['io.output.queue.size']['moving-avg'].get()

    @property
    def eblob(self):
        return EblobStatsView(self.__stats__, self.__id__)


class BackendsStatsView(BaseView):
    def __init__(self, stats):
        super(BackendsStatsView, self).__init__(stats)

    def __len__(self):
        return len(self.__stats__['backends'].get({}))

    def __getitem__(self, item):
        return BackendStatsView(self.__stats__, str(item))

    def __iter__(self):
        for backend_id in self.__stats__['backends'].get({}):
            yield BackendStatsView(self.__stats__, backend_id)

    @property
    def queue_size(self):
        return self.blocking_queue_size + self.nonblocking_queue_size

    @property
    def blocking_queue_size(self):
        return sum(b.blocking_queue_size for b in self)

    @property
    def nonblocking_queue_size(self):
        return sum(b.nonblocking_queue_size for b in self)

    @property
    def active_threads(self):
        return self.active_blocking_threads + self.active_nonblocking_threads

    @property
    def active_blocking_threads(self):
        return sum(b.active_blocking_threads for b in self)

    @property
    def active_nonblocking_threads(self):
        return sum(b.active_nonblocking_threads for b in self)


class CommandStatsView(BaseView):
    class __DestView__(BaseView):
        class __ClientView__(BaseView):
            __self_slots__ = ('successes', 'failures', 'size', 'total')
            __slots__ = __self_slots__ + ('__stats__', )

            def __init__(self, stats):
                super(CommandStatsView.__DestView__.__ClientView__, self).__init__(stats)

            def __getattr__(self, item):
                if item is 'total':
                    return self.successes + self.failures
                elif item in self.__self_slots__:
                    return self.__stats__[item].get()
                raise AttributeError("'{0}' object has no attribute '{1}'".format(str(type(self)), item))

        __self_slots__ = 'outside', 'internal'
        __slots__ = __self_slots__ + __ClientView__.__slots__

        def __init__(self, stats):
            super(CommandStatsView.__DestView__, self).__init__(stats)

        def __getattr__(self, item):
            if item in self.__ClientView__.__slots__[:-1]:
                return sum(getattr(getattr(self, slot), item) for slot in self.__self_slots__)
            elif item in self.__self_slots__:
                return self.__ClientView__(self.__stats__[item])
            raise AttributeError("'{0}' object has no attribute '{1}'".format(str(type(self)), item))

    __self_slots__ = ('disk', 'cache')
    __slots__ = __self_slots__ + __DestView__.__ClientView__.__slots__

    def __init__(self, stats):
        super(CommandStatsView, self).__init__(stats)

    def __getattr__(self, item):
        if item in self.__DestView__.__ClientView__.__slots__[:-1]:
            return sum(getattr(getattr(self, slot), item) for slot in self.__self_slots__)
        if item in self.__self_slots__:
            return self.__DestView__(self.__stats__[item])
        raise AttributeError("'{0}' object has no attribute '{1}'".format(str(type(self)), item))


class ExtendedCommandStatsView(CommandStatsView):
    def __init__(self, stats, command):
        super(ExtendedCommandStatsView, self).__init__(stats['commands'][command])
        self.__extended_stats__ = stats
        self.__command__ = command

    @property
    def eblob_time(self):
        return self.__extended_stats__['stats']['eblob_backend.cmd.{0}'.format(self.__command__)]['moving-avg'].get()

    @property
    def cache_time(self):
        return self.__extended_stats__['stats']['cache.{0}'.format(self.__command__)]['moving-avg'].get()

    @property
    def total_time(self):
        return self.__extended_stats__['stats']['io.cmd.{0}'.format(self.__command__)]['moving-avg'].get()

    @property
    def lock_time(self):
        return self.__extended_stats__['stats']['io.cmd.{0}.lock_time'.format(self.__command__)]['moving-avg'].get()


class CommandsStatsView(BaseView):
    __self_slots__ = ('read', 'write', 'remove')
    __slots__ = __self_slots__ + ('__stats__', )

    def __init__(self, stats, extended=False):
        super(CommandsStatsView, self).__init__(stats)
        self.__extended__ = extended

    def __getattr__(self, item):
        if item in self.__self_slots__:
            if self.__extended__:
                return ExtendedCommandStatsView(self.__stats__, item.upper())
            else:
                return CommandStatsView(self.__stats__['commands'][item.upper()])
        raise AttributeError("'{0}' object has no attribute '{1}'".format(str(type(self)), item))


class ExtendedCommandsStatsView(CommandsStatsView):
    def __init__(self, stats):
        super(ExtendedCommandsStatsView, self).__init__(stats, True)

    @property
    def total(self):
        return self.__stats__['stats']['io.cmds']['value'].get()

    @property
    def rate(self):
        return self.__stats__['stats']['io.cmds']['rate'].get()

    @property
    def time(self):
        return self.__stats__['stats']['io.cmd']['moving-avg'].get()


class SysStatsView(BaseView):
    def __init__(self, stats):
        super(SysStatsView, self).__init__(stats)
        self.__procfs__ = self.__stats__['procfs']

    @property
    def rss(self):
        return self.__procfs__['stat']['rss'].get() * getpagesize()

    @property
    def msize(self):
        return self.__procfs__['stat']['msize'].get() * getpagesize()

    @property
    def mtotal(self):
        return self.__procfs__['vm']['total'].get()

    @property
    def mfree(self):
        return self.__procfs__['vm']['free'].get()

    @property
    def mbuffers(self):
        return self.__procfs__['vm']['buffers'].get()

    @property
    def read_bytes(self):
        return self.__procfs__['io']['read_bytes'].get()

    @property
    def rchar(self):
        return self.__procfs__['io']['rchar'].get()

    @property
    def write_bytes(self):
        return self.__procfs__['io']['write_bytes'].get()

    @property
    def wchar(self):
        return self.__procfs__['io']['wchar'].get()

    @property
    def blocking_queue_size(self):
        return self.__stats__['stats']['pool.sys.blocking.queue.size']['moving-avg'].get()

    @property
    def nonblocking_queue_size(self):
        return self.__stats__['stats']['pool.sys.nonblocking.queue.size']['moving-avg'].get()

    @property
    def active_blocking_threads(self):
        return self.__stats__['stats']['pool.sys.blocking.active_threads']['moving-avg'].get()

    @property
    def active_nonblocking_threads(self):
        return self.__stats__['stats']['pool.sys.nonblocking.active_threads']['moving-avg'].get()


class StatsView(BaseView):
    def __init__(self, stats):
        super(StatsView, self).__init__(Value(stats))

    @property
    def sys(self):
        return SysStatsView(self.__stats__)

    @property
    def commands(self):
        return ExtendedCommandsStatsView(self.__stats__)

    @property
    def backends(self):
        return BackendsStatsView(self.__stats__)

    @property
    def handy(self):
        return HandyStatsView(self.__stats__)

    @property
    def timestamp(self):
        return self.__stats__['string_timestamp'].get()
