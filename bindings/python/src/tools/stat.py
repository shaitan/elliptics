#!/usr/bin/python
# -*- coding: utf-8 -*-

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

import click
import elliptics
from elliptics.tools.misc import convert_addresses, gettermsize, json_pretty_print

no_color = False


def format_value(val, units, level):
    global no_color
    value_color, units_color, reset_color = '', '', ''
    if not no_color:
        value_color, units_color, reset_color = '\033[0;30m\033[1m', '\033[0;30m\033[1m', '\033[0;0m'
        if val:
            colors = ('\033[1;31m', '\033[1;35m', '\033[1;32m', '\033[0;34m',
                      '\033[1;36m', '\033[1;30m', '\033[0;31m', '\033[0;32m')
            value_color = colors[level % len(colors)]
    return "{value_color}{{0:>4}}{units_color}{{1:<1}}{reset_color}".format(
        value_color=value_color,
        units_color=units_color,
        reset_color=reset_color).format(val, units)


def convert(value, base):
    units = ('', 'k', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y')
    c = 0
    while len(str(long(round(value)))) > 4:
        value = value / base
        c += 1
    return format_value(long(round(value)), units[c], c)


def convert_float(value, base=1000):
    if value < base:
        return str(value)[:5]
    else:
        return convert(value, base)


def convert_counter(value):
    return convert(value, 1000)


def convert_size(value):
    return convert(value, 1024)


def convert_time(value):
    return str(value)


def convert_time_seconds(value):
    from datetime import timedelta
    return str(timedelta(seconds=value.seconds))


class Value(object):
    def __init__(self, value=0, converter=convert_counter):
        self.value = value
        self.converter = converter

    def update(self, value):
        self.value = value

    def get(self):
        return self.value

    def __str__(self):
        if self.converter:
            return self.converter(self.value)
        else:
            return str(self.value)


class DiffValue(Value):
    def __init__(self, value=0, converter=convert_counter):
        super(DiffValue, self).__init__(value, converter)
        self.prev_value = value

    def update(self, value):
        super(DiffValue, self).update(value - self.prev_value)
        self.prev_value = value


def convert_categories(ctx, param, value):
    if not value:
        return elliptics.monitor_stat_categories.all
    return sum(set((elliptics.monitor_stat_categories.names[v] for v in value)))


def init_columns():
    from collections import OrderedDict
    return OrderedDict([
        ('rps', DiffValue()),
        ('rsucc', DiffValue()),
        ('rfail', DiffValue()),
        ('rsize', DiffValue(0, convert_size)),
        ('wsucc', DiffValue()),
        ('wfail', DiffValue()),
        ('wsize', DiffValue(0, convert_size)),
        ('queue', Value()),
        ('thrds', Value()),
        ('rss', Value(0, convert_size)),
        ('virt', Value(0, convert_size)),
        ('rbyte', DiffValue(0, convert_size)),
        ('wbyte', DiffValue(0, convert_size)),
        ('rchar', DiffValue(0, convert_size)),
        ('wchar', DiffValue(0, convert_size)),
        ('hqueu', Value())])


def update(statistics, columns):
    from elliptics.tools.stats_view import StatsView

    stat = statistics.get().values()[0]
    view = StatsView(stat)

    columns['rps'].update(view.commands.total)
    columns['rsucc'].update(view.commands.read.successes)
    columns['rfail'].update(view.commands.read.failures)
    columns['rsize'].update(view.commands.read.size)
    columns['wsucc'].update(view.commands.write.successes)
    columns['wfail'].update(view.commands.write.failures)
    columns['wsize'].update(view.commands.write.size)
    columns['rss'].update(view.sys.rss)
    columns['virt'].update(view.sys.msize)
    columns['rbyte'].update(view.sys.read_bytes)
    columns['wbyte'].update(view.sys.write_bytes)
    columns['rchar'].update(view.sys.rchar)
    columns['wchar'].update(view.sys.wchar)
    columns['queue'].update(view.backends.queue_size)
    columns['thrds'].update(view.backends.active_threads)
    columns['hqueu'].update(view.handy.queue_size)


def print_stat(statistics, columns={}, counter=0):
    from threading import Timer
    if not columns:
        columns = init_columns()
    (width, height) = gettermsize()
    if (counter % height) == 0:
        counter += 2
        print ' '.join(map('\033[0;34m\033[4m{0:>5}\033[0;0m'.format, columns.keys()))
    update(statistics, columns)
    print ' '.join(map(str, columns.values()))
    counter += 1
    Timer(1, print_stat, [statistics, columns, counter]).start()


def print_sys(remotes, win, state, view):
    top_line = 'top - {0} remotes: {1}\n'.format(view.timestamp, map(str, remotes))
    win.addstr(top_line)
    mem_line = "Mem: {0} total, {1} rss, {2} virt, {3} free, {4} buffers\n".format(
        view.sys.mtotal,
        view.sys.rss,
        view.sys.msize,
        view.sys.mfree,
        view.sys.mbuffers)
    win.addstr(mem_line)
    queue_line = "Queues: {0} bsys, {1} nbsys, {2} bback, {3} nbback\n".format(
        str(view.sys.blocking_queue_size)[:6],
        str(view.sys.nonblocking_queue_size)[:6],
        str(view.backends.blocking_queue_size)[:6],
        str(view.backends.nonblocking_queue_size)[:6])
    win.addstr(queue_line)
    threads_line = "Threads: {0} bsys, {1} nbsys, {2} bback, {3} nbback\n".format(
        str(view.sys.active_blocking_threads)[:6],
        str(view.sys.active_nonblocking_threads)[:6],
        str(view.backends.active_blocking_threads)[:6],
        str(view.backends.active_nonblocking_threads)[:6])
    win.addstr(threads_line)
    disk_line = "Disk: {0} read, {1} rchar, {2} write, {3} wchar\n".format(
        view.sys.read_bytes - state['view'].sys.read_bytes,
        view.sys.write_bytes - state['view'].sys.write_bytes,
        view.sys.rchar - state['view'].sys.rchar,
        view.sys.wchar - state['view'].sys.wchar)
    win.addstr(disk_line)
    rps_line = "RPS: {0} total, {1} read, {2} write, {3} remove\n".format(
        view.commands.total - state['view'].commands.total,
        view.commands.read.total - state['view'].commands.read.total,
        view.commands.write.total - state['view'].commands.write.total,
        view.commands.remove.total - state['view'].commands.remove.total)
    win.addstr(rps_line)
    times_line = ("Time: %s eblob read, " % view.commands.read.eblob_time +
                  "%s cache read, " % view.commands.read.cache_time +
                  "%s total read, " % view.commands.read.total_time +
                  "%s read lock, " % view.commands.read.lock_time +
                  "%s eblob write, " % view.commands.write.eblob_time +
                  "%s cache write, " % view.commands.write.cache_time +
                  "%s total write, " % view.commands.write.total_time +
                  "%s write lock\n" % view.commands.write.lock_time)
    win.addstr(times_line)


class BackendStat(object):
    __slots__ = ['id', 'queue', 'nqueue', 'threads', 'nthreads',
                 'reads', 'writes', 'removes', 'state', 'time', 'node']
    format_str = "{0:>4} {1:>5} {2:>5} {3:>5} {4:>5} {5:>6} {6:>6} {7:>6} {8:1} {9:^8} {10}\n"

    def __init__(self, id, node):
        from datetime import timedelta
        self.id = id
        self.queue = Value(converter=convert_float)
        self.nqueue = Value(converter=convert_float)
        self.threads = Value(converter=convert_float)
        self.nthreads = Value(converter=convert_float)
        self.reads = DiffValue()
        self.writes = DiffValue()
        self.removes = DiffValue()
        self.time = Value(timedelta(0), converter=convert_time_seconds)
        self.state = Value('e', converter=None)
        self.node = node

    @classmethod
    def header_line(self):
        return self.format_str.format('BID', 'QUEUE', 'NQUEU', 'THRDS', 'NTHRS', 'READS',
                                      'WRITE', 'REMOV', 'S', 'TIME+', 'NODE')

    def __str__(self):
        return self.format_str.format(
            self.id,
            str(self.queue),
            str(self.nqueue),
            str(self.threads),
            str(self.nthreads),
            str(self.reads),
            str(self.writes),
            str(self.removes),
            str(self.state),
            str(self.time),
            str(self.node))


def convert_state(state):
    try:
        return {0: 'D',
                1: 'E',
                2: 'A',
                3: 'S'}[state]
    except:
        return 'U'


class BackendTimeStat(object):
    __slots__ = ['id', 'wtime', 'nwtime', 'htime', 'dwtime', 'ltime', 'cltime', 'node']
    format_str = "{0:>4} {1:>5} {2:>5} {3:>5} {4:>5} {5:>5} {6:>5} {7}\n"

    def __init__(self, id, node):
        self.id = id
        self.wtime = Value(converter=convert_time)
        self.nwtime = Value(converter=convert_time)
        self.htime = Value(converter=convert_time)
        self.dwtime = Value(converter=convert_time)
        self.ltime = Value(converter=convert_time)
        self.cltime = Value(converter=convert_time)
        self.node = node

    @classmethod
    def header_line(self):
        return self.format_str.format('BID', 'WTIME', 'NWTIM', 'HTIME', 'DWTIM', 'LTIME', 'CLTIM', 'NODE')

    def __str__(self):
        return self.format_str.format(
            self.id,
            str(self.wtime),
            str(self.nwtime),
            str(self.htime),
            str(self.dwtime),
            str(self.ltime),
            str(self.cltime),
            str(self.node))


def print_common_top(win, state, address, view):
    import curses
    if 'backends' not in state:
        state['backends'] = {}
    backends_state = state['backends']
    win.addstr(7, 0, BackendStat.header_line(), curses.A_REVERSE)
    for bview in view.backends:
        bid = int(bview.backend_id)
        if bid not in backends_state:
            backends_state[bid] = BackendStat(bid, address)
        backend_stat = backends_state[bid]
        backend_stat.state.update(convert_state(bview.state))
        backend_stat.queue.update(bview.blocking_queue_size)
        backend_stat.nqueue.update(bview.nonblocking_queue_size)
        backend_stat.threads.update(bview.active_blocking_threads)
        backend_stat.nthreads.update(bview.active_nonblocking_threads)
        backend_stat.time.update(bview.time)
        backend_stat.reads.update(bview.commands.read.total)
        backend_stat.writes.update(bview.commands.write.total)
        backend_stat.removes.update(bview.commands.remove.total)

    backends_stats = sorted(backends_state.values(), key=lambda bstat: bstat.id, reverse=True)

    for b in backends_stats:
        try:
            win.addstr(str(b))
        except:
            break


def print_times_top(win, state, address, view):
    import curses
    win.addstr(8, 0, BackendTimeStat.header_line(), curses.A_REVERSE)
    if 'backends' not in state:
        state['backends'] = {}
    backends_state = state['backends']
    for bview in view.backends:
        bid = int(bview.backend_id)
        if bid not in backends_state:
            backends_state[bid] = BackendTimeStat(bid, address)
        backend_stat = backends_state[bid]
        backend_stat.wtime.update(bview.blocking_wait_time)
        backend_stat.nwtime.update(bview.nonblocking_wait_time)
        backend_stat.htime.update(bview.eblob.hash_time)
        backend_stat.dwtime.update(bview.eblob.disk_write_time)
        backend_stat.ltime.update(bview.eblob.disk_index_lookup_time)
        backend_stat.cltime.update(bview.eblob.cache_lookup_time)

    backends_stats = sorted(backends_state.values(), key=lambda bstat: bstat.id, reverse=True)

    for b in backends_stats:
        try:
            win.addstr(str(b))
        except:
            break


def print_top(remotes, statistics, win, state, times):
    from elliptics.tools.stats_view import StatsView
    result = statistics.get()
    address = result.keys()[0]
    view = StatsView(result.values()[0])
    if not state:
        state['view'] = view
    print_sys(remotes, win, state, view)
    win.insertln()
    if times:
        print_times_top(win, state, address, view)
    else:
        print_common_top(win, state, address, view)
    state['view'] = view
    win.move(7, 0)


def run_top(remotes, statistics, times):
    import curses
    import atexit
    import time

    global no_color
    no_color = True

    win = curses.initscr()

    def tear_down():
        win.keypad(0)
        curses.nocbreak()
        curses.echo()
        curses.endwin()

    atexit.register(tear_down)
    curses.endwin()

    try:
        state = {}
        while 1:
            curses.endwin()
            win.erase()
            print_top(remotes, statistics, win, state=state, times=times)
            win.refresh()
            #win.nodelay(1)
            #c = win.getch()
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        pass


class StatisticsProvider(object):
    def __init__(self, remotes, http, full):
        self.remotes = remotes
        self.http = http
        if not self.http:
            flags = 0 if full else elliptics.config_flags.no_route_list
            self.session = elliptics.Session(elliptics.create_node(
                remotes=remotes,
                flags=flags,
                nonblocking_io_thread_num=8))

    def get(self):
        if self.http:
            return self.__get_over_http__()
        else:
            return self.__get_over_raw__()

    def __get_over_http__(self):
        import httplib
        import zlib
        import json
        ret = {}
        for remote in self.remotes:
            conn = httplib.HTTPConnection(remote.host, remote.port)
            conn.request("GET", "/all")
            response = conn.getresponse()
            ret[str(remote)] = json.loads(zlib.decompress(response.read()))
            conn.close()
        return ret

    def __get_over_raw__(self):
        ret = {}
        for r in self.session.monitor_stat().get():
            ret[str(r.address)] = r.statistics
        return ret


@click.group(invoke_without_command=True,
             context_settings=dict(help_option_names=['-h', '--help']),
             short_help='operations connected with monitor statistics')
@click.pass_context
@click.option('--remote', '-r', multiple=True, callback=convert_addresses, help="Elliptics node address")
@click.option('--category', '-c', multiple=True,
              type=click.Choice(elliptics.monitor_stat_categories.names.keys()), callback=convert_categories)
@click.option('--full', '-f', is_flag=True)
@click.option('--http', is_flag=True)
def monitor(ctx, remote, category, full, http):
    ctx.obj['remotes'] = remote
    ctx.obj['http'] = http
    if ctx.invoked_subcommand is None:
        stat_json = StatisticsProvider(ctx.obj['remotes'], ctx.obj['http'], full).get()
        if len(stat_json) == 1:
            return json_pretty_print(stat_json.values()[0])
        else:
            return json_pretty_print(stat_json)


@monitor.command()
@click.pass_context
def stat(ctx):
    print_stat(StatisticsProvider(ctx.obj['remotes'], ctx.obj['http'], False))


@monitor.command()
@click.pass_context
@click.option('--times', '-t', is_flag=True)
def top(ctx, times):
    run_top(ctx.obj['remotes'], StatisticsProvider(ctx.obj['remotes'], ctx.obj['http'], False), times)

if __name__ == '__main__':
    monitor(obj={})
