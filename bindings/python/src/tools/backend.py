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
from elliptics.tools.misc import convert_addresses, json_pretty_print


def convert_backend_state(state):
    try:
        return {0: 'disabled',
                1: 'enabled',
                2: 'activating',
                3: 'disabling'}[state]
    except:
        return 'unknown'


def convert_defrag_state(state):
    try:
        return {0: 'not-started',
                1: 'in-progress'}[state]
    except:
        return 'unknown'


def print_results(ctx, results, backends_filter=[]):
    backends = []
    for r in results:
        try:
            for backend in r.get()[0].backends:
                if not backends_filter or backend.backend_id in backends_filter:
                    backends.append(backend)
        except Exception as e:
            click.echo(e)
            ctx.exit()

    json_pretty_print({
        'backends': [{
            'backend_id': backend.backend_id,
            'state': convert_backend_state(backend.state),
            'defrag_state': convert_defrag_state(backend.defrag_state),
            'last_start': str(backend.last_start),
            'last_start_err': backend.last_start_err,
            'readonly': backend.read_only
        } for backend in backends]})


def exec_func(ctx, func):
    results = []
    for backend in ctx.obj['backends']:
        for address in ctx.obj['remotes']:
            results.append(func(address, backend))
    print_results(ctx, results)


@click.group(context_settings=dict(help_option_names=['-h', '--help']),
             short_help='backends operations')
@click.pass_context
@click.option('--remote', '-r', multiple=True, callback=convert_addresses, help='Elliptics node address')
@click.option('--backend', '-b', multiple=True, type=int, help='Backend id')
@click.option('--log', '-l', default='/dev/stderr', type=click.Path(),
              help='Output log messages from library to file [default: %default]')
@click.option('--log-level', '-L', default='error',
              type=click.Choice(map(str, elliptics.log_level.names.keys())),
              help='Elliptics client verbosity [default: error]')
@click.option('--wait-timeout', '-w', default=5, type=int, help='Timeout for performing operations [default: %default]')
@click.option('--check-timeout', '-c', default=30, type=int, help='Timeout for route list requests [default: %default]')
def backend(ctx, remote, backend, log, log_level, wait_timeout, check_timeout):
    ctx.obj['remotes'] = remote
    ctx.obj['backends'] = backend
    ctx.obj['session'] = elliptics.Session(elliptics.create_node(
        remotes=ctx.obj['remotes'],
        flags=elliptics.config_flags.no_route_list,
        log_file=log,
        log_level=elliptics.log_level.names[log_level],
        wait_timeout=wait_timeout,
        check_timeout=check_timeout))


@backend.command(short_help='enable backends specified by `-b/--backend`')
@click.pass_context
def enable(ctx):
    exec_func(ctx, ctx.obj['session'].enable_backend)


@backend.command(short_help='disable backends specified by `-b/--backend`')
@click.pass_context
def disable(ctx):
    exec_func(ctx, ctx.obj['session'].disable_backend)


@backend.command(short_help='defrag backends specified by `-b/--backend`')
@click.pass_context
def defrag(ctx):
    exec_func(ctx, ctx.obj['session'].start_defrag)


@backend.command(short_help='turn on readonly mode at backends specified by `-b/--backend`')
@click.pass_context
def make_readonly(ctx):
    exec_func(ctx, ctx.obj['session'].make_readonly)


@backend.command(short_help='turn off readonly mode at backends specified by `-b/--backend`')
@click.pass_context
def make_writable(ctx):
    exec_func(ctx, ctx.obj['session'].make_writable)


@backend.command(short_help='print status of backends specified by `-b/--backend`')
@click.pass_context
def status(ctx):
    results = []
    for address in ctx.obj['remotes']:
        results.append(ctx.obj['session'].request_backends_status(address))

    print_results(ctx, results, ctx.obj['backends'])

if __name__ == '__main__':
    backend(obj={})
