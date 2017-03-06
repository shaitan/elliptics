#!/usr/bin/env python

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

import os
import shutil
import sys
sys.path.insert(0, "")  # for running from cmake


def make_backends(backends_count, group_id):
    '''
    Returns configuration of a single group that has @backends_count backends.
    '''
    return [{'group': group_id, 'records_in_blob': 100}] * backends_count


def make_servers(groups, nodes_count, backends_count):
    '''
    Returns configuration of testing cluster: given arguments specify cluster with @nodes_count elliptics nodes,
    where every node will serve multiple @groups and each group has @backends_count backends.
    '''
    backends = []
    for g in groups:
        backends.extend(make_backends(backends_count, g))
    return [{'backends': backends}] * nodes_count


class Servers:
    def __init__(self,
                 servers=make_servers([1], 2, 2),
                 isolated=False,
                 path='servers'):
        import json
        import subprocess
        self.path = path
        if os.path.exists(self.path):
            shutil.rmtree(self.path)
        os.mkdir(self.path)

        config = {}
        config['fork'] = True
        config['monitor'] = True
        config['path'] = self.path
        config['isolated'] = isolated
        config['top_period'] = 5 * 60
        config['top_length'] = 50
        config['top_events_size'] = 1000 * 100
        config['servers'] = servers
        js = json.dumps(config)

        print js
        self.p = subprocess.Popen(args=['../dnet_run_servers'],
                                  stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE)

        self.p.stdin.write(js + '\0')

        assert self.p.poll() is None

        while self.p.poll() is None:
            js = self.p.stdout.readline()
            if js:
                self.config = json.loads(js)
                break

        assert self.p.poll() is None

        self.config_params = config
        self.remotes = [str(x['remote']) for x in self.config['servers']]
        self.monitors = [str(x['monitor']) for x in self.config['servers']]
        groups = set()
        for server in servers:
            for backend in server['backends']:
                groups.add(backend['group'])
        self.groups = list(groups)

    def stop(self):
        if self.p and self.p.poll() is None:
            self.p.terminate()
            self.p.wait()
