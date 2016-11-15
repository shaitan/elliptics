#!/usr/bin/env python

# =============================================================================
# 2016+ Copyright (c) Andrey Budnik <budnik27@gmail.com>
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

import sys
sys.path.insert(0, "")  # for running from cmake
import pytest
import elliptics
from conftest import make_session, scope
from server import Servers, make_backends
from test_recovery import recovery, RECOVERY, cleanup_backends, write_data, check_data


@pytest.yield_fixture(scope="module")
def servers(request):
    servers = [{'backends': make_backends(backends_count=1, group_id=g)} for g in 1, 2]
    _servers = Servers(without_cocaine=True,
                       servers=servers,
                       isolated=True,
                       path='isolated_servers')

    yield _servers

    _servers.stop()


@pytest.mark.incremental
class TestIsolatedRecovery:
    namespace = "TestIsolatedRecovery"

    def test_dc_isolated_groups(self, servers):
        '''
        Write one key into every group,
        run dc server-send recovery,
        check that keys were recovered into all groups.
        '''
        scope.node = elliptics.Node(elliptics.Logger("client.log", elliptics.log_level.debug))
        scope.node.add_remotes(servers.remotes)
        session = make_session(node=scope.node,
                               test_name='TestIsolatedRecovery.test_dc_isolated_groups',
                               test_namespace=self.namespace)

        groups = session.routes.groups()
        scope.test_group = groups[0]
        scope.test_group2 = groups[1]

        routes = session.routes.filter_by_group(scope.test_group)
        scope.test_address = routes[0].address

        keys = []
        data = 'isolated_data'
        groups = (scope.test_group, scope.test_group2)
        session.timestamp = elliptics.Time.now()
        for group_id in groups:
            key = 'isolated_key_{}'.format(group_id)
            session.groups = [group_id]
            write_data(scope, session, [key], [data])
            check_data(scope, session, [key], [data], session.timestamp)
            keys.append(key)

        recovery(one_node=False,
                 remotes=map(elliptics.Address.from_host_port_family, servers.remotes),
                 backend_id=None,
                 address=scope.test_address,
                 groups=groups,
                 rtype=RECOVERY.DC,
                 log_file='dc_isolated_groups.log',
                 tmp_dir='dc_isolated_groups')

        for group_id in groups:
            session.groups = [group_id]
            check_data(scope, session, keys, [data] * len(keys), session.timestamp)

    @pytest.mark.usefixtures("servers")
    def test_teardown(self):
        """Cleanup backends.

        * disable all backends
        * remove all blobs
        * enable all backends on all nodes
        """
        session = make_session(node=scope.node,
                               test_name='TestIsolatedRecovery.test_teardown',
                               test_namespace=self.namespace)
        addresses_with_backends = session.routes.addresses_with_backends()
        cleanup_backends(session, addresses_with_backends, addresses_with_backends)
