# =============================================================================
# 2013+ Copyright (c) Kirill Smorodinnikov <shaitkir@gmail.com>
# 2018+ Copyright (c) Artem Ikchurin <artem.ikchurin@gmail.com>
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
from datetime import datetime
from conftest import make_session
from statistics_checker import MonitorStatsChecker
from statistics_checker import categories_combination

import elliptics


class TestBinaryMonitor:

    @pytest.mark.usefixtures("servers")
    def test_monitor_stat(self, simple_node):
        '''Simply get all statistics from all nodes and check that statistics is valid dict'''
        session = make_session(node=simple_node,
                               test_name='TestSession.test_monitor_stat')
        for addr in session.routes.addresses():
            stat = session.monitor_stat(addr).get()[0]
            assert stat.error.code == 0
            assert stat.error.message == ''
            assert type(stat.statistics) == dict

    @pytest.mark.parametrize("categories", categories_combination())
    @pytest.mark.usefixtures("servers")
    def test_monitor_categories_and_backends(self, simple_node, backends_combination, categories):
        '''Requests all possible combination of categories and backends one by one and checks statistics'''
        session = make_session(node=simple_node,
                               test_name='TestSession.test_monitor_categories_and_backends')

        address = session.routes.addresses()[0]

        start = datetime.now()
        entry = session.monitor_stat(address,
                                     categories=categories,
                                     backends=backends_combination).get()[0]
        try:
            assert type(entry.address) is elliptics.Address
            json_stat = entry.statistics
        except Exception as e:
            with open("monitor.stat.json", "w") as f:
                f.write(entry.__statistics__)
            raise e
        end = datetime.now()

        checker = MonitorStatsChecker(json_statistics=json_stat,
                                      time_period=(start, end),
                                      categories=categories,
                                      address=address,
                                      routes=session.routes,
                                      backends_combination=backends_combination)
        checker.check_json_stat()
