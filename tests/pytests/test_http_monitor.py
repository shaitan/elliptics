# =============================================================================
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
import zlib
import json
from datetime import datetime
try:
    import urllib.request as urllib_req
except ImportError:
    import urllib2 as urllib_req
from statistics_checker import MonitorStatsChecker
from statistics_checker import categories_combination

import elliptics

PATH_CATEGORIES = {"/cache": elliptics.core.monitor_stat_categories.cache,
                   "/io": elliptics.core.monitor_stat_categories.io,
                   "/commands": elliptics.core.monitor_stat_categories.commands,
                   "/backend": elliptics.core.monitor_stat_categories.backend,
                   "/stats": elliptics.core.monitor_stat_categories.stats,
                   "/procfs": elliptics.core.monitor_stat_categories.procfs,
                   "/top": elliptics.core.monitor_stat_categories.top,
                   "/all": elliptics.core.monitor_stat_categories.all}

# this response must be equal to the content_string::list from /monitor/http_miscs.hpp
HTTP_DEFAULT_RESPONSE = "<html>\n" \
                        "\t<body>\n" \
                        "\t\tGET <a href='/list'>/list</a> - Retrieves a list of acceptable statistics<br/>\n" \
                        "\t\tGET <a href='/all'>/all</a> - Retrieves all statistics from all submodules<br/>\n" \
                        "\t\tGET <a href='/cache'>/cache</a> - Retrieves statistics about cache<br/>\n" \
                        "\t\tGET <a href='/io'>/io</a> - Retrieves statistics about io statistics<br/>\n" \
                        "\t\tGET <a href='/commands'>/commands</a> - Retrieves statistics about commands<br/>\n" \
                        "\t\tGET <a href='/backend'>/backend</a> - Retrieves statistics about backend<br/>\n" \
                        "\t\tGET <a href='/stats'>/stats</a> - Retrieves in-process runtime statistics<br/>\n" \
                        "\t\tGET <a href='/procfs'>/procfs</a> - Retrieves system statistics about process<br/>\n" \
                        "\t\tGET <a href='/top'>/top</a> - " \
                        "Retrieves statistics of top keys ordered by generated traffic<br/>\n" \
                        "\t</body>\n" \
                        "</html>";

@pytest.fixture(scope="session")
def address(servers):
    return elliptics.Address.from_host_port_family(servers.remotes[0]), \
           '{}:{}'.format(servers.remotes[0].split(':')[0], servers.monitors[0])


class TestHttpMonitor:

    @pytest.mark.usefixtures("servers")
    def test_http_statistics_with_non_int_categories(self, address):
        '''Requests statistics with non int categories. Server mast return default responce'''

        url = 'http://{}/?categories=not_int'.format(address[1])
        responce = urllib_req.urlopen(url).read()
        assert responce == HTTP_DEFAULT_RESPONSE

    @pytest.mark.usefixtures("servers")
    def test_http_statistics_with_empty_categories(self, address):
        '''Requests statistics with empty categories. Server mast return default responce'''

        url = 'http://{}/?categories='.format(address[1])
        responce = urllib_req.urlopen(url).read()
        assert responce == HTTP_DEFAULT_RESPONSE

    @pytest.mark.usefixtures("servers")
    def test_http_statistics_with_non_int_backends(self, address):
        '''Requests statistics with non int backends. Server mast return default responce'''

        url = 'http://{}/all?backends=non_int,2'.format(address[1])
        responce = urllib_req.urlopen(url).read()
        assert responce == HTTP_DEFAULT_RESPONSE

    @pytest.mark.usefixtures("servers")
    def test_http_statistics_with_bad_parametrs(self, address, routes):
        '''Requests statistics with valid path and bad get parametrs. Server mast ignore unknown parametrs'''

        url = 'http://{}/all?1param=1value&2param=&=3value'.format(address[1])

        start = datetime.now()
        json_stat = self.__get_statistics(url)
        end = datetime.now()

        checker = MonitorStatsChecker(json_statistics=json_stat,
                                      time_period=(start, end),
                                      categories=PATH_CATEGORIES['/all'],
                                      address=address[0],
                                      routes=routes)
        checker.check_json_stat()

    @pytest.mark.parametrize("path", PATH_CATEGORIES.keys())
    @pytest.mark.usefixtures("servers")
    def test_http_statistics_by_path(self, address, routes, backends_combination, path):
        '''Requests all possible combination of path and backends one by one and checks statistics'''

        start = datetime.now()
        json_stat = self.__get_statistics_by_path(address=address[1],
                                                  path=path,
                                                  backends=backends_combination)
        end = datetime.now()

        checker = MonitorStatsChecker(json_statistics=json_stat,
                                      time_period=(start, end),
                                      categories=PATH_CATEGORIES[path],
                                      address=address[0],
                                      routes=routes,
                                      backends_combination=backends_combination)
        checker.check_json_stat()

    @pytest.mark.parametrize("categories", categories_combination())
    @pytest.mark.usefixtures("servers")
    def test_http_statistics_by_category(self, address, routes, backends_combination, categories):
        '''Requests all possible combination of categories and backends one by one and checks statistics'''

        start = datetime.now()
        json_stat = self.__get_statistics_by_categories(address=address[1],
                                                        categories=categories,
                                                        backends=backends_combination)
        end = datetime.now()

        checker = MonitorStatsChecker(json_statistics=json_stat,
                                      time_period=(start, end),
                                      categories=categories,
                                      address=address[0],
                                      routes=routes,
                                      backends_combination=backends_combination)
        checker.check_json_stat()

    def __get_statistics_by_path(self, address, path, backends=None):
        url = 'http://{}{}'.format(address, path)
        if backends is not None:
            url = '{}?backends={}'.format(url, ','.join(str(i) for i in backends))
        return self.__get_statistics(url)

    def __get_statistics_by_categories(self, address, categories, backends=None):
        url = 'http://{}/?categories={}'.format(address, str(categories))
        if backends is not None:
            url = '{}&backends={}'.format(url, ','.join(str(i) for i in backends))
        return self.__get_statistics(url)

    @staticmethod
    def __get_statistics(url):
        data = urllib_req.urlopen(url).read()
        json_data = zlib.decompress(data)
        # convert json to python dict
        return json.loads(json_data)
