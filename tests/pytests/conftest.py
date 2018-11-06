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
import collections
import multiprocessing.dummy
import os
import sys

import mock

sys.path.insert(0, "")  # for running from cmake

import pytest

import elliptics

from server import Servers
from server import make_servers


def pytest_addoption(parser):
    parser.addoption('--remotes', action='append', default=[],
                     help='Elliptics node address')
    parser.addoption('--groups', action='store', help='elliptics groups', default='1,2,3')
    parser.addoption('--loglevel', type='choice', choices=xrange(5), default=elliptics.log_level.debug)

    parser.addoption('--backends-count', action='store', default=2,
                     help='Number of backends that will be enabled per group on node')
    parser.addoption('--nodes-count', action='store', default=2,
                     help='Number of nodes that should be run')
    parser.addoption('--recovery-keys', action='store', default=10,
                     help='Number of keys that would be used at test_recovery')


def set_property(obj, prop, value, check_value=None,
                 getter=None, setter=None):
    check_value = check_value if check_value else value
    setattr(obj, prop, value)
    assert getattr(obj, prop) == check_value
    if setter:
        getattr(obj, setter)(value)
    assert getattr(obj, prop) == check_value
    if getter:
        assert getattr(obj, getter)() == check_value
    assert getattr(obj, prop) == check_value


def raises(type, message, func, *args, **kwargs):
    exception = pytest.raises(type, func, *args, **kwargs)
    assert exception.value.message == message


class PassthroughWrapper(object):
    ''' Wrapper to assure session/node destroy sequence: session first, node last '''
    def __init__(self, node, session):
        self.node = node
        self.session = session

    def __getattr__(self, name):
        return getattr(self.session, name)

    def __del__(self):
        del self.session
        del self.node


def connect(endpoints, groups, **kw):
    remotes = []
    for r in endpoints:
        remotes.append(elliptics.Address.from_host_port_family(r))

    def rename(kw, old, new):
        if old in kw:
            kw[new] = kw.pop(old)

    # drop impeding attrs, just in case
    kw.pop('elog', None)
    kw.pop('cfg', None)
    kw.pop('remotes', None)
    # rename good names to required bad ones
    rename(kw, 'logfile', 'log_file')
    rename(kw, 'loglevel', 'log_level')

    n = elliptics.create_node(**kw)
    n.add_remotes(remotes)

    s = elliptics.Session(n)
    s.add_groups(groups)

    # return PassthroughWrapper(n, s)
    return s


def make_trace_id(test_name):
    import hashlib
    return int(hashlib.sha512(test_name).hexdigest(), 16) % (1 << 64)


def make_session(node, test_name, test_namespace=None):
    session = elliptics.Session(node)
    session.trace_id = make_trace_id(test_name)
    if test_namespace:
        session.set_namespace(test_namespace)
    return session


#
# Fixtures to use in tests
#

@pytest.yield_fixture(scope="session")
def servers(request):
    '''
    Creates elliptics server nodes to work against.
    Returns node ensemble configuration.
    '''
    groups = [int(g) for g in request.config.option.groups.split(',')]

    _servers = Servers(servers=make_servers(groups, int(request.config.option.nodes_count),
                                            int(request.config.option.backends_count)))

    request.config.option.remotes = _servers.remotes
    request.config.option.monitors = _servers.monitors

    yield _servers

    _servers.stop()


@pytest.fixture(scope='session')
def elliptics_client(request):
    '''
    Initializes client connection to elliptics.
    Returns Session object.
    '''
    if len(request.config.option.remotes) == 0:
        pytest.fail('`elliptics_client` fixture should go after `server` fixture, check your test')
    remote = request.config.option.remotes
    groups = [int(g) for g in request.config.option.groups.split(',')]
    loglevel = request.config.option.loglevel
    logfile = 'client.log'
    return connect(remote, groups, loglevel=loglevel, logfile=logfile)
    # client = connect([remote], groups, loglevel=loglevel)
    # client.set_filter(elliptics.filters.all_with_ack)
    # return client


@pytest.fixture(scope='session')
def simple_node(request):
    if len(request.config.option.remotes) == 0:
        pytest.fail('`simple_node` fixture should go after `server` fixture, check your test')
    simple_node = elliptics.Node(elliptics.Logger("client.log", elliptics.log_level.debug))
    simple_node.add_remotes(request.config.option.remotes)
    return simple_node


@pytest.fixture(scope="class", autouse=True)
def scope():
    '''
    Scope fixture for sharing info between test cases.
    '''
    class Scope():
        def __repr__(self):
            return '{0}'.format(vars(self))
    return Scope()


@pytest.fixture(scope="session")
def routes(simple_node):
    '''
    Initializes session.
    Returns routes list.
    '''
    return make_session(node=simple_node,
                        test_name='Fixture.backends').routes


@pytest.fixture(scope="session",
                params=["none", "empty", "one_real", "all", "repeating", "part",
                        "unreal", "one_unreal", "mix"])
def backends_combination(request, routes):
    '''
    Creates variable fixture with all combinations of backends.
    Return list with backends ids.
    '''
    all_backends = list(routes.get_address_backends(routes.addresses()[0]))
    if request.param == "none":
        return None
    elif request.param == "empty":
        return []
    elif request.param == "one_real":
        return all_backends[:1]
    elif request.param == "all":
        return all_backends
    elif request.param == "repeating":
        return all_backends + all_backends
    elif request.param == "part":
        return all_backends[:len(all_backends) / 2]
    elif request.param == "unreal":
        return range(max(all_backends) + 1, max(all_backends) + 3)
    elif request.param == "one_unreal":
        return [max(all_backends) + 1]
    elif request.param == "mix":
        return all_backends + range(max(all_backends) + 1, max(all_backends) + 3)
    return None


@pytest.fixture()
def mock_pool(mocker):
    """Mock multiprocessing.Pool and use multiprocessing.dummy.Pool instead

    By this mock we avoid creating sub-processes and transferring other mocks between them.
    """
    mocker.patch('multiprocessing.Pool', mock.MagicMock(return_value=multiprocessing.dummy.Pool()))


@pytest.fixture()
def mock_elliptics(mocker):
    """Mock most of elliptics components

    To be able overwrite their behaviour and avoid heavy initialization.
    """
    mocker.patch('elliptics.Node')
    mocker.patch('elliptics.Logger')
    mocker.patch('elliptics.create_node')
    mocker.patch('elliptics.Session')
    mocker.patch('elliptics.newapi.Session')


@pytest.fixture()
def mock_route_list(mock_elliptics, cluster):
    """Mock route-list based on test configuration described in @cluster

    Mock route-list in both old and new session.
    """
    elliptics.Session.return_value.routes = cluster.route_list
    elliptics.newapi.Session.return_value.routes = cluster.route_list


@pytest.fixture()
def mock_iterator_result_container(mocker):
    """Mock IteratorResultContainer

    Original IteratorResultContainer works only with specific structure and can't be used with mocked results.
    """

    def container_side_effect():
        containers = collections.defaultdict(list)

        def side_effect(fd, *_args):
            # read real filename because recovery re-opens files and fd itself can be different
            # for the same files
            return containers[os.readlink('/proc/self/fd/{}'.format(fd))]

        return side_effect

    mocker.patch('elliptics.core.newapi.IteratorResultContainer',
                 mocker.MagicMock(side_effect=container_side_effect()))


class MockedRecordInfo(object):
    """Simple mock for record_info available from IteratorResultEntry"""
    def __init__(self, record_flags):
        self.record_flags = record_flags


class MockedIteratorResult(object):
    """Simple mock for IteratorResultEntry with minimal coverage"""
    def __init__(self, key, user_flags, data_timestamp, data_size, status, record_flags, blob_id, data_offset, iterated_keys, total_keys):
        self.key = key
        self.user_flags = user_flags
        self.data_timestamp = data_timestamp
        self.data_size = data_size
        self.status = status
        self.record_info = MockedRecordInfo(record_flags=record_flags)
        self.record_flags = record_flags
        self.blob_id = blob_id
        self.data_offset = data_offset
        self.iterated_keys = iterated_keys
        self.total_keys = total_keys

    def __cmp__(self, other):
        return cmp(self.key, other.key)


@pytest.fixture()
def mock_iterator(mock_iterator_result_container, cluster):
    """Mock iterator results based on initial configuration described in @cluster"""

    def iterator_side_effect(address, backend_id, **_kwargs):
        """Returns different results for different address & backend_id based on initial configuration

        defined by @cluster"""
        records = []
        for backend in cluster.backends:
            if backend.address != address or backend.backend_id != backend_id:
                continue

            records = [
                MockedIteratorResult(key=record.key,
                                     user_flags=record.user_flags,
                                     data_timestamp=record.data_timestamp,
                                     data_size=record.data_size,
                                     status=record.status,
                                     record_flags=record.record_flags,
                                     blob_id=record.blob_id,
                                     data_offset=record.data_offset,
                                     iterated_keys=i,
                                     total_keys=len(backend.records))
                for i, record in enumerate(backend.records, start=1)
            ]

        return mock.MagicMock(spec=elliptics.core.AsyncResult,
                              __iter__=mock.MagicMock(return_value=iter(records)))

    elliptics.newapi.Session.return_value.start_iterator.side_effect = iterator_side_effect
