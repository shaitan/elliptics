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

#    return PassthroughWrapper(n, s)
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
