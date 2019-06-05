import os
import shutil
import stat
import time
from contextlib import contextmanager

import elliptics
import pytest

from server import Servers


@pytest.fixture(scope='function')
def testdir(tmpdir):
    """Fixture for auto-removing temporary directory after test"""
    ret = tmpdir
    yield ret
    shutil.rmtree(str(ret))


@contextmanager
def run_server(group_id, records_in_blob, path, datasort_dir=None, single_pass_threshold=None):
    """Run server under contextmanager, so it will be killed at exit.

    Server will be run with one backend in @group, all other parameters will be placed into config

    Args:
        group_id(int): id of the group which should be served by the backend
        records_in_blob(int): limit for a blob in the backend
        path(str or None): where backend should store its blobs (if None use default provided by test env)
        datasort_dir(str or None): where backend should store temporary chunks during defrag
            (if None use temporary directory at @path)

    Yields:
        Servers: configured server with one backend and specified paramters.
    """
    config = [{
        'backends': [{
            'group': group_id,
            'records_in_blob': records_in_blob,
            'periodic_timeout': 1,
        }]
    }]

    # set datasort_dir only if it is provided
    if datasort_dir is not None:
        config[0]['backends'][0]['datasort_dir'] = datasort_dir

    if single_pass_threshold is not None:
        config[0]['backends'][0]['single_pass_file_size_threshold'] = single_pass_threshold
    server = Servers(servers=config, path=path)

    try:
        yield server
    finally:
        server.stop()


def execute_defrag(session, remote, backend_id, chunks_dir, compact):
    """Run and wait defrag and check its status via monitor stats

    Args:
        session(elliptics.Session or elliptics.newapi.Session): session connected to the node
        remote(str): address of the node
        backend_id(int): id of the backend where defrag should be triggered
        chunks_dir(str or None): optional chunks_dir where defrag should store temporary chunks
        compact(bool): whether compact or defrag should be triggered
    """
    remote = elliptics.Address.from_host_port_family(remote)

    start = int(time.time())

    # choose defrag method
    defrag_method = session.start_compact if compact else session.start_defrag

    if chunks_dir is None:
        # use short call if chunks_dir isn't specified
        results = defrag_method(remote, backend_id)
    else:
        results = defrag_method(remote, backend_id, chunks_dir)

    # there should be the only result, so get it
    result = results.get()[0]

    # choose which defrag state should be set by backend
    defrag_state = elliptics.defrag_state.compact if compact else elliptics.defrag_state.data_sort

    # there is the only backend
    assert len(result.backends) == 1
    status = result.backends[0]
    # check its backend_id
    assert status.backend_id == backend_id
    # check its defrag state
    assert status.defrag_state == defrag_state

    # wait while defrag_state isn't reset
    while status.defrag_state == defrag_state:
        result = session.request_backends_status(remote).get()[0]
        assert len(result.backends) == 1
        status = result.backends[0]
        assert status.backend_id == backend_id

    end = int(time.time())

    # sleep 1.5 second while backend updates cached statistics
    time.sleep(1.5)

    result = session.monitor_stat(remote,
                                  categories=elliptics.monitor_stat_categories.backend,
                                  backends=[backend_id]).get()[0]

    # fetch backend's global statistics which contains info about last defrag
    global_stat = result.statistics['backends']['0']['backend']['global_stats']
    # check start/end time from statistics
    assert start <= global_stat['datasort_start_time'] <= global_stat['datasort_completion_time'] <= end
    # check that last defrag completed without errors
    assert global_stat['datasort_completion_status'] == 0


def prepare_session(testdir, remote, group_id):
    """Initialize and return session for specified remote

    Args:
        testdir: fixture for test's temporary dirs/files
        remote(str): address of the node
        group_id(int): id of the group to work with

    Returns:
        elliptics.newapi.Session: session configured for working with the backend
    """
    node = elliptics.create_node(log_file=str(testdir.join("client.log")),
                                 log_level=elliptics.log_level.debug,
                                 remotes=[remote])

    session = elliptics.newapi.Session(node)
    session.groups = [group_id]
    return session


def write_n_records(session, n):
    """Write n records

    Args:
        session(elliptics.Session): session which should be used for write
        n(int): number of records to write
    """
    results = [session.write_data('a' + str(i), 'aaa') for i in range(n)]

    for result in results:
        result.wait()


def remove_n_records(session, n):
    """Remove n records

    Args:
        session(elliptics.Session): session which should be used for remote
        n(int): number of records to remove
    """
    results = [session.remove('a' + str(i)) for i in range(n)]

    for result in results:
        result.wait()


@pytest.mark.parametrize('request_dir', [False, True])  # whether chunks_dir in start_defrag should be specified
@pytest.mark.parametrize('configure_dir', [False, True])  # whether datasort_dir in config should be specified
def test_defrag_chunks_dir(testdir, configure_dir, request_dir):
    """Run defrag on one prepared blob and check result

    Result checked via monitor statistics which includes info about last defrag,
    so it should be done in expected time range and without any error.
    """
    # group_id doesn't matter
    group_id = 1
    # number of records doesn't matter
    records_in_blob = 10

    datasort_dir = None
    if configure_dir:
        datasort_dir = str(testdir.mkdir('config_datasort_dir'))

    with run_server(group_id=group_id,
                    records_in_blob=records_in_blob,
                    path=str(testdir.join('servers')),
                    datasort_dir=datasort_dir) as server:
        session = prepare_session(testdir, server.remotes[0], group_id=group_id)

        # write 11 keys to fill 1 blob and second
        write_n_records(session, n=records_in_blob + 1)

        chunks_dir = None
        if request_dir:
            chunks_dir = str(testdir.mkdir('requested_datasort_dir'))

            # lock datasort_dir specified in the config to guarantee that it won't be used
            if datasort_dir is not None:
                os.chmod(datasort_dir, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)

        execute_defrag(session, server.remotes[0], 0, chunks_dir, compact=False)


def test_compact_chunks_dir(testdir):
    """Run compact on one prepared blob and check result

    Result checked via monitor statistics which includes info about last defrag,
    so it should be done in expected time range and without any error.

    Note:
        There is no need to use the same parametrize from test_defrag_chunks_dir because
        compact differs from defrag only in the way which blobs should be handled.
        So this test is needed only to cover API (elliptics.newapi.Sesion.start_compact call).
    """
    # group_id doesn't matter
    group_id = 1
    # number of records doesn't matter
    records_in_blob = 10

    datasort_dir = str(testdir.mkdir('config_datasort_dir'))
    os.chmod(datasort_dir, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)

    with run_server(group_id=group_id,
                    records_in_blob=records_in_blob,
                    path=str(testdir.join('servers')),
                    datasort_dir=datasort_dir) as server:
        session = prepare_session(testdir, server.remotes[0], group_id=group_id)

        # write 11 keys to fill 1 blob and second
        write_n_records(session, n=records_in_blob + 1)
        # remove first half of the keys to make compact defrag the first blob
        remove_n_records(session, n=records_in_blob / 2)

        chunks_dir = str(testdir.mkdir('requested_datasort_dir'))

        execute_defrag(session, server.remotes[0], 0, chunks_dir, compact=True)

@pytest.mark.parametrize('single_pass_threshold', [0, 42])
def test_single_pass_threshold(testdir, single_pass_threshold):
    """Check whether eblob parameters specific to defrag are passed correctly to backend"""
    # group_id doesn't matter
    group_id = 1
    # number of records doesn't matter
    records_in_blob = 10

    with run_server(group_id=group_id,
                    records_in_blob=records_in_blob,
                    path=str(testdir.join('servers')),
                    single_pass_threshold=single_pass_threshold) as server:
        # prepare session
        session = prepare_session(testdir, server.remotes[0], group_id=group_id)

        # check that single_pass_file_size_threshold is correct in config fetched from stat
        future = session.monitor_stat(categories=elliptics.monitor_stat_categories.backend, backends=[0])
        stats = future.get()[0].statistics
        assert stats["backends"]["0"]["backend"]["config"]["single_pass_file_size_threshold"] == single_pass_threshold

        # disable backend
        addr = elliptics.Address.from_host_port_family(server.remotes[0])
        session.disable_backend(addr, 0).wait()

        # check that config value fetched from elliptics is still present
        future = session.monitor_stat(categories=elliptics.monitor_stat_categories.backend, backends=[0])
        stats = future.get()[0].statistics
        assert stats["backends"]["0"]["backend"]["config"]["single_pass_file_size_threshold"] == single_pass_threshold
