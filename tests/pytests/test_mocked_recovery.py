import errno
import hashlib

import elliptics
import mock
import pytest

from test_recovery import RECOVERY
from test_recovery import recovery


class DummyRecord(object):
    """Support structure for internal presentation of a record

    Attributes:
        key (elliptics.Id): record's id
        user_flags (int): any user-defined flags
        data_timestamp (elliptics.Time): timestamp of the record
        data_size (long): size of record's data
        status (int): status that should be assigned to the record during iteration. Is it needed?
        record_flags (int): eblob-level flags of the record
        blob_id (int): id of the blob where eblob stores the record
        data_offset (long): offset within the blob where record's data starts
    """

    def __init__(self,
                 key,
                 user_flags=100500,
                 data_timestamp=elliptics.Time(100, 500),
                 data_size=100,
                 status=0,
                 record_flags=0,
                 blob_id=0,
                 data_offset=0):
        self.key = elliptics.Id.from_hex(hashlib.sha512(key).hexdigest())
        self.user_flags = user_flags
        self.data_timestamp = data_timestamp
        self.data_size = data_size
        self.status = status
        self.record_flags = record_flags
        self.blob_id = blob_id
        self.data_offset = data_offset


class Backend(object):
    """Support structure for internal presentation of a backend and its records

    Attributes:
        address (elliptics.Address): network address of the node where this backend lives
        backend_id (int): id of the backend
        group_id (int): id of the group that backend serves
        records ([DummyRecord]): list of records that backend has, mostly used as initial state for iterator.
    """
    def __init__(self, address, backend_id, group_id, records=None):
        self.address = elliptics.Address.from_host_port(address)
        self.backend_id = backend_id
        self.group_id = group_id

        self.records = records or []

    def route(self, key):
        return elliptics.Route(id=elliptics.Id(key, self.group_id),
                               address=self.address,
                               backend_id=self.backend_id)

    def first_route(self):
        return self.route([0x00] * 64)

    def last_route(self):
        return self.route([0xff] * 64)


class Cluster(object):
    """Support structure for internal presentation of a cluster

    Attributes:
        backends ([Backend]): list of backends cluster consists of.
    """
    def __init__(self, backends):
        self.backends = backends

    @property
    def route_list(self):
        """Route-list for configured cluster

        :rtype: elliptics.RouteList
        """
        routes = ([backend.first_route() for backend in self.backends] +
                  [backend.last_route() for backend in self.backends])
        return elliptics.RouteList(routes=routes)

    @property
    def remotes(self):
        """Remotes of all nodes presented in cluster

        :rtype: [str]
        """
        return [str(backend.address) for backend in self.backends]

    @property
    def groups(self):
        """Groups that are presented in cluster

        :rtype: [int]
        """
        return [backend.group_id for backend in self.backends]


@pytest.mark.parametrize('cluster', [Cluster([
    Backend(address='121.0.0.1:1', backend_id=1, group_id=1, records=[
        DummyRecord(key='the only alive record')
    ]),
    Backend(address='121.0.0.2:2', backend_id=2, group_id=2),
])])
@pytest.mark.usefixtures('mock_route_list', 'mock_iterator', 'mock_pool')
def test_recover_of_one_key(cluster):
    """Test the case when cluster consists of 2 groups on different nodes and one of it has the only alive record.

    Expect: the record will be server-sent to second group.
    """
    mocked_server_send = elliptics.newapi.Session.return_value.server_send
    mocked_server_send.return_value = [mock.MagicMock()]

    recovery(one_node=False,
             remotes=cluster.remotes,
             backend_id=None,
             address=None,
             groups=cluster.groups,
             rtype=RECOVERY.DC,
             log_file='recovery.log',
             tmp_dir='test_recover_of_one_key',
             no_meta=True,
             no_server_send=False,
             expected_ret_code=0)

    # expect that server-send will be called for the only record
    mocked_server_send.assert_called_once_with(keys=[record.key for record in cluster.backends[0].records],
                                               src_group=cluster.backends[0].group_id,
                                               dst_groups=[cluster.backends[1].group_id],
                                               flags=0,
                                               chunk_commit_timeout=1000,
                                               chunk_retry_count=0,
                                               chunk_size=1024,
                                               chunk_write_timeout=1000)


@pytest.mark.parametrize('cluster', [Cluster([
    Backend(address='121.0.0.1:1', backend_id=1, group_id=1, records=[
        DummyRecord(key='uncommitted key', record_flags=elliptics.record_flags.uncommitted)
    ]),
    Backend(address='121.0.0.2:2', backend_id=2, group_id=2),
])])
@pytest.mark.usefixtures('mock_route_list', 'mock_iterator', 'mock_pool')
def test_recover_of_one_uncommitted_key(cluster):
    """Test the case when cluster consists of 2 groups on different nodes and one of it has the only uncommitted record.

    Uncommitted record is also out-dated.

    Expect: the record will be removed and nothing will be server-sent.
    """
    mocked_remove = elliptics.newapi.Session.return_value.remove
    mocked_remove.return_value.get.return_value = [mock.MagicMock()]

    mocked_server_send = elliptics.newapi.Session.return_value.server_send

    recovery(one_node=False,
             remotes=cluster.remotes,
             backend_id=None,
             address=None,
             groups=cluster.groups,
             rtype=RECOVERY.DC,
             log_file='recovery.log',
             tmp_dir='test_recover_of_one_uncommitted_key',
             no_meta=True,
             no_server_send=False,
             expected_ret_code=0)

    # nothing should be server-sent
    mocked_server_send.assert_not_called()

    # uncommitted key should be removed
    mocked_remove.assert_called_once_with(cluster.backends[0].records[0].key)


@pytest.mark.parametrize('cluster', [Cluster([
    Backend(address='121.0.0.1:1', backend_id=1, group_id=1, records=[
        DummyRecord(key='test key'),
    ]),
    Backend(address='121.0.0.2:1', backend_id=1, group_id=2, records=[
        DummyRecord(key='test key'),
    ]),
    Backend(address='121.0.0.3:1', backend_id=1, group_id=3)
])])
@pytest.mark.usefixtures('mock_route_list', 'mock_iterator', 'mock_pool')
@pytest.mark.parametrize('error', [
    -errno.ETIMEDOUT,
    -errno.ENOSPC,
    -errno.EBADFD,
    -errno.ECONNRESET,
    -errno.EINVAL,
    -errno.EIO,
    -errno.EBADF,
    -errno.ESPIPE,
    -errno.EROFS,
    -errno.EPIPE,
    # TODO(shaitan): -errno.ENXIO - Leads to downgrading to READ/WRITE recovery and hangs
])
def test_server_send_with_destination_failure(cluster, error):
    """Test the case when the key should be recovered from two groups to third, but third group response with an error

    Make second try of server-send successful.

    Expect: server-send will be called twice for different groups and recovery will be successful. The key shouldn't be
    server-sent from second group to first one.
    """
    test_key = cluster.backends[0].records[0].key

    mocked_server_send = elliptics.newapi.Session.return_value.server_send

    mocked_server_send.side_effect = [
        mock.MagicMock(__iter__=mock.MagicMock(return_value=iter([
            mock.MagicMock(key=test_key,
                           status=error)
        ]))),
        mock.MagicMock(__iter__=mock.MagicMock(return_value=iter([
            mock.MagicMock(key=test_key,
                           status=0)
        ])))
    ]

    recovery(one_node=False,
             remotes=cluster.remotes,
             backend_id=None,
             address=None,
             groups=cluster.groups,
             rtype=RECOVERY.DC,
             log_file='recovery.log',
             tmp_dir='test_failed_server_send' + str(error),
             no_meta=True,
             no_server_send=False,
             expected_ret_code=0)

    # server-send should be called twice
    assert mocked_server_send.call_count == 2
    mocked_server_send.assert_has_calls(calls=[
        mock.call(keys=[test_key],
                  flags=0,  # default flags
                  chunk_size=1024,  # default chunk_size
                  src_group=cluster.backends[0].group_id,  # first try should be to first group
                  dst_groups=[cluster.backends[2].group_id],  # both try should use only third group as a destination
                  chunk_write_timeout=1000,  # default timeout
                  chunk_commit_timeout=1000,  # default timeout
                  chunk_retry_count=0),  # default retry count
        mock.call(keys=[test_key],
                  flags=0,  # default flags
                  chunk_size=1024,  # default chunk_size
                  src_group=cluster.backends[1].group_id,  # second try should be to second group
                  dst_groups=[cluster.backends[2].group_id],  # both try should use only third group as a destination
                  chunk_write_timeout=1000,  # default timeout
                  chunk_commit_timeout=1000,  # default timeout
                  chunk_retry_count=0),  # default retry count
    ])


@pytest.mark.parametrize('cluster', [Cluster([
    Backend(address='121.0.0.1:1', backend_id=1, group_id=1, records=[
        DummyRecord(key='test key'),
    ]),
    Backend(address='121.0.0.2:1', backend_id=1, group_id=2, records=[
        DummyRecord(key='test key'),
    ]),
    Backend(address='121.0.0.3:1', backend_id=1, group_id=3)
])])
@pytest.mark.usefixtures('mock_route_list', 'mock_iterator', 'mock_pool')
@pytest.mark.parametrize('error', [
    -errno.EILSEQ,
    -errno.ERANGE,
    # TODO(shaitan): -errno.ENOENT - doesn't lead to copying a key to first group
])
def test_server_send_with_source_failure(cluster, error):
    """Test the case when the key should be recovered from two groups to third, but first group is experiencing an error

    Make second try of server-send successful.

    Expect: server-send will be called twice for different groups and recovery will be successful. The key should be
    server-sent from second group to first one.
    """
    test_key = cluster.backends[0].records[0].key

    mocked_server_send = elliptics.newapi.Session.return_value.server_send

    mocked_server_send.side_effect = [
        mock.MagicMock(__iter__=mock.MagicMock(return_value=iter([
            mock.MagicMock(key=test_key,
                           status=error)
        ]))),
        mock.MagicMock(__iter__=mock.MagicMock(return_value=iter([
            mock.MagicMock(key=test_key,
                           status=0)
        ])))
    ]

    recovery(one_node=False,
             remotes=cluster.remotes,
             backend_id=None,
             address=None,
             groups=cluster.groups,
             rtype=RECOVERY.DC,
             log_file='recovery.log',
             tmp_dir='test_failed_server_send' + str(error),
             no_meta=True,
             no_server_send=False,
             expected_ret_code=0)

    # server-send should be called twice
    assert mocked_server_send.call_count == 2
    mocked_server_send.assert_has_calls(calls=[
        mock.call(keys=[test_key],
                  flags=0,  # default flags
                  chunk_size=1024,  # default chunk_size
                  src_group=cluster.backends[0].group_id,  # first try should be to first group
                  dst_groups=[cluster.backends[2].group_id],  # first try should use third group as a destination
                  chunk_write_timeout=1000,  # default timeout
                  chunk_commit_timeout=1000,  # default timeout
                  chunk_retry_count=0),  # default retry count
        mock.call(keys=[test_key],
                  flags=0,  # default flags
                  chunk_size=1024,  # default chunk_size
                  src_group=cluster.backends[1].group_id,  # second try should be to second group
                  # second try should use first and third groups as destinations
                  dst_groups=[cluster.backends[0].group_id, cluster.backends[2].group_id],
                  chunk_write_timeout=1000,  # default timeout
                  chunk_commit_timeout=1000,  # default timeout
                  chunk_retry_count=0),  # default retry count
    ])


@pytest.mark.parametrize('cluster', [Cluster([
    Backend(address='121.0.0.1:1', backend_id=1, group_id=1, records=[
        DummyRecord(key='key with different replicas in two groups and missed in third'),
        DummyRecord(key='key missed in second group #1'),
        DummyRecord(key='key missed in second group #2'),
        DummyRecord(key='key uncommitted in third group'),
    ]),
    Backend(address='121.0.0.2:1', backend_id=1, group_id=2, records=[
        DummyRecord(key='key with different replicas in two groups and missed in third',
                    data_timestamp=elliptics.Time(101, 500)),
    ]),
    Backend(address='121.0.0.3:1', backend_id=1, group_id=3, records=[
        DummyRecord(key='key missed in second group #1'),
        DummyRecord(key='key missed in second group #2'),
        DummyRecord(key='key uncommitted in third group', record_flags=elliptics.record_flags.uncommitted),
    ])
])])
@pytest.mark.usefixtures('mock_route_list', 'mock_iterator', 'mock_pool')
def test_specific_case_with_readonly_groups(cluster):
    """Test the case when old version of recovery did wrong and left some keys non-recovered.

    Initial state:
        group #1 and #2 marked read-only
        the key that is presented in group #1 and #2 but group #2 has newer version of the key
        two keys that are presented in group #1 and #3
        the key that is presented in group #1 and uncommitted in group #3

    Expect: uncommitted replica will be removed from group #3 and will be server-sent from group #1 to #3,
    the key with different replicas will be server-sent from group #2 to #3.
    """
    mocked_remove = elliptics.newapi.Session.return_value.remove
    mocked_remove.return_value.get.return_value = [mock.MagicMock(status=0)]

    uncommitted_key = elliptics.Id.from_hex(
        hashlib.sha512('key uncommitted in third group').hexdigest()
    )

    different_replicas_key = elliptics.Id.from_hex(
        hashlib.sha512('key with different replicas in two groups and missed in third').hexdigest()
    )

    mocked_server_send = elliptics.newapi.Session.return_value.server_send
    mocked_server_send.side_effect = [
        mock.MagicMock(__iter__=mock.MagicMock(return_value=iter([
            mock.MagicMock(key=uncommitted_key,
                           status=0),
        ]))),
        mock.MagicMock(__iter__=mock.MagicMock(return_value=iter([
            mock.MagicMock(key=different_replicas_key,
                           status=0),
        ]))),
    ]

    recovery(one_node=False,
             remotes=cluster.remotes,
             backend_id=None,
             address=None,
             groups=cluster.groups,
             rtype=RECOVERY.DC,
             log_file='recovery.log',
             tmp_dir='test_specific_case_with_readonly_groups',
             no_meta=True,
             no_server_send=False,
             expected_ret_code=0,
             ro_groups={1, 2})

    # uncommitted key should be removed from third group
    mocked_remove.assert_called_once_with(uncommitted_key)

    mocked_server_send.assert_has_calls(calls=[
        mock.call(keys=[uncommitted_key],  # firstly uncommitted key should be recovered
                  flags=0,  # default flags
                  chunk_size=1024,  # default chunk_size
                  # first server-send should be sent to group #1 because it has the largest number of keys to recover
                  src_group=1,
                  dst_groups=[3],  # the key should be server-sent to group #3
                  chunk_write_timeout=1000,  # default timeout
                  chunk_commit_timeout=1000,  # default timeout
                  chunk_retry_count=0),  # default retry count
        mock.call(keys=[different_replicas_key],  # secondly key with different replicas should be recovered
                  flags=0,  # default flags
                  chunk_size=1024,  # default chunk_size
                  # second server-send should be to group #2, because all other server-sends should be skipped
                  # since group #1 and #2 are read-only
                  src_group=2,
                  dst_groups=[3],  # the key should be server-sent to group #3
                  chunk_write_timeout=1000,  # default timeout
                  chunk_commit_timeout=1000,  # default timeout
                  chunk_retry_count=0),  # default retry count
    ])

    # only the two calls above should be made
    assert mocked_server_send.call_count == 2
