import elliptics

import errno
import json

import pytest

from conftest import make_trace_id


@pytest.mark.usefixtures('servers')
def test_lookup_read_nonexistent_key(simple_node):
    """Try to lookup and read a non-existent key and validate fields of results."""
    session = elliptics.newapi.Session(simple_node)
    session.trace_id = make_trace_id('test_lookup_read_nonexistent_key')
    session.exceptions_policy = elliptics.exceptions_policy.no_exceptions
    session.groups = session.routes.groups()

    key = 'test_lookup_read_nonexistent_key'
    for result in session.lookup(key):
        assert result.status == -errno.ENOENT
        assert result.record_info is None
        assert result.path is None

    for result in session.read(key):
        assert result.status == -errno.ENOENT
        assert result.record_info is None
        assert result.io_info is None
        assert result.json is None
        assert result.data is None


@pytest.mark.usefixtures('servers')
def test_lookup_read_existent_key(simple_node):
    """Write a key, lookup and read it and validate fields of results."""
    session = elliptics.newapi.Session(simple_node)
    session.trace_id = make_trace_id('test_lookup_read_existent_key')
    session.groups = session.routes.groups()

    key = 'test_lookup_read_existent_key'
    json_string = json.dumps({'some': 'field'})
    data = 'some data'

    i = 0
    for i, result in enumerate(session.write(key, json_string, len(json_string), data, len(data)),
                               start=1):
        assert result.status == 0
        assert result.record_info.json_size == len(json_string)
        assert result.record_info.json_capacity == len(json_string)
        assert result.record_info.data_size == len(data)
    assert i == len(session.groups)

    i = 0
    for i, result in enumerate(session.lookup(key), start=1):
        assert result.status == 0
        assert result.record_info.json_size == len(json_string)
        assert result.record_info.json_capacity == len(json_string)
        assert result.record_info.data_size == len(data)
    assert i == 1

    i = 0
    for i, result in enumerate(session.read(key, 0, 0), start=1):
        assert result.status == 0
        assert result.record_info.json_size == len(json_string)
        assert result.record_info.json_capacity == len(json_string)
        assert result.record_info.data_size == len(data)
        assert result.json == json_string
        assert result.data == data
    assert i == 1


@pytest.mark.usefixtures('servers')
def test_use_session_clone(simple_node):
    """Create session, clone and write a key by clone."""
    session = elliptics.newapi.Session(simple_node)
    session.trace_id = make_trace_id('test_use_session_after_clone')
    session.groups = session.routes.groups()

    key = 'test_use_session_after_clone\'s key'

    clone = session.clone()
    clone.write(key, '{"no": "matter"}', 0, 'no matter', 0).wait()
    clone.lookup(key).wait()
    clone.read(key).wait()
    clone.read_json(key).wait()
    clone.read_data(key).wait()
    clone.remove(key)


@pytest.mark.usefixtures('servers')
def test_session_timestamps(simple_node):
    """Test session.timestamp and session.json_timestamp."""
    session = elliptics.newapi.Session(simple_node)
    session.trace_id = make_trace_id('test_lookup_read_existent_key')
    session.groups = session.routes.groups()

    key = 'test_lookup_read_existent_key'
    json_string = json.dumps({'some': 'field'})
    data = 'some data'

    data_ts = elliptics.Time.now()
    json_ts = elliptics.Time(data_ts.tsec, data_ts.tnsec + 1)
    assert json_ts > data_ts

    assert session.timestamp is None
    assert session.json_timestamp is None
    # write and check timestamps from result
    result = session.write(key, json_string, len(json_string), data, len(data)).get()[0]
    assert elliptics.Time.now() > result.record_info.data_timestamp > data_ts
    assert elliptics.Time.now() > result.record_info.json_timestamp > data_ts

    session.timestamp = data_ts
    assert session.timestamp == data_ts
    assert session.json_timestamp is None
    # write and check timestamps from result
    result = session.write(key, json_string, len(json_string), data, len(data)).get()[0]
    assert result.record_info.data_timestamp == data_ts
    assert result.record_info.json_timestamp == data_ts

    session.json_timestamp = json_ts
    assert session.timestamp == data_ts
    assert session.json_timestamp == json_ts
    # write and check timestamps from result
    result = session.write(key, json_string, len(json_string), data, len(data)).get()[0]
    assert result.record_info.data_timestamp == data_ts
    assert result.record_info.json_timestamp == json_ts

    session.timestamp = None
    assert session.timestamp is None
    assert session.json_timestamp == json_ts
    # write and check timestamps from result
    result = session.write(key, json_string, len(json_string), data, len(data)).get()[0]
    assert elliptics.Time.now() > result.record_info.data_timestamp > json_ts
    assert result.record_info.json_timestamp == json_ts

@pytest.mark.usefixtures('servers')
def test_session_bulk_read(simple_node):
    """Test bulk_read_json, bulk_read_data, bulk_read."""
    session = elliptics.newapi.Session(simple_node)
    session.trace_id = make_trace_id('test_session_bulk_read')
    session.groups = session.routes.groups()

    # prepare test data
    keys = []
    datas = {}
    def make_item(data, json):
        return {"data": data, "json": json}

    write_results = []
    for group_id in session.groups:
        session.groups = [group_id]
        for i in range(10):
            eid = session.transform('k{}'.format(i))
            eid.group_id = group_id
            keys.append(eid)
            data = "data{}_{}".format(group_id, i)
            json_string = json.dumps({'some': "json{}_{}".format(group_id, i)})
            datas[repr(eid)] = make_item(data, json_string)
            result = session.write(eid, json_string, len(json_string), data, len(data))
            write_results.append(result)

    for r in write_results:
        assert r.get()[0].status == 0

    assert len(keys) == len(datas)

    # check bulk_read_json, bulk_read_data, bulk_read
    def check_result(method, check_json, check_data):
        result = method(keys)
        counter = 0
        for r in result:
            counter += 1
            assert repr(r.id) in datas
            ref = datas[repr(r.id)]

            if check_json:
                assert ref["json"] == r.json
            else:
                assert not r.json

            if check_data:
                assert ref["data"] == r.data
            else:
                assert not r.data
        assert counter == len(keys)

    check_result(session.bulk_read_json, True, False)
    check_result(session.bulk_read_data, False, True)
    check_result(session.bulk_read, True, True)
