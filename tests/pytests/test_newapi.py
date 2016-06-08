import elliptics

import json
import errno

from conftest import make_trace_id


def test_lookup_read_nonexistent_key(server, simple_node):
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

def test_lookup_read_existent_key(server, simple_node):
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


def test_use_session_clone(server, simple_node):
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
