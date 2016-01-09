'''Structured data feature tests.

This module contains tests that demonstrates and checks structured data API.
'''

import pytest
from conftest import make_session
import errno
import elliptics
from collections import namedtuple, OrderedDict

Field = namedtuple('Field', ['name', 'data'])


class TestBase(object):
    '''Base class for all test. It defines common methods for session initialization'''
    def get_test_name(self):
        '''Returns test name made via concatenating test class and test method'''
        import inspect
        return '%s.%s' % (type(self).__name__, inspect.stack()[2][3])

    def get_session(self, node):
        '''Creates session with test-specific namespace and all groups'''
        session = make_session(node=node, test_name=self.get_test_name())
        session.groups = [session.routes.groups()[0]]
        return session


@pytest.mark.incremental
@pytest.mark.structured_data
class TestOneField(TestBase):
    ''' '''
    key = 'document'
    field = 'content'
    content = 'The content of the document'

    def test_write(self, server, simple_node):
        '''Writes the structured record and verifies results (index, address, status and error)'''

        session = self.get_session(node=simple_node)

        index = {
            self.field: self.content,
        }

        async = session.write_struct(self.key, index)

        results = async.get()
        assert len(results) == len(session.groups)

        for result in results:
            attributes = result.index[self.field]['__attributes__']
            assert attributes['capacity'] == attributes['size'] == len(self.content)
            assert attributes['offset'] == 0

            # checks that result was sent by correct node
            assert result.address == session.lookup_address(self.key, result.group_id)
            assert result.status == 0  # checks that there was no error
            # extra check that error wasn't filled because there was no error
            assert result.error.code == 0
            assert result.error.message == ''

    def test_lookup(self, server, simple_node):
        '''Lookups the structured record and verifies results (index, address, status and error)'''
        session = self.get_session(node=simple_node)

        groups = session.groups
        for g in groups:
            session.groups = [g]
            async = session.lookup_struct(self.key)

            results = async.get()
            assert len(results) == 1

            result = results[0]

            attributes = result.index[self.field]['__attributes__']
            assert attributes['capacity'] == attributes['size'] == len(self.content)
            assert attributes['offset'] == 0

            # checks that result was sent by correct node
            assert result.address == session.lookup_address(self.key, result.group_id)
            assert result.status == 0  # checks that there was no error
            # extra check that error wasn't filled because there was no error
            assert result.error.code == 0
            assert result.error.message == ''

    def test_read_whole(self, server, simple_node):
        '''Reads whole the structured record without specifying index from each group and
        verifies result (index, datas)'''  # address, status and error)'''
        session = self.get_session(simple_node)

        groups = session.groups
        for g in groups:
            session.groups = [g]
            async = session.read_struct(self.key)

            results = async.get()
            assert len(results) == 1

            result = results[0]
            attributes = result.index[self.field]['__attributes__']
            assert attributes['capacity'] == attributes['size'] == len(self.content)
            assert attributes['offset'] == 0
            assert attributes['data'] == 0

            assert len(result.datas) == 1
            assert result.datas[0] == self.content
            # assert result.address == session.lookup_address(self.key, result.group_id)
            # assert result.status == 0
            # assert result.error.code == 0
            # assert result.error.message == ''

    def test_read_field(self, server, simple_node):
        '''Reads only one field from the structured record from each group and
        verifies result (index, datas)'''  # address, status and error)'''
        session = self.get_session(simple_node)

        index = {
            self.field: {},
        }

        groups = session.groups
        for g in groups:
            session.groups = [g]
            async = session.read_struct(self.key, index)

            results = async.get()
            assert len(results) == 1

            result = results[0]
            attributes = result.index[self.field]['__attributes__']
            assert attributes['capacity'] == attributes['size'] == len(self.content)
            assert attributes['offset'] == 0
            assert attributes['data'] == 0

            assert len(result.datas) == 1
            assert result.datas[0] == self.content
            # assert result.address == session.lookup_address(self.key, result.group_id)
            # assert result.status == 0
            # assert result.error.code == 0
            # assert result.error.message == ''

    @pytest.mark.parametrize('size', (None,
                                      0,
                                      1,
                                      len(content) / 2,
                                      len(content) - 1,
                                      len(content),
                                      len(content) * 1024,
                                      ))
    @pytest.mark.parametrize('offset', (None,
                                        0,
                                        1,
                                        len(content) / 2,
                                        len(content) - 1
                                        ))
    def test_read_field_with_size_offset(self, server, simple_node, size, offset):
        '''Reads one field with offset from the structured record from each group and
        verifies result (index, datas)'''  # address, status and error)'''
        session = self.get_session(simple_node)

        index = {
            self.field: {
                '__attributes__': {},
            },
        }

        if size is not None:
            index[self.field]['__attributes__']['size'] = size

        if offset is not None:
            index[self.field]['__attributes__']['offset'] = offset

        offset = 0 if offset is None else offset
        size = len(self.content) - offset if not size else size

        groups = session.groups
        for g in groups:
            session.groups = [g]
            async = session.read_struct(self.key, index)

            results = async.get()
            assert len(results) == 1

            result = results[0]
            attributes = result.index[self.field]['__attributes__']
            assert attributes['capacity'] == attributes['size'] == len(self.content)
            assert attributes['offset'] == 0
            assert attributes['data'] == 0

            assert len(result.datas) == 1
            assert result.datas[0] == self.content[offset:][:size]
            # assert result.address == session.lookup_address(self.key, result.group_id)
            # assert result.status == 0
            # assert result.error.code == 0
            # assert result.error.message == ''

    @pytest.mark.parametrize('offset', (len(content) * 1024, ))
    def test_read_field_with_too_big_offset(self, server, simple_node, offset):
        '''Reads one field with too big offset from the structured record from each group and
        verifies result (index, datas and error)'''  # address, status
        session = self.get_session(simple_node)

        index = {
            self.field: {
                '__attributes__': {
                    'offset': offset,
                },
            },
        }

        groups = session.groups
        for g in groups:
            session.groups = [g]
            async = session.read_struct(self.key, index)

            results = async.get()
            assert len(results) == 1

            result = results[0]
            attributes = result.index[self.field]['__attributes__']
            assert attributes['capacity'] == attributes['size'] == len(self.content)
            assert attributes['offset'] == 0
            assert attributes['data'] == -errno.E2BIG

            assert len(result.datas) == 0
            # assert result.address == session.lookup_address(self.key, result.group_id)
            # assert result.status == 0
            # assert result.error.code == 0
            # assert result.error.message == ''

    def test_read_nonexistent_field(self, server, simple_node):
        '''Reads one field which is not presented at the structured record for each group and
        verifies result (index, datas and error)'''
        session = self.get_session(simple_node)

        nonexistent_field = 'nonexistent_field'

        index = {
            nonexistent_field: {},
        }

        groups = session.groups
        for g in groups:
            session.groups = [g]
            async = session.read_struct(self.key, index)

            results = async.get()
            assert len(results) == 1

            result = results[0]
            attributes = result.index[nonexistent_field]['__attributes__']
            assert attributes['data'] == -errno.ENOENT
            assert 'capacity' not in attributes
            assert 'size' not in attributes
            assert 'offset' not in attributes

            assert len(result.datas) == 0
            # assert result.address == session.lookup_address(self.key, result.group_id)
            # assert result.status == 0
            # assert result.error.code == 0
            # assert result.error.message == ''


@pytest.mark.incremental
@pytest.mark.structured_data
class TestMultiFields(TestBase):
    ''' '''
    key = 'document'
    document = {
        'Header': 'The header of the document',
        'Chapter #1': 'Content of the chapter #1',
        'Chapter #2': 'Content of the chapter #2',
        'Chapter #3': 'Content of the chapter #3',
        'Footer': 'The footer of the document',
    }

    def test_write(self, server, simple_node):
        session = self.get_session(node=simple_node)

        async = session.write_struct(self.key, self.document)

        results = async.get()
        assert len(results) == len(session.groups)

        for result in results:
            for field in self.document:
                attributes = result.index[field]['__attributes__']
                assert attributes['capacity'] == attributes['size'] == len(self.document[field])
                assert attributes['offset'] >= 0

            # checks that result was sent by correct node
            assert result.address == session.lookup_address(self.key, result.group_id)
            assert result.status == 0  # checks that there was no error
            # extra check that error wasn't filled because there was no error
            assert result.error.code == 0
            assert result.error.message == ''

    def test_read_whole_record(self, server, simple_node):
        session = self.get_session(node=simple_node)

        groups = session.groups
        for group in groups:
            session.groups = [group]
            async = session.read_struct(self.key)

            results = async.get()
            assert len(results) == 1

            for result in results:
                assert len(result.datas) == len(self.document)
                for field in self.document:
                    attributes = result.index[field]['__attributes__']
                    assert attributes['capacity'] == attributes['size'] == len(self.document[field])
                    assert attributes['offset'] >= 0
                    assert 0 <= attributes['data'] <= len(self.document)
                    assert result.datas[attributes['data']] == self.document[field]

    @pytest.mark.parametrize('field', document)
    def test_read_one_field(self, server, simple_node, field):
        session = self.get_session(node=simple_node)

        index = {
            field: {}
        }

        groups = session.groups
        for group in groups:
            session.groups = [group]
            async = session.read_struct(self.key, index)

            results = async.get()
            assert len(results) == 1

            result = results[0]
            attributes = result.index[field]['__attributes__']
            assert attributes['capacity'] == attributes['size'] == len(self.document[field])
            assert attributes['offset'] >= 0
            assert attributes['data'] == 0
            assert len(result.datas) == 1
            assert result.datas[0] == self.document[field]

    def test_read_all_fields(self, server, simple_node):
        session = self.get_session(node=simple_node)

        index = {
            field: {} for field in self.document
        }

        groups = session.groups
        for group in groups:
            session.groups = [group]
            async = session.read_struct(self.key, index)

            results = async.get()
            assert len(results) == 1

            result = results[0]

            for result in results:
                assert len(result.datas) == len(self.document)
                for field in self.document:
                    attributes = result.index[field]['__attributes__']
                    assert attributes['capacity'] == attributes['size'] == len(self.document[field])
                    assert attributes['offset'] >= 0
                    assert 0 <= attributes['data'] <= len(self.document)
                    assert result.datas[attributes['data']] == self.document[field]


@pytest.mark.incremental
@pytest.mark.structured_data
class TestWriteOneSimpleField(TestBase):
    '''Class of tests that checks writing structured keys with only one simple field'''

    key = 'key'  # the key of the structured record
    field = Field(name='some stored info',
                  data='very useful info that should be stored',
                  )

    scenarios = [
        # Scenario #1: index contains in-place field's data, data_list is None (empty)
        (field.data, None),
        # Scenario #2: index contains `0` (link to the first element of data_list),
        #   data_list contains field's data
        (0, [field.data])
    ]

    scenarios_ids = [
        'in-index field\'s data',
        'out-of-index field\'s data',
    ]

    def check_results(self, async, session, size=None, capacity=None):
        '''Checks that it received correct results from all nodes

        Args:
            async: An async_result returned from elliptics.Session.write_struct
            session: A elliptics.Session that was used for writing
            size: An optional argument, that should be equal to final size of the field's data
            capacity: An optional argument, that should be equal to size of the space
                that should be reserved for the record

        Returns:
            It returns nothing, but it will throw an exception if something goes wrong.
        '''

        # if size isn't specified it should be equal to size of the field's data
        if size is None:
            size = len(self.field.data)

        # if capacity isn't specified it should be equal to size of the field's data
        if capacity is None:
            capacity = len(self.field.data)

        results = async.get()  # waits and gets all results of the write_struct operation
        assert len(results) == len(session.groups)  # checks number of responses

        # Test index which should be returned with all results.
        # It contains only one field `field.name` with:
        #   `offset` where field's data is placed, for all tests of this class it should always be 0,
        #       because they write records with only one field
        #   `size` is size of the field's data
        #   `capacity` is the space that was reserved for the field's data

        # check each received response
        for result in results:
            # checks that response index contains valid written field
            # it does not check offset because it is not guarantee what offset will it have
            attributes = result.index[self.field.name]['__attributes__']
            assert attributes['size'] == size
            assert attributes['capacity'] == capacity

            # checks that result was sent by correct node
            assert result.address == session.lookup_address(self.key, result.group_id)
            assert result.status == 0  # checks that there was no error
            # extra check that error wasn't filled because there was no error
            assert result.error.code == 0
            assert result.error.message == ''

    def test_string_index(self, server, simple_node):
        '''Writes structured record with using json index with in-place field's data definition and checks results
        This test is just example that index can be a json string or dict object
        '''
        from json import dumps

        # creates session that will be used for writing structured record
        session = self.get_session(node=simple_node)

        # json index of the structured record:
        # it has only one field with name `field.name` and in-place field's data definition `field.data`
        index = dumps({
            self.field.name: self.field.data
        })

        async = session.write_struct(self.key, index)  # async structured record writing
        self.check_results(async, session)

    @pytest.mark.parametrize('index_data, data_list', scenarios, ids=scenarios_ids)
    def test_dict_index(self, server, simple_node, index_data, data_list):
        '''Writes structured record with using dict index with in-place field's data definition and checks results'''

        # creates session that will be used for writing structured record
        session = self.get_session(node=simple_node)

        # Dictionary index of the structured record:
        # it has only one field with name `field.name` and in-place field's data definition `field.data`
        index = {
            self.field.name: index_data
        }

        async = session.write_struct(self.key, index, data=data_list)  # async structured record writing
        self.check_results(async, session)

    @pytest.mark.parametrize('index_data, data_list', scenarios, ids=scenarios_ids)
    def test_extended_index(self, server, simple_node, index_data, data_list):
        '''Writes structured record with on field with out-of-index field's data with default extra info'''

        # creates session that will be used for writing structured record
        session = self.get_session(node=simple_node)

        # Dictionary index of the structured record:
        # it has only one field with name `field.name` and out-place field's data definition:
        # `'data': 0` means that field's data is passed as first element of the data list
        index = {
            self.field.name: {
                '__attributes__': {
                    'data': index_data
                }
            }
        }

        async = session.write_struct(self.key, index, data=data_list)  # async structured record writing
        self.check_results(async, session)

    @pytest.mark.parametrize('index_data, data_list', scenarios, ids=scenarios_ids)
    def test_extended_index_with_empty_capacity(self, server, simple_node, index_data, data_list):
        '''Writes structured record with on field with out-of-index field's data with default extra info'''

        # creates session that will be used for writing structured record
        session = self.get_session(node=simple_node)

        # Dictionary index of the structured record:
        # it has only one field with name `field.name` and out-place field's data definition:
        # `'data': 0` means that field's data is passed as first element of the data list
        index = {
            self.field.name: {
                '__attributes__': {
                    'capacity': 0,
                    'data': index_data,
                },
            }
        }

        async = session.write_struct(self.key, index, data=data_list)  # async structured record writing
        self.check_results(async, session)

    @pytest.mark.parametrize('index_data, data_list', scenarios, ids=scenarios_ids)
    def test_extended_index_with_nonempty_capacity(self, server, simple_node, index_data, data_list):
        '''Writes structured record with on field with out-of-index field's data with default extra info'''

        # creates session that will be used for writing structured record
        session = self.get_session(node=simple_node)

        capacity = 1024

        # Dictionary index of the structured record:
        # it has only one field with name `field.name` and out-place field's data definition:
        # `'data': 0` means that field's data is passed as first element of the data list
        index = {
            self.field.name: {
                '__attributes__': {
                    'capacity': capacity,
                    'data': index_data,
                },
            }
        }

        async = session.write_struct(self.key, index, data=data_list)  # async structured record writing
        self.check_results(async, session, capacity=capacity)

    @pytest.mark.parametrize('index_data, data_list', scenarios, ids=scenarios_ids)
    def test_extended_index_with_empty_offset(self, server, simple_node, index_data, data_list):
        '''Writes structured record with on field with out-of-index field's data with default extra info'''

        # creates session that will be used for writing structured record
        session = self.get_session(node=simple_node)

        # Dictionary index of the structured record:
        # it has only one field with name `field.name` and out-place field's data definition:
        # `'offset': 0` means that node should write field's data without offset
        # `'data': 0` means that field's data is passed as first element of the data list
        index = {
            self.field.name: {
                '__attributes__': {
                    'offset': 0,
                    'data': index_data,
                },
            }
        }

        async = session.write_struct(self.key, index, data_list)  # async structured record writing
        self.check_results(async, session)

    @pytest.mark.parametrize('index_data, data_list', scenarios, ids=scenarios_ids)
    def test_extended_index_with_nonempty_offset(self, server, simple_node, index_data, data_list):
        '''Writes structured record with on field with out-of-index field's data with default extra info'''

        # creates session that will be used for writing structured record
        session = self.get_session(node=simple_node)

        offset = 1024

        # Dictionary index of the structured record:
        # it has only one field with name `field.name` and out-place field's data definition:
        # `'offset': 1024` means that node should write field's data with 1024 bytes offset
        # `'data': 0` means that field's data is passed as first element of the data list
        index = {
            self.field.name: {
                '__attributes__': {
                    'offset': offset,
                    'data': index_data,
                },
            }
        }

        async = session.write_struct(self.key, index, data_list)  # async structured record writing
        # it wrote field with offset `offset`,
        # so final size of the field should be: offset + size of field's data
        test_size = len(self.field.data) + offset
        self.check_results(async, session, size=test_size, capacity=test_size)

    @pytest.mark.parametrize('index_data, data_list', scenarios, ids=scenarios_ids)
    def test_extended_index_with_offset_and_capacity(self, server, simple_node, index_data, data_list):
        '''Writes structured record with one field with out-of-index field's data with nonempty offset and capacity'''

        # creates session that will be used for writing structured record
        session = self.get_session(node=simple_node)

        offset = 1024
        capacity = 1024 * 2

        # Dictionary index of the structured record:
        # it has only one field with name `field.name` and out-place field's data definition:
        # `'offset': 1024` means that node should write field's data with 1024 bytes offset
        # `'data': 0` means that field's data is passed as first element of the data list
        index = {
            self.field.name: {
                '__attributes__': {
                    'capacity': capacity,
                    'offset': offset,
                    'data': index_data,
                },
            }
        }

        async = session.write_struct(self.key, index, data_list)  # async structured record writing
        # it wrote field with offset `offset`,
        # so final size of the field should be: offset + size of field's data
        test_size = len(self.field.data) + offset
        self.check_results(async, session, size=test_size, capacity=capacity)


@pytest.mark.incremental
@pytest.mark.structured_data
class TestReadOneSimpleField(TestBase):
    '''Class of tests that checks reading structured keys with only one simple field'''

    key = 'key'  # the key of the structured record
    field = Field(name='some stored info',
                  data='very useful info that should be stored',
                  )

    scenarios = [
        # Scenario #1: read whole field
        (0, 0),
        # Scenario #1: read whole field with size
        (0, len(field.data)),
        # Scenario #2: read with offset
        (10, 0),
        # Scenario #3: read with offset and size
        (10, 10),
        # Scenario #4: read with too big size
        (0, len(field.data) + 10),
        # Scenario #5: read with too big size and correct offset
        (10, len(field.data) + 10),
        # Scenario #6: read with out of bound offset
        (len(field.data) + 1, 0),
        # Scenario #7: read with out of bound offset and some size
        (len(field.data) + 1, 10),
    ]

    scenarios_ids = [
        'whole field: offset={},size={}'.format(0, 0),
        'whole field: offset={},size={}'.format(0, len(field.data)),
        'part of field: offset={},size={}'.format(10, 0),
        'part of field: offset={},size={}'.format(10, 10),
        'too big size: offset={},size={}'.format(0, len(field.data) + 10),
        'too big size and some correct offset: offset={},size={}'.format(10, len(field.data) + 10),
        'out of bound offset: offset={},size={}'.format(len(field.data) + 1, 0),
        'out of bound offset and some size: offset={},size={}'.format(len(field.data) + 1, 10),
    ]

    def get_test_name(self):
        return type(self).__name__

    def test_write_record(self, server, simple_node):
        '''Writes structured record with only one field

        Args:
            session: Elliptics.Session that should be used for writing

        Returns:
            It returns nothing, but it will throw exception if something goes wrong.
        '''

        session = self.get_session(simple_node)

        # Dictionary index of the structured record:
        # it has only one field with name `field.name` and in-place field's data definition `field.data`
        index = {
            self.field.name: self.field.data
        }

        session.write_struct(self.key, index).get()  # async structured record writing

    def test_lookup_index(self, server, simple_node):
        '''Lookups index of the record and checks it'''

        session = self.get_session(simple_node)

        groups = session.groups
        for g in groups:
            session.groups = [g]
            async = session.lookup_struct(self.key)

            results = async.get()
            assert len(results) == 1

            result = results[0]

            attributes = result.index[self.field.name]['__attributes__']
            assert attributes['size'] == len(self.field.data)
            assert attributes['capacity'] == len(self.field.data)

            # checks that result was sent by correct node
            assert result.address == session.lookup_address(self.key, result.group_id)
            assert result.status == 0  # checks that there was no error
            # extra check that error wasn't filled because there was no error
            assert result.error.code == 0
            assert result.error.message == ''

    def test_read_whole_record(self, server, simple_node):
        '''Reads whole record with index and check it'''

        session = self.get_session(simple_node)

        groups = session.groups
        for g in groups:
            session.groups = [g]
            async = session.read_struct(self.key)

            results = async.get()
            assert len(results) == 1

            result = results[0]
            attributes = result.index[self.field.name]['__attributes__']
            assert attributes['capacity'] == attributes['size'] == len(self.field.data)
            assert attributes['offset'] == 0
            assert attributes['data'] == 0

            assert len(result.datas) == 1
            assert result.datas[0] == self.field.data
            # assert result.address == session.lookup_address(self.key, result.group_id)
            # assert result.status == 0
            # assert result.error.code == 0
            # assert result.error.message == ''

    def test_read_one_field(self, server, simple_node):
        '''Reads only one field from the record and check it'''

        session = self.get_session(simple_node)

        read_index = {
            self.field.name: {}
        }

        groups = session.groups
        for g in groups:
            session.groups = [g]
            async = session.read_struct(self.key, read_index)

            results = async.get()
            assert len(results) == 1

            result = results[0]
            attributes = result.index[self.field.name]['__attributes__']

            assert attributes['capacity'] == attributes['size'] == len(self.field.data)
            assert attributes['offset'] == 0
            assert attributes['data'] == 0

            assert len(result.datas) == 1
            assert result.datas[0] == self.field.data

    @pytest.mark.parametrize('offset, size', scenarios, ids=scenarios_ids)
    def test_read_one_field_partly(self, server, simple_node, offset, size):
        '''Partly reads only one field from the record and check it'''

        session = self.get_session(simple_node)

        read_index = {
            self.field.name: {
                '__attributes__': {
                    'offset': offset,
                    'size': size,
                },
            },
        }

        groups = session.groups
        for g in groups:
            session.groups = [g]
            async = session.read_struct(self.key, read_index)

            results = async.get()
            assert len(results) == 1

            result = results[0]
            attributes = result.index[self.field.name]['__attributes__']
            if offset < len(self.field.data):
                assert attributes['capacity'] == attributes['size'] == len(self.field.data)
                assert attributes['offset'] == 0
                assert attributes['data'] == 0
            else:
                assert attributes['data'] == -errno.E2BIG

            if offset < len(self.field.data):
                assert len(result.datas) == 1
                if size == 0:
                    assert result.datas[0] == self.field.data[offset:]
                else:
                    assert result.datas[0] == self.field.data[offset:offset + size]
            else:
                assert len(result.datas) == 0

    def test_read_nonexistent_field(self, server, simple_node):
        '''Tries to read nonexistent field of existent record and check that it correctly fails'''

        session = self.get_session(simple_node)

        field_name = 'some nonexistent field'

        read_index = {
            field_name: {}
        }

        groups = session.groups
        for g in groups:
            session.groups = [g]
            async = session.read_struct(self.key, read_index)

            results = async.get()
            assert len(results) == 1

            result = results[0]
            attributes = result.index[field_name]['__attributes__']
            assert attributes['data'] == -errno.ENOENT
            assert len(result.datas) == 0

    def test_read_nonexistent_record(self, server, simple_node):
        '''Tries to read some field of nonexistent record and check that it correctly fails'''

        session = self.get_session(simple_node)

        key = 'some nonexistent record'

        read_index = {
            'some nonexistent field': {}
        }

        groups = session.groups
        for g in groups:
            session.groups = [g]
            async = session.read_struct(key, read_index)

            with pytest.raises(elliptics.NotFoundError):
                async.wait()


@pytest.mark.incremental
@pytest.mark.structured_data
class TestOneLevelFieldsStructure(TestBase):
    '''This test class verifies API against records with one level fields structure:
    All records have multiple fields which don't have nested subfields.
    '''

    key = 'key'
    fields = [Field(name='1st field with some useful info',
                    data='1st field\'s useful data',
                    ),
              Field(name='2nd field with some useful info',
                    data='2nd field\'s useful data',
                    ),
              Field(name='3rd field with some useful info',
                    data='3rd field\'s useful data',
                    ),
              ]
    key_with_default = 'key with default'
    default_field = Field(name='default',
                          data='default field\'s data',
                          )

    def get_test_name(self):
        return type(self).__name__

    def check_write_results(self, key, async, session, index):
        '''Checks write results'''

        results = async.get()
        assert len(results) == len(session.groups)

        for result in results:
            for name in index:
                attributes = result.index[name]['__attributes__']
                assert attributes['offset'] >= 0
                assert attributes['capacity'] == attributes['size'] == len(index[name])

            assert result.address == session.lookup_address(key, result.group_id)
            assert result.status == 0
            assert result.error.code == 0
            assert result.error.message == ''

    def test_write_record_without_default_field(self, server, simple_node):
        '''Writes key with multiple fields at first level without default field and checks results'''
        session = self.get_session(node=simple_node)

        index = OrderedDict()
        for field in self.fields:
            index[field.name] = field.data

        async = session.write_struct(self.key, index)

        self.check_write_results(self.key, async, session, index)

    def test_write_record_with_default_field(self, server, simple_node):
        '''Writes key with multiple fields at first level with default field and checks results'''
        session = self.get_session(node=simple_node)

        fields = self.fields[:] + [self.default_field]

        index = OrderedDict()
        for field in fields:
            index[field.name] = field.data

        async = session.write_struct(self.key_with_default, index)

        self.check_write_results(self.key_with_default, async, session, index)

    def check_lookup_results(self, key, async, session):
        '''Checks lookup results'''

        fields = self.fields[:]
        if key == self.key_with_default:
            fields.append(self.default_field)

        results = async.get()
        assert len(results) == 1

        result = results[0]

        for field in fields:
            attributes = result.index[field.name]['__attributes__']
            assert attributes['offset'] >= 0
            assert attributes['capacity'] == attributes['size'] == len(field.data)

        assert result.address == session.lookup_address(key, result.group_id)
        assert result.status == 0
        assert result.error.code == 0
        assert result.error.message == ''

    def test_lookup_index(self, server, simple_node):
        '''Lookups both keys and checks results'''

        session = self.get_session(simple_node)

        groups = session.groups
        for g in groups:
            session.groups = [g]
            async = session.lookup_struct(self.key)
            self.check_lookup_results(self.key, async, session)

            async = session.lookup_struct(self.key_with_default)
            self.check_lookup_results(self.key_with_default, async, session)

    def check_read_whole_record_results(self, key, async, session):
        '''Checks results of reads'''

        fields = self.fields[:]
        if key == self.key_with_default:
            fields.append(self.default_field)

        results = async.get()
        assert len(results) == 1

        result = results[0]
        indexes = set()
        for field in fields:
            attributes = result.index[field.name]['__attributes__']
            assert attributes['offset'] >= 0
            assert attributes['capacity'] == attributes['size'] == len(field.data)
            data_index = attributes['data']
            assert data_index < len(result.datas)
            assert data_index not in indexes
            indexes.add(data_index)
            assert result.datas[data_index] == field.data

        assert indexes == set(range(len(result.datas))) == set(range(len(fields)))

    def test_read_whole_record(self, server, simple_node):
        '''Reads whole record for both key and checks results'''

        session = self.get_session(simple_node)

        groups = session.groups
        for g in groups:
            session.groups = [g]
            async = session.read_struct(self.key)
            self.check_read_whole_record_results(self.key, async, session)

            async = session.read_struct(self.key_with_default)
            self.check_read_whole_record_results(self.key_with_default, async, session)

    @pytest.mark.parametrize("field", fields)
    def test_read_one_field(self, server, simple_node, field):
        '''Reads one field from both keys and checks it'''

        session = self.get_session(simple_node)

        groups = session.groups
        for g in groups:
            session.groups = [g]

    def test_read_default_field(self, server, simple_node):
        '''Reads default field and checks it'''
        pass


@pytest.mark.incremental
@pytest.mark.structured_data
class TestMultilevelFields(TestBase):
    '''
    Class of tests that checks writing/reading structured keys with only one composite field
    that has subfields some of which can have their subfields etc.
    '''

    key = 'document'
    document = {
        'Content': {
            'Header': 'The header of the document',
            'Chapter #1': 'Content of the chapter #1',
            'Chapter #2': 'Content of the chapter #2',
            'Chapter #3': 'Content of the chapter #3',
            'Footer': 'The footer of the document',
        },
        'Meta': {
            'HTTP': {
                'Content-Type': 'text/plain',
            },
            'Version': '0.0.0.1',
        },
        'Signature': {
            'Author': 'Shaitan',
            'License': 'LGPLv3',
        },
    }

    @staticmethod
    def sizeof(field):
        if isinstance(field, dict):
            return sum(TestMultilevelFields.sizeof(value) for value in field.values())
        else:
            return len(field)

    def verify_lookup_results(self, session, async):
        results = async.get()
        assert len(results) == len(session.groups)

        for result in results:
            # verify `Content`
            content = result.index['Content']
            attributes = content['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Content'])
            assert attributes['offset'] >= 0
            content_offset = attributes['offset']

            # verify `Content->Header`
            attributes = content['Header']['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Content']['Header'])
            assert attributes['offset'] >= content_offset

            # verify `Content->Chapter #1`
            attributes = content['Chapter #1']['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Content']['Chapter #1'])
            assert attributes['offset'] >= content_offset

            # verify `Content->Chapter #2`
            attributes = content['Chapter #2']['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Content']['Chapter #2'])
            assert attributes['offset'] >= content_offset

            # verify `Content->Chapter #3`
            attributes = content['Chapter #3']['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Content']['Chapter #3'])
            assert attributes['offset'] >= content_offset

            # verify `Content->Footer`
            attributes = content['Footer']['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Content']['Footer'])
            assert attributes['offset'] >= content_offset

            # verify `Meta`
            meta = result.index['Meta']
            attributes = meta['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Meta'])
            assert attributes['offset'] >= 0
            meta_offset = attributes['offset']

            # verify `Meta->HTTP`
            http = meta['HTTP']
            attributes = http['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Meta']['HTTP'])
            assert attributes['offset'] >= meta_offset
            http_offset = attributes['offset']

            # verify `Meta->HTTP->Content-Type`
            attributes = http['Content-Type']['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Meta']['HTTP']['Content-Type'])
            assert attributes['offset'] >= http_offset

            # verify `Meta->Version`
            attributes = meta['Version']['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Meta']['Version'])
            assert attributes['offset'] >= meta_offset

            # verify `Signature`
            signature = result.index['Signature']
            attributes = signature['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Signature'])
            assert attributes['offset'] >= 0
            signature_offset = attributes['offset']

            # verify `Signature->Author`
            attributes = signature['Author']['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Signature']['Author'])
            assert attributes['offset'] >= signature_offset

            # verify `Signature->License`
            attributes = signature['License']['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Signature']['License'])
            assert attributes['offset'] >= signature_offset

    def test_write(self, server, simple_node):
        session = self.get_session(node=simple_node)

        async = session.write_struct(self.key, self.document)
        self.verify_lookup_results(session, async)

    def test_lookup(self, server, simple_node):
        session = self.get_session(node=simple_node)

        async = session.lookup_struct(self.key)
        self.verify_lookup_results(session, async)

    def test_read_whole_record(self, server, simple_node):
        session = self.get_session(node=simple_node)

        groups = session.groups
        for group in groups:
            session.groups = [group]
            async = session.read_struct(self.key)  # TODO: if this would be session.read_struct(self.key, self.document) it crashes
            results = async.get()
            assert len(results) == 1
            result = results[0]

            # verify `Content`
            content = result.index['Content']
            attributes = content['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Content'])
            assert 'data' not in attributes
            assert attributes['offset'] >= 0
            content_offset = attributes['offset']

            # verify `Content->Header`
            attributes = content['Header']['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Content']['Header'])
            assert attributes['offset'] >= content_offset
            assert 0 <= attributes['data'] <= len(result.datas)
            assert result.datas[attributes['data']] == self.document['Content']['Header']

            # verify `Content->Chapter #1`
            attributes = content['Chapter #1']['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Content']['Chapter #1'])
            assert attributes['offset'] >= content_offset
            assert 0 <= attributes['data'] <= len(result.datas)
            assert result.datas[attributes['data']] == self.document['Content']['Chapter #1']

            # verify `Content->Chapter #2`
            attributes = content['Chapter #2']['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Content']['Chapter #2'])
            assert attributes['offset'] >= content_offset
            assert 0 <= attributes['data'] <= len(result.datas)
            assert result.datas[attributes['data']] == self.document['Content']['Chapter #2']

            # verify `Content->Chapter #3`
            attributes = content['Chapter #3']['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Content']['Chapter #3'])
            assert attributes['offset'] >= content_offset
            assert 0 <= attributes['data'] <= len(result.datas)
            assert result.datas[attributes['data']] == self.document['Content']['Chapter #3']

            # verify `Content->Footer`
            attributes = content['Footer']['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Content']['Footer'])
            assert attributes['offset'] >= content_offset
            assert 0 <= attributes['data'] <= len(result.datas)
            assert result.datas[attributes['data']] == self.document['Content']['Footer']

            # verify `Meta`
            meta = result.index['Meta']
            attributes = meta['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Meta'])
            assert 'data' not in attributes
            assert attributes['offset'] >= 0
            meta_offset = attributes['offset']

            # verify `Meta->HTTP`
            http = meta['HTTP']
            attributes = http['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Meta']['HTTP'])
            assert 'data' not in attributes
            assert attributes['offset'] >= meta_offset
            http_offset = attributes['offset']

            # verify `Meta->HTTP->Content-Type`
            attributes = http['Content-Type']['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Meta']['HTTP']['Content-Type'])
            assert attributes['offset'] >= http_offset
            assert 0 <= attributes['data'] <= len(result.datas)
            assert result.datas[attributes['data']] == self.document['Meta']['HTTP']['Content-Type']

            # verify `Meta->Version`
            attributes = meta['Version']['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Meta']['Version'])
            assert attributes['offset'] >= meta_offset
            assert 0 <= attributes['data'] <= len(result.datas)
            assert result.datas[attributes['data']] == self.document['Meta']['Version']

            # verify `Signature`
            signature = result.index['Signature']
            attributes = signature['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Signature'])
            assert 'data' not in attributes
            assert attributes['offset'] >= 0
            signature_offset = attributes['offset']

            # verify `Signature->Author`
            attributes = signature['Author']['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Signature']['Author'])
            assert attributes['offset'] >= signature_offset
            assert 0 <= attributes['data'] <= len(result.datas)
            assert result.datas[attributes['data']] == self.document['Signature']['Author']

            # verify `Signature->License`
            attributes = signature['License']['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Signature']['License'])
            assert attributes['offset'] >= signature_offset
            assert 0 <= attributes['data'] <= len(result.datas)
            assert result.datas[attributes['data']] == self.document['Signature']['License']

    @pytest.mark.parametrize('field', ('Header',
                                       'Chapter #1',
                                       'Chapter #2',
                                       'Chapter #3',
                                       'Footer'))
    def test_read_content_field(self, server, simple_node, field):
        session = self.get_session(node=simple_node)

        index = {
            'Content': {
                field: {}
            },
        }

        groups = session.groups
        for group in groups:
            session.groups = [group]
            async = session.read_struct(self.key, index)
            results = async.get()
            assert len(results) == 1
            result = results[0]

            # index should contain only requested subset
            assert len(result.index) == 1
            assert len(result.datas) == 1

            # verify `Content`
            content = result.index['Content']
            # attributes = content['__attributes__']
            # assert attributes['capacity'] == attributes['size'] == \
            #     TestMultilevelFields.sizeof(self.document['Content'])
            # assert 'data' not in attributes
            # assert attributes['offset'] >= 0
            content_offset = 0  # attributes['offset']

            # `Content` should contain only requested subset
            assert len(content) == 1

            # verify `Content->@field`
            attributes = content[field]['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Content'][field])
            assert attributes['offset'] >= content_offset
            assert attributes['data'] == 0
            assert result.datas[attributes['data']] == self.document['Content'][field]

    def test_read_content_type(self, server, simple_node):
        session = self.get_session(node=simple_node)

        index = {
            'Meta': {
                'HTTP': {
                    'Content-Type': {}
                }
            }
        }

        groups = session.groups
        for group in groups:
            session.groups = [group]
            async = session.read_struct(self.key, index)
            results = async.get()
            assert len(results) == 1
            result = results[0]

            # index should contain only requested `Meta->HTTP->Content-Type`
            assert len(result.index) == 1
            assert len(result.datas) == 1

            # verify `Meta`
            meta = result.index['Meta']
            # attributes = meta['__attributes__']
            # assert attributes['capacity'] == attributes['size'] == \
            #     TestMultilevelFields.sizeof(self.document['Meta'])
            # assert 'data' not in attributes
            # assert attributes['offset'] >= 0
            meta_offset = 0  # attributes['offset']

            # `Meta` should contain only requested `HTTP->Content-Type`
            assert len(meta) == 1

            # verify `Meta->HTTP`
            http = meta['HTTP']
            # attributes = http['__attributes__']
            # assert attributes['capacity'] == attributes['size'] == \
            #     TestMultilevelFields.sizeof(self.document['Meta']['HTTP'])
            # assert 'data' not in attributes
            # assert attributes['offset'] >= meta_offset
            http_offset = 0  # attributes['offset']

            # `HTTP` should contain only requested `Content-Type`
            assert len(meta) == 1

            # verify `Meta->HTTP->Content-Type`
            attributes = http['Content-Type']['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Meta']['HTTP']['Content-Type'])
            assert attributes['offset'] >= http_offset
            assert 0 <= attributes['data'] <= len(result.datas)
            assert result.datas[attributes['data']] == self.document['Meta']['HTTP']['Content-Type']

    def test_read_content(self, server, simple_node):
        session = self.get_session(node=simple_node)

        index = {
            'Content': {}
        }

        groups = session.groups
        for group in groups:
            session.groups = [group]
            async = session.read_struct(self.key, index)
            results = async.get()
            assert len(results) == 1
            result = results[0]

            # index should contain only requested `Content`
            assert len(result.index) == 1
            # datas should contain data of only requested fields
            assert len(result.datas) == len(self.document['Content'])

            # verify `Content`
            content = result.index['Content']
            # attributes = content['__attributes__']
            # assert attributes['capacity'] == attributes['size'] == \
            #     TestMultilevelFields.sizeof(self.document['Content'])
            # assert 'data' not in attributes
            # assert attributes['offset'] >= 0
            content_offset = 0  # attributes['offset']

            # `Content` should contain only requested fields
            assert len(content) == len(self.document['Content'])

            # verify `Content->Header`
            attributes = content['Header']['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Content']['Header'])
            assert attributes['offset'] >= content_offset
            assert 0 <= attributes['data'] <= len(result.datas)
            assert result.datas[attributes['data']] == self.document['Content']['Header']

            # verify `Content->Chapter #1`
            attributes = content['Chapter #1']['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Content']['Chapter #1'])
            assert attributes['offset'] >= content_offset
            assert 0 <= attributes['data'] <= len(result.datas)
            assert result.datas[attributes['data']] == self.document['Content']['Chapter #1']

            # verify `Content->Chapter #2`
            attributes = content['Chapter #2']['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Content']['Chapter #2'])
            assert attributes['offset'] >= content_offset
            assert 0 <= attributes['data'] <= len(result.datas)
            assert result.datas[attributes['data']] == self.document['Content']['Chapter #2']

            # verify `Content->Chapter #3`
            attributes = content['Chapter #3']['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Content']['Chapter #3'])
            assert attributes['offset'] >= content_offset
            assert 0 <= attributes['data'] <= len(result.datas)
            assert result.datas[attributes['data']] == self.document['Content']['Chapter #3']

            # verify `Content->Footer`
            attributes = content['Footer']['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Content']['Footer'])
            assert attributes['offset'] >= content_offset
            assert 0 <= attributes['data'] <= len(result.datas)
            assert result.datas[attributes['data']] == self.document['Content']['Footer']

    @pytest.mark.parametrize('field', ('Header',
                                       'Chapter #1',
                                       'Chapter #2',
                                       'Chapter #3',
                                       'Footer'))
    def test_read_author_and_one_content_field(self, server, simple_node, field):
        session = self.get_session(node=simple_node)

        index = {
            'Content': {
                field: {}
            },
            'Signature': {
                'Author': {}
            }
        }

        groups = session.groups
        for group in groups:
            session.groups = [group]
            async = session.read_struct(self.key, index)
            results = async.get()
            assert len(results) == 1
            result = results[0]

            # index should contain only `Content` and `Signature`
            assert len(result.index) == 2
            assert len(result.datas) == 2

            # verify `Content`
            content = result.index['Content']
            # attributes = content['__attributes__']
            # assert attributes['capacity'] == attributes['size'] == \
            #     TestMultilevelFields.sizeof(self.document['Content'])
            # assert 'data' not in attributes
            # assert attributes['offset'] >= 0
            content_offset = 0  # attributes['offset']

            # `Content` should contain only requested @field
            assert len(content) == 1

            # verify `Content->@field`
            attributes = content[field]['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Content'][field])
            assert attributes['offset'] >= content_offset
            assert attributes['data'] == 0
            assert result.datas[attributes['data']] == self.document['Content'][field]

            # verify `Signature`
            signature = result.index['Signature']
            # attributes = signature['__attributes__']
            # assert attributes['capacity'] == attributes['size'] == \
            #     TestMultilevelFields.sizeof(self.document['Signature'])
            # assert attributes['offset'] >= 0
            signature_offset = 0  # attributes['offset']

            # `Signature` should contain only `Author`
            assert len(signature) == 1

            # verify `Signature->Author`
            attributes = signature['Author']['__attributes__']
            assert attributes['capacity'] == attributes['size'] == \
                TestMultilevelFields.sizeof(self.document['Signature']['Author'])
            assert attributes['offset'] >= signature_offset

    def test_old_read(self, server, simple_node):
        session = self.get_session(node=simple_node)

        groups = session.groups
        for group in groups:
            session.groups = [group]
            async = session.lookup_struct(self.key)  # lookup struct index
            results = async.get()
            assert len(results) == 1
            result = results[0]
            index = result.index

            async = session.lookup(self.key)
            results = async.get()
            assert len(results) == 1
            result = results[0]
            assert result.status == 0
            assert result.record_flags == elliptics.record_flags.exthdr | elliptics.record_flags.chunked_csum
            assert result.offset >= 0
            assert result.size == index['__attributes__']['size']

            async = session.read_data(self.key)
            results = async.get()
            assert len(results) == 1
            result = results[0]

            assert len(result.data) == index['__attributes__']['size']


@pytest.mark.incremental
@pytest.mark.structured_data
class TestDefaultField(TestBase):
    '''
    Class of tests that checks working old interface against records written via write_struct
    '''
    pass


@pytest.mark.incremental
@pytest.mark.structured_data
class TestMultipleFields(TestBase):
    '''
    Class of tests that checks writing/reading structured keys with multiple composite fields
    some of which can have their subfields etc.
    '''
    pass


@pytest.mark.incremental
@pytest.mark.structured_data
class TestPreStructuredData(TestBase):
    '''
    Class of tests that checks writing/reading keys with prestructured data and index
    '''
    pass
