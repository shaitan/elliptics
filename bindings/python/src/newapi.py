# =============================================================================
# 2016+ Copyright (c) Kirill Smorodinnikov <shaitkir@gmail.com>
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

from elliptics.log import logged_class
from elliptics.core import monitor_stat_categories
from elliptics.route import RouteList, Address
import elliptics.core


@logged_class
class Session(elliptics.core.newapi.Session):
    """New elliptics session interface."""
    __forward = elliptics.core.newapi.Session.forward

    def __init__(self, node):
        """
        Initialize session by the node.

        session = elliptics.Session(node)
        """
        super(Session, self).__init__(node)
        self._node = node

    def clone(self):
        """
        Create and return session which is equal to the current but completely independent from it.

        cloned_session = session.clone()
        """
        session = super(Session, self).clone()
        session.__class__ = self.__class__
        session._node = self._node
        return session

    @property
    def routes(self):
        """
        Return current routes table.

        routes = session.routes
        """
        return RouteList.from_routes(super(Session, self).routes)

    def lookup_address(self, key, group_id):
        """
        Return address of node from specified @group_id which is responsible for the key.

        address = session.lookup_address('looking up key')
        print 'looking up key' should lives on node:', address
        """
        return Address.from_host_port(super(Session, self).lookup_address(key, group_id))

    def set_indexes(self, id, indexes, datas=None):
        """
        Reset id indexes. The id will be removed from previous indexes. Update list of indexes where id is.

        Return elliptics.AsyncResult.
        -- id - string or elliptics.Id
        -- indexes - iterable object which provides set of indexes or dict of {'index':'data'}
        -- datas - iterable object which provides data which will be associated with the id in the index.
        indexes_result = []
        try:
            result = session.set_indexes('key', ['index1', 'index2'], ['index1_key_data', 'index2_key_data'])
            indexes_result = result.get()
        except Exception as e:
            print 'Set indexes has been failed:', e
        try:
            result = session.set_indexes('key', {'index1':'index1_key_data',
                                                 'index2':'index2_key_data'})
            indexes_result = result.get()
        except Exception as e:
            print 'Set indexes has been failed:', e
        """
        if type(indexes) is dict:
            datas = indexes.values()
            indexes = indexes.keys()

        return super(Session, self).set_indexes(id, indexes, datas)

    def update_indexes(self, id, indexes, datas=None):
        """
        Add @id to additional @indexes and/or update data for the @id in specified @indexes.

        Also update list of indexes where @id is.
        Return elliptics.AsyncResult.
        -- id - string or elliptics.Id
        -- indexes - iterable object which provides set of indexes or dict of {'index':'data'}
        -- datas - iterable object which provides data which will be associated with the id in the index.
        indexes_result = []
        try:
            result = session.update_indexes('key', ['index3', 'index4'],
                                            ['index3_key_data', 'index4_key_data'])
            indexes_result = result.get()
        except Exception as e:
            print 'Update indexes has been failed:', e
        try:
            result = session.update_indexes('key', {'index3':'index3_key_data',
                                                    'index4':'index4_key_data'})
            indexes_result = result.get()
        except Exception as e:
            print 'Update indexes has been failed:', e
        """
        if type(indexes) is dict:
            datas = indexes.values()
            indexes = indexes.keys()

        return super(Session, self).update_indexes(id, indexes, datas)

    def update_indexes_internal(self, id, indexes, datas=None):
        """
        Add id to additional @indexes and/or update data for the @id in specified @indexes.

        Don't update list of indexes where @id is.
        Return elliptics.AsyncResult.
        -- id - string or elliptics.Id
        -- indexes - iterable object which provides set of indexes
        -- datas - iterable object which provides data which will be associated with the id in the index.
        indexes_result = []
        try:
            result = session.update_indexes_internal('key', ['index5', 'index6'],
                                                     ['index5_key_data', 'index6_key_data'])
            indexes_result = result.get()
        except Exception as e:
            print 'Update indexes has been failed:', e
        indexes_result = []
        try:
            result = session.update_indexes_internal('key', {'index5':'index5_key_data',
                                                             'index6':'index6_key_data'})
            indexes_result = result.get()
        except Exception as e:
            print 'Update indexes internal has been failed:', e
        """
        if type(indexes) is dict:
            datas = indexes.values()
            indexes = indexes.keys()

        return super(Session, self).update_indexes_internal(id, indexes, datas)

    def set_direct_id(self, address, backend_id=None):
        """
        Make session sends all request directly to @address without forwarding.

        If @backend_id is not None all requests sent by session will be handled at specified backend
        """
        if backend_id is None:
            super(Session, self).set_direct_id(host=address.host,
                                               port=address.port,
                                               family=address.family)
        else:
            super(Session, self).set_direct_id(host=address.host,
                                               port=address.port,
                                               family=address.family,
                                               backend_id=backend_id)

    @property
    def forward(self):
        """
        If is set stick session to particular remote address.
        This remote won't handle request but will resend it to proper server node.
        If proper server node isn't available on forward node, forward node will fail request with -ENOTSUP error.
        """
        if self.__forward is None:
            return None
        return Address.from_host_port_family(self.__forward)

    @forward.setter
    def forward(self, remote):
        self.__forward = None if remote is None else str(remote)

    @forward.deleter
    def forward(self):
        self.__forward = None

    def update_status(self, address, status):
        """
        Update status of @address to @status.

        If address is elliptics.Address then status of this node will be updated.
        """
        super(Session, self).update_status(host=address.host,
                                           port=address.port,
                                           family=address.family,
                                           status=status)

    def enable_backend(self, address, backend_id):
        """
        Enable backend @backend_id on @address.

        Return elliptics.AsyncResult that provides new status of backend
        """
        return super(Session, self).enable_backend(host=address.host,
                                                   port=address.port,
                                                   family=address.family,
                                                   backend_id=backend_id)

    def disable_backend(self, address, backend_id):
        """
        Disable backend @backend_id on @address.

        Return elliptics.AsyncResult that provides new status of backend
        """
        return super(Session, self).disable_backend(host=address.host,
                                                    port=address.port,
                                                    family=address.family,
                                                    backend_id=backend_id)

    def start_defrag(self, address, backend_id):
        """
        Start defragmentation of backend @backend_id on @address.

        Return elliptics.AsyncResult that provides new status of backend
        """
        return super(Session, self).start_defrag(host=address.host,
                                                 port=address.port,
                                                 family=address.family,
                                                 backend_id=backend_id)

    def start_compact(self, address, backend_id):
        """
        Start compaction of backend @backend_id on @address.

        Return elliptics.AsyncResult that provides new status of backend
        """
        return super(Session, self).start_compact(host=address.host,
                                                  port=address.port,
                                                  family=address.family,
                                                  backend_id=backend_id)

    def stop_defrag(self, address, backend_id):
        """
        Stop defragmentation of backend @backend_id on @address.

        Return elliptics.AsyncResult that provides new status of backend
        """
        return super(Session, self).stop_defrag(host=address.host,
                                                port=address.port,
                                                family=address.family,
                                                backend_id=backend_id)

    def request_backends_status(self, address):
        """
        Request statuses of all backends from @address.

        Return elliptics.AsyncResult that provides statuses of all presented backend
        """
        return super(Session, self).request_backends_status(host=address.host,
                                                            port=address.port,
                                                            family=address.family)

    def make_readonly(self, address, backend_id):
        """Make read-only backend @backend_id on @address."""
        return super(Session, self).make_readonly(host=address.host,
                                                  port=address.port,
                                                  family=address.family,
                                                  backend_id=backend_id)

    def make_writable(self, address, backend_id):
        """Make read-write-able backend @backend_id on @address."""
        return super(Session, self).make_writable(host=address.host,
                                                  port=address.port,
                                                  family=address.family,
                                                  backend_id=backend_id)

    def set_backend_ids(self, address, backend_id, ids):
        """Set new ids to backend with @backend_id at node addressed by @host, @port, @family."""
        return super(Session, self).set_backend_ids(host=address.host,
                                                    port=address.port,
                                                    family=address.family,
                                                    backend_id=backend_id,
                                                    ids=ids)

    def set_delay(self, address, backend_id, delay):
        """Set @delay in milliseconds for backend with @backend_id at node @address."""
        return super(Session, self).set_delay(host=address.host,
                                              port=address.port,
                                              family=address.family,
                                              backend_id=backend_id,
                                              delay=delay)

    def monitor_stat(self, address=None, categories=monitor_stat_categories.all):
        """
        Gather monitor statistics of specified categories from @address.

        If @address is None monitoring statistics will be gathered from all nodes.
        result = session.monitor_stat(elliptics.Address.from_host_port('host.com:1025'))
        stats = result.get()
        """
        if not address:
            address = ()
        else:
            address = tuple(address)
        return super(Session, self).monitor_stat(address, categories)

    def start_iterator(self, address, backend_id, flags, key_ranges=None, time_range=None):
        """Start iterator on node @address and backend @backend_id."""
        return super(Session, self).start_iterator(host=address.host,
                                                   port=address.port,
                                                   family=address.family,
                                                   backend_id=backend_id,
                                                   flags=flags,
                                                   key_ranges=key_ranges,
                                                   time_range=time_range)
