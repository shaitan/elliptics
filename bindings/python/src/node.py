# =============================================================================
# 2013+ Copyright (c) Kirill Smorodinnikov <shaitkir@gmail.com>
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

import elliptics.core

from elliptics import log_level
from elliptics.log import Logger
from elliptics.log import logged_class
from elliptics.route import Address


@logged_class
class Node(elliptics.core.Node):
    '''
    Node represents a connection with Elliptics.
    '''
    def __init__(self, logger, access_logger=None, config=None):
        """Initializes node by the logger, the logger for access entry and custom configuration

        node = elliptics.Node(logger)
        node = elliptics.Node(logger, config)
        node = elliptics.Node(logger, access_logger)
        node = elliptics.Node(logger, access_logger, config)
        """
        if access_logger is None:
            if config is None:
                super(Node, self).__init__(logger)
            else:
                super(Node, self).__init__(logger, config)
        else:
            if config is None:
                super(Node, self).__init__(logger, access_logger)
            else:
                super(Node, self).__init__(logger, access_logger, config)

        self.__logger = logger
        self.__access_logger = access_logger

    def add_remotes(self, remotes):
        '''
           Adds connections to Elliptics node
           @remotes -- elliptics.Addresses of server node

           node.add_remotes(Address.from_host_port("host.com:1025"))
           node.add_remotes([Address.from_host_port("host.com:1025"),
                             Address.from_host_port("host.com:1026"),
                             "host.com:1027:2"])
        '''
        def convert(address, b_raised=True):
            if type(address) is str:
                return tuple(Address.from_host_port_family(address))
            elif type(address) is Address:
                return tuple(address)
            elif b_raised:
                raise ValueError("Couldn't convert {0} to elliptics.Address".format(repr(address)))

        addr = convert(remotes, False)
        if addr is not None:
            super(Node, self).add_remotes((addr, ))
        elif hasattr(remotes, '__iter__'):
            super(Node, self).add_remotes(map(convert, remotes))
        else:
            raise ValueError("Couldn't convert {0} to elliptics.Address".format(repr(remotes)))


def create_node(elog=None,
                log_file='/dev/stderr',
                log_level=log_level.error,
                cfg=None,
                wait_timeout=3600,
                check_timeout=60,
                flags=0,
                io_thread_num=1,
                net_thread_num=1,
                nonblocking_io_thread_num=1,
                remotes=[],
                log_watched=False,
                access_logger=None):
    if not elog:
        elog = Logger(log_file, log_level, log_watched)

    if not cfg:
        cfg = elliptics.core.Config()
        cfg.wait_timeout = wait_timeout
        cfg.check_timeout = check_timeout
        cfg.flags = flags
        cfg.io_thread_num = io_thread_num
        cfg.nonblocking_io_thread_num = nonblocking_io_thread_num
        cfg.net_thread_num = net_thread_num

    n = Node(logger=elog, access_logger=access_logger, config=cfg)
    try:
        n.add_remotes(remotes)
    except:
        pass
    return n
