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

import warnings

from elliptics import record_flags
from elliptics.core import CallbackResultEntry
from elliptics.core import LookupResultEntry
from elliptics.core import MonitorStatResultEntry
from elliptics.core import RouteEntry
from elliptics.route import Address

warnings.simplefilter('always', PendingDeprecationWarning)


def dump_record_flags(flags):
    return '|'.join(name for name, flag in record_flags.names.iteritems() if flags & flag)


@property
def storage_address(self):
    """
    Node address as elliptics.Address
    """
    return Address.from_host_port(self.__storage_address__)


@property
def monitor_statistics(self):
    from json import loads
    return loads(self.__statistics__)


def wrap_address(classes):
    @property
    def address(self):
        """
        Node address as elliptics.Address
        """
        return Address.from_host_port(self.__address__)
    for cls in classes:
        cls.__address__ = cls.address
        cls.address = address

LookupResultEntry.__storage_address__ = LookupResultEntry.storage_address
LookupResultEntry.storage_address = storage_address

MonitorStatResultEntry.__statistics__ = MonitorStatResultEntry.statistics
MonitorStatResultEntry.statistics = monitor_statistics

wrap_address([CallbackResultEntry,
              RouteEntry
              ])


del storage_address
del wrap_address
