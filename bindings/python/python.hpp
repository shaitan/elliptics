/*
 * Copyright 2017+ Kirill Smorodinnikov <shaitkir@gmail.com>
 *
 * This file is part of Elliptics.
 *
 * Elliptics is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Elliptics is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Elliptics.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

namespace ioremap { namespace  elliptics { namespace python {

enum class defrag_state {
	NOT_STARTED = DNET_BACKEND_DEFRAG_NOT_STARTED,
	DATA_SORT = DNET_BACKEND_DEFRAG_IN_PROGRESS,
	INDEX_SORT = DNET_BACKEND_INDEX_SORT_IN_PROGRESS,
	COMPACT = DNET_BACKEND_COMPACT_IN_PROGRESS,
};

enum class inspect_state {
	NOT_STARTED = DNET_BACKEND_INSPECT_NOT_STARTED,
	IN_PROGRESS = DNET_BACKEND_INSPECT_IN_PROGRESS,
};

}}} /* namespace ioremap::elliptics::python */
