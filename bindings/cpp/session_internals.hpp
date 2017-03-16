/*
 * Copyright 2017+ Budnik Andrey <budnik27@gmail.com>
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

#ifndef IOREMAP_ELLIPTICS_SESSION_INTERNALS_HPP
#define IOREMAP_ELLIPTICS_SESSION_INTERNALS_HPP

#include "elliptics/newapi/result_entry.hpp"

namespace ioremap { namespace elliptics { namespace newapi {

async_read_result send_bulk_read(session &sess, const std::vector<dnet_id> &keys, uint64_t read_flags);

}}} // namespace ioremap::elliptics::newapi

#endif // IOREMAP_ELLIPTICS_SESSION_INTERNALS_HPP
