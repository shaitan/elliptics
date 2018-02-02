/*
 * Copyright 2013+ Kirill Smorodinnikov <shaitkir@gmail.com>
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
 * You should have received a copy of the GNU General Public License
 * along with Elliptics.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __DNET_STAT_PROVIDER_HPP
#define __DNET_STAT_PROVIDER_HPP

#include <unordered_set>

#include "rapidjson/document.h"

namespace ioremap { namespace monitor {
/*!
 * Struct that stores statistics categories and ids of requested backends
 */
struct request {
	uint64_t categories;
	std::unordered_set<uint32_t> backends_ids;

	request(): categories(0) {}
	request(uint64_t req_categories): categories(req_categories) {}
};

/*!
 * \internal
 *
 * Interface of statistics provider
 * Subsystems which wants to have their own statistics should create provider
 * and add it to statistics via add_provider method
 */
class stat_provider {
public:

	/*!
	 * \internal
	 *
	 * Returns json string of the real provider statistics
	 * \a request - struct that stores categories which statistics should be included to json
	 * and ids of requested backends
	 */
	virtual void statistics(const request &request,
	                        rapidjson::Value &value,
	                        rapidjson::Document::AllocatorType &allocator) const = 0;

	/*!
	 * \internal
	 *
	 * Destructor
	 */
	virtual ~stat_provider() {}
};

}} /* namespace ioremap::monitor */

#endif /* __DNET_STAT_PROVIDER_HPP */
