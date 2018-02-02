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

#include "backends_stat_provider.hpp"

#include <blackhole/attribute.hpp>

#include "statistics.hpp"

#include "library/elliptics.h"
#include "library/backend.h"
#include "library/request_queue.h"

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "cache/cache.hpp"

namespace ioremap { namespace monitor {

backends_stat_provider::backends_stat_provider(struct dnet_node *node)
: m_node(node)
{}

/*
 * Generates json statistics from backends in accordance with the request
 */
void backends_stat_provider::statistics(const request &request,
                                        rapidjson::Value &value,
                                        rapidjson::Document::AllocatorType &allocator) const {
	if (!(request.categories & (DNET_MONITOR_IO | DNET_MONITOR_CACHE | DNET_MONITOR_BACKEND)))
		return;

	m_node->io->backends_manager->statistics(request, value, allocator);
}

}} /* namespace ioremap::monitor */

void dnet_backend_command_stats_update(struct dnet_backend *backend,
                                       struct dnet_cmd *cmd,
                                       uint64_t size,
                                       int handled_in_cache,
                                       int err,
                                       long diff) {
	if (!backend)
		return;

	backend->command_stats().command_counter(cmd->cmd, cmd->trans, err, handled_in_cache, size, diff);
}
