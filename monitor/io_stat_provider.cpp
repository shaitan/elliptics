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

#include "io_stat_provider.hpp"

#include "library/backend.h"
#include "library/elliptics.h"
#include "library/request_queue.h"

namespace ioremap { namespace monitor {

// fill @value with all states' statistics
static rapidjson::Value & fill_states_stats(struct dnet_node *n,
                                            rapidjson::Value &value,
                                            rapidjson::Document::AllocatorType &allocator) {
	pthread_mutex_lock(&n->state_lock);
	struct dnet_net_state *st;
	list_for_each_entry(st, &n->empty_state_list, node_entry) {
		rapidjson::Value state(rapidjson::kObjectType);
		state.AddMember("send_queue_size", atomic_read(&st->send_queue_size), allocator);
		state.AddMember("la", st->la, allocator);
		state.AddMember("free", (uint64_t)st->free, allocator);
		state.AddMember("stall", st->stall, allocator);
		state.AddMember("join_state", st->__join_state, allocator);
		value.AddMember(dnet_addr_string(&st->addr), allocator, state, allocator);
	}
	pthread_mutex_unlock(&n->state_lock);

	return value;
}

void io_stat_provider::statistics(uint64_t categories,
                                  rapidjson::Value &value,
                                  rapidjson::Document::AllocatorType &allocator) const {
	if (!(categories & DNET_MONITOR_IO))
		return;

	value.SetObject();
	dump_io_pool_stats(m_node->io->pool, value, allocator);

	rapidjson::Value output(rapidjson::kObjectType);
	output.AddMember("current_size", m_node->io->output_stats.list_size, allocator);
	value.AddMember("output", output, allocator);

	rapidjson::Value states(rapidjson::kObjectType);
	value.AddMember("states", fill_states_stats(m_node, states, allocator), allocator);
	value.AddMember("blocked", m_node->io->blocked == 1, allocator);

	rapidjson::Value pools(rapidjson::kObjectType);
	dnet_io_pools_fill_stats(m_node, pools, allocator);
	value.AddMember("pools", pools, allocator);
}

void dump_io_pool_stats(struct dnet_io_pool &io_pool,
                        rapidjson::Value &value,
                        rapidjson::Document::AllocatorType &allocator) {
	rapidjson::Value blocking(rapidjson::kObjectType);
	blocking.AddMember("current_size", dnet_get_pool_queue_size(io_pool.recv_pool.pool), allocator);
	value.AddMember("blocking", blocking, allocator);

	rapidjson::Value nonblocking(rapidjson::kObjectType);
	nonblocking.AddMember("current_size", dnet_get_pool_queue_size(io_pool.recv_pool_nb.pool), allocator);
	value.AddMember("nonblocking", nonblocking, allocator);
}

}} /* namespace ioremap::monitor */
