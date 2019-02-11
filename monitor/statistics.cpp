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

#include "statistics.hpp"

#include <blackhole/attribute.hpp>

#include "monitor.hpp"
#include "cache/cache.hpp"
#include "elliptics/backends.h"
#include "monitor/compress.hpp"

//FIXME: elliptics uses rather modified version of rapidjson
// which is partially incompatible with a stock version used by
// handystats, so its a necessity to include exactly prettywriter.h,
// its effectively forces selection of elliptics' version of rapidjson
// in its entirety.
#include "rapidjson/stringbuffer.h"
#include "rapidjson/prettywriter.h"

#ifdef HAVE_HANDYSTATS
#include <handystats/json_dump.hpp>
#endif

namespace ioremap { namespace monitor {

static void ext_stat_json(const ext_counter &ext_stat,
                          rapidjson::Value &stat_value,
                          rapidjson::Document::AllocatorType &allocator) {
	stat_value.AddMember("successes", ext_stat.counter.successes, allocator);
	stat_value.AddMember("failures", ext_stat.counter.failures, allocator);
	stat_value.AddMember("size", ext_stat.size, allocator);
	stat_value.AddMember("time", ext_stat.time, allocator);
}

static void source_stat_json(const source_counter &source_stat,
                             rapidjson::Value &stat_value,
                             rapidjson::Document::AllocatorType &allocator) {
	rapidjson::Value outside_stat(rapidjson::kObjectType);
	ext_stat_json(source_stat.outside, outside_stat, allocator);
	stat_value.AddMember("outside", outside_stat, allocator);

	rapidjson::Value internal_stat(rapidjson::kObjectType);
	ext_stat_json(source_stat.internal, internal_stat, allocator);
	stat_value.AddMember("internal", internal_stat, allocator);
}

static void dnet_stat_count_json(const dnet_stat_count &counter, rapidjson::Value &stat_value,
		rapidjson::Document::AllocatorType &allocator) {
	stat_value.AddMember("successes", counter.count, allocator);
	stat_value.AddMember("failures", counter.err, allocator);
}

static void node_stat_json(dnet_node *n, int cmd, rapidjson::Value &stat_value,
		rapidjson::Document::AllocatorType &allocator) {
	rapidjson::Value storage_stat(rapidjson::kObjectType);
	dnet_stat_count_json(n->counters[cmd], storage_stat, allocator);
	stat_value.AddMember("storage", storage_stat, allocator);

	rapidjson::Value proxy_stat(rapidjson::kObjectType);
	dnet_stat_count_json(n->counters[cmd + __DNET_CMD_MAX], proxy_stat, allocator);
	stat_value.AddMember("proxy", proxy_stat, allocator);
}

static void cmd_stat_json(dnet_node *node, int cmd, const command_counters &cmd_stat,
		rapidjson::Value &stat_value, rapidjson::Document::AllocatorType &allocator) {
	rapidjson::Value cache_stat(rapidjson::kObjectType);
	source_stat_json(cmd_stat.cache, cache_stat, allocator);
	stat_value.AddMember("cache", cache_stat, allocator);

	rapidjson::Value disk_stat(rapidjson::kObjectType);
	source_stat_json(cmd_stat.disk, disk_stat, allocator);
	stat_value.AddMember("disk", disk_stat, allocator);

	/*
	 * @node is only set for global counters
	 */
	if (node) {
		rapidjson::Value total_stat(rapidjson::kObjectType);
		node_stat_json(node, cmd, total_stat, allocator);
		stat_value.AddMember("total", total_stat, allocator);
	}
}

static void single_client_stat_json(dnet_net_state *st, rapidjson::Value &stat_value,
		rapidjson::Document::AllocatorType &allocator) {
	for (int i = 1; i < __DNET_CMD_MAX; ++i) {
		if (st->stat[i].count != 0 || st->stat[i].err != 0) {
			rapidjson::Value cmd_stat(rapidjson::kObjectType);
			dnet_stat_count_json(st->stat[i], cmd_stat, allocator);
			stat_value.AddMember(dnet_cmd_string(i), allocator, cmd_stat, allocator);
		}
	}
}

static void clients_stat_json(dnet_node *n, rapidjson::Value &stat_value,
		rapidjson::Document::AllocatorType &allocator) {
	struct dnet_net_state *st;

	pthread_mutex_lock(&n->state_lock);
	try {
		list_for_each_entry(st, &n->empty_state_list, node_entry) {
			rapidjson::Value client_stat(rapidjson::kObjectType);
			single_client_stat_json(st, client_stat, allocator);
			stat_value.AddMember(dnet_addr_string(&st->addr), allocator, client_stat, allocator);
		}
	} catch(std::exception &e) {
		pthread_mutex_unlock(&n->state_lock);
		DNET_LOG_ERROR(n, "monitor: failed collecting client state stats: {}", e.what());
		throw;
	} catch(...) {
		pthread_mutex_unlock(&n->state_lock);
		DNET_LOG_ERROR(n, "monitor: failed collecting client state stats: unknown exception");
		throw;
	}
	pthread_mutex_unlock(&n->state_lock);
}

command_stats::command_stats()
: m_cmd_stats(__DNET_CMD_MAX) {}

void command_stats::clear() {
	std::unique_lock<std::mutex> guard(m_cmd_stats_mutex);
	memset(m_cmd_stats.data(), 0, sizeof(m_cmd_stats.front()) * m_cmd_stats.size());
}

void command_stats::command_counter(const int orig_cmd,
                                 const uint64_t trans,
                                 const int err,
                                 const int cache,
                                 const uint64_t size,
                                 const unsigned long time)
{
	int cmd = orig_cmd;

	if (cmd >= __DNET_CMD_MAX || cmd <= 0)
		cmd = DNET_CMD_UNKNOWN;

	auto &place = cache ? m_cmd_stats[cmd].cache : m_cmd_stats[cmd].disk;
	auto &source = trans ? place.outside : place.internal;
	auto &counter = err ? source.counter.failures : source.counter.successes;

	std::unique_lock<std::mutex> guard(m_cmd_stats_mutex);
	++counter;
	source.size += size;
	source.time += time;
}

void command_stats::commands_report(dnet_node *node,
                                    rapidjson::Value &stat_value,
                                    rapidjson::Document::AllocatorType &allocator) const {
	std::unique_lock<std::mutex> guard(m_cmd_stats_mutex);
	auto tmp_stats = m_cmd_stats;
	guard.unlock();

	for (int i = 1; i < __DNET_CMD_MAX; ++i) {
		if (tmp_stats[i].has_data()) {
			rapidjson::Value cmd_stat(rapidjson::kObjectType);
			cmd_stat_json(node, i, tmp_stats[i], cmd_stat, allocator);
			stat_value.AddMember(dnet_cmd_string(i), allocator, cmd_stat, allocator);
		}
	}
}

void statistics::command_counter(const int cmd,
                                 const uint64_t trans,
                                 const int err,
                                 const int cache,
                                 const uint64_t size,
                                 const unsigned long time)
{
	m_command_stats.command_counter(cmd, trans, err, cache, size, time);
}

statistics::statistics(monitor& mon, struct dnet_config *cfg) : m_monitor(mon)
{
	(void) cfg;
	const auto monitor_cfg = get_monitor_config(mon.node());
	if (monitor_cfg && monitor_cfg->has_top) {
		m_top_stats = std::make_shared<top_stats>(monitor_cfg->top_length, monitor_cfg->events_size, monitor_cfg->period_in_seconds);
	}
}

void statistics::add_provider(stat_provider *stat, const std::string &name)
{
	std::unique_lock<std::mutex> guard(m_provider_mutex);
	m_stat_providers.insert(make_pair(name, std::shared_ptr<stat_provider>(stat)));
}

inline std::string convert_report(const rapidjson::Document &report)
{
	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	report.Accept(writer);
	return compress(buffer.GetString());
}

std::string statistics::report(const request &request)
{
	rapidjson::Document report;
	DNET_LOG_INFO(m_monitor.node(), "monitor: collecting statistics for categories: {:x}", request.categories);
	report.SetObject();
	auto &allocator = report.GetAllocator();

	dnet_time time;
	dnet_current_time(&time);

	rapidjson::Value timestamp(rapidjson::kObjectType);
	timestamp.AddMember("tv_sec", time.tsec, allocator);
	timestamp.AddMember("tv_usec", time.tnsec / 1000, allocator);
	report.AddMember("timestamp", timestamp, allocator);
	report.AddMember("string_timestamp", dnet_print_time(&time), allocator);

	report.AddMember("monitor_status", "enabled", allocator);
	report.AddMember("categories", request.categories, allocator);

	if (request.categories & DNET_MONITOR_COMMANDS) {
		rapidjson::Value commands_value(rapidjson::kObjectType);
		m_command_stats.commands_report(m_monitor.node(), commands_value, allocator);

		rapidjson::Value clients_stat(rapidjson::kObjectType);
		clients_stat_json(m_monitor.node(), clients_stat, allocator);
		commands_value.AddMember("clients", clients_stat, allocator);

		report.AddMember("commands", commands_value, allocator);
	}

	if (request.categories & DNET_MONITOR_STATS) {
#if defined(HAVE_HANDYSTATS) && !defined(HANDYSTATS_DISABLE)
		rapidjson::Document stats(&allocator);
		stats.Parse<0>(HANDY_JSON_DUMP().c_str());
		report.AddMember("stats", static_cast<rapidjson::Value &>(stats), allocator);
#else
		report.AddMember("__stats__", "stats subsystem disabled at compile time", allocator);
#endif
	}

	std::unique_lock<std::mutex> guard(m_provider_mutex);
	for (auto &item : m_stat_providers) {
		const auto &provider_name = item.first;
		const auto &provider = item.second;

		rapidjson::Value value;
		provider->statistics(request, value, allocator);
		report.AddMember(provider_name.c_str(), allocator, value, allocator);
	}

	DNET_LOG_DEBUG(m_monitor.node(), "monitor: finished generating json statistics for categories: {:x}",
	               request.categories);
	return convert_report(report);
}

}} /* namespace ioremap::monitor */
