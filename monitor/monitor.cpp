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

#include "monitor.h"
#include "monitor.hpp"
#include "compress.hpp"

#include <exception>
#include <iostream>

#include "library/elliptics.h"
#include "io_stat_provider.hpp"
#include "backends_stat_provider.hpp"
#include "procfs_provider.hpp"

#include "example/config.hpp"

static unsigned int get_monitor_port(struct dnet_node *n) {
	const auto monitor = ioremap::monitor::get_monitor_config(n);
	return monitor ? monitor->monitor_port : 0;
}

#ifdef HAVE_HANDYSTATS
#include <handystats/core.hpp>
#endif

namespace ioremap { namespace monitor {

monitor *get_monitor(struct dnet_node *n) {
	return reinterpret_cast<monitor *>(n->monitor);
}

monitor_config* get_monitor_config(struct dnet_node *n) {
	const auto& data = *static_cast<const ioremap::elliptics::config::config_data *>(n->config_data);
	return data.monitor_config.get();
}

std::unique_ptr<monitor_config> monitor_config::parse(const kora::config_t &monitor) {
	std::unique_ptr<monitor_config> cfg{new monitor_config()};

	cfg->monitor_port = monitor.at<unsigned int>("port", 0);

	cfg->has_top = monitor.has("top");
	if (cfg->has_top) {
		const auto top = monitor["top"];
		cfg->top_length = top.at<size_t>("top_length", DNET_DEFAULT_MONITOR_TOP_LENGTH);
		cfg->events_size = top.at<size_t>("events_size", DNET_DEFAULT_MONITOR_TOP_EVENTS_SIZE);
		cfg->period_in_seconds = top.at<int>("period_in_seconds", DNET_DEFAULT_MONITOR_TOP_PERIOD);
		cfg->has_top = (cfg->top_length > 0) && (cfg->events_size > 0) && (cfg->period_in_seconds > 0);
	}

	if (monitor.has("handystats")) {
		cfg->handystats = kora::to_json(monitor.underlying_object());
	}
	return cfg;
}

monitor::monitor(struct dnet_node *n, struct dnet_config *cfg)
: m_node(n)
, m_statistics(*this, cfg)
, m_server(*this, get_monitor_port(n), cfg->family) {
#if defined(HAVE_HANDYSTATS) && !defined(HANDYSTATS_DISABLE)
	const auto monitor_config = get_monitor_config(n);
	if (cfg->handystats_config != nullptr) {
		//TODO: add parse/configuration errors logging when handystats will allow to get them
		if (HANDY_CONFIG_FILE(cfg->handystats_config)) {
			DNET_LOG_INFO(n, "monitor: initializing stats subsystem, config file '{}'",
			              cfg->handystats_config);
		} else {
			DNET_LOG_ERROR(n, "monitor: initializing stats subsystem, "
			                  "error parsing config file '{}', using defaults",
			               cfg->handystats_config);
		}
	} else if (!monitor_config->handystats.empty()) {
		if (HANDY_CONFIG_JSON(monitor_config->handystats.c_str())) {
			DNET_LOG_INFO(n, "monitor: initializing stats subsystem, "
			                 "using config[\"monitor\"][\"handystats\"]");
		} else {
			DNET_LOG_ERROR(n, "monitor: initializing stats subsystem, "
			                  "error parsing config[\"monitor\"][\"handystats\"], using defaults");
		}
	} else {
		DNET_LOG_INFO(n, "monitor: initializing stats subsystem, no config file specified, using defaults");
	}
	HANDY_INIT();
#else
	DNET_LOG_INFO(n, "monitor: stats subsystem disabled at compile time");
#endif
}

monitor::~monitor() {
	//TODO: is node still alive here? If so, add shutdown log messages
	// for both monitoring and handystats
	stop();
#if defined(HAVE_HANDYSTATS) && !defined(HANDYSTATS_DISABLE)
	HANDY_FINALIZE();
#endif
}

void monitor::stop() {
	m_server.stop();
}

void add_provider(struct dnet_node *n, stat_provider *provider, const std::string &name) {
	auto real_monitor = get_monitor(n);
	if (real_monitor)
		real_monitor->get_statistics().add_provider(provider, name);
	else
		delete provider;
}

void remove_provider(dnet_node *n, const std::string &name)
{
	auto real_monitor = get_monitor(n);
	if (real_monitor)
		real_monitor->get_statistics().remove_provider(name);
}

static void init_io_stat_provider(struct dnet_node *n) {
	try {
		add_provider(n, new io_stat_provider(n), "io");
	} catch (const std::exception &e) {
		DNET_LOG_ERROR(n, "monitor: failed to initialize io_stat_provider: {}", e.what());
	}
}

static void init_backends_stat_provider(struct dnet_node *n) {
	try {
		add_provider(n, new backends_stat_provider(n), "backends");
	} catch (const std::exception &e) {
		DNET_LOG_ERROR(n, "monitor: failed to initialize backends_stat_provider: {}", e.what());
	}
}

static void init_procfs_provider(struct dnet_node *n) {
	try {
		add_provider(n, new procfs_provider(n), "procfs");
	} catch (const std::exception &e) {
		DNET_LOG_ERROR(n, "monitor: failed to initialize procfs_stat_provider: {}", e.what());
	}
}

static void init_top_provider(struct dnet_node *n) {
	try {
		bool top_loaded = false;
		const auto monitor = get_monitor(n);
		if (monitor) {
			auto top_stats = monitor->get_statistics().get_top_stats();
			if (top_stats) {
				add_provider(n, new top_provider(top_stats), "top");
				top_loaded = true;
			}
		}

		const auto monitor_cfg = get_monitor_config(n);
		if (top_loaded && monitor_cfg) {
			DNET_LOG_INFO(n, "monitor: top provider loaded: top length: {}, events size: {}, period: {}",
			              monitor_cfg->top_length, monitor_cfg->events_size,
			              monitor_cfg->period_in_seconds);
		} else {
			DNET_LOG_INFO(n, "monitor: top provider is disabled");
		}

	} catch (const std::exception &e) {
		DNET_LOG_ERROR(n, "monitor: failed to initialize top_stat_provider: {}", e.what());
	}
}

}} /* namespace ioremap::monitor */

int dnet_monitor_init(struct dnet_node *n, struct dnet_config *cfg) {
	if (!get_monitor_port(n) || !cfg->family) {
		n->monitor = NULL;
		DNET_LOG_ERROR(n, "monitor: monitor hasn't been initialized because monitor port is zero");
		return 0;
	}

	try {
		n->monitor = static_cast<void*>(new ioremap::monitor::monitor(n, cfg));
	} catch (const std::exception &e) {
		DNET_LOG_ERROR(n, "monitor: failed to initialize monitor on port: {}: {}", get_monitor_port(n),
		               e.what());
		return -ENOMEM;
	}

	ioremap::monitor::init_io_stat_provider(n);
	ioremap::monitor::init_backends_stat_provider(n);
	ioremap::monitor::init_procfs_provider(n);
	ioremap::monitor::init_top_provider(n);

	return 0;
}

void dnet_monitor_exit(struct dnet_node *n) {
	auto real_monitor = ioremap::monitor::get_monitor(n);
	if (real_monitor) {
		n->monitor = NULL;
		delete real_monitor;
	}
}

void dnet_monitor_add_provider(struct dnet_node *n, struct stat_provider_raw stat, const char *name) {
	try {
		auto provider = new ioremap::monitor::raw_provider(stat);
		ioremap::monitor::add_provider(n, provider, std::string(name));
	} catch (const std::exception &e) {
		std::cerr << e.what() << std::endl;
	}
}

void dnet_monitor_remove_provider(struct dnet_node *n, const char *name) {
	ioremap::monitor::remove_provider(n, std::string(name));
}

void dnet_monitor_stats_update(struct dnet_node *n,
                               const struct dnet_cmd *cmd,
                               const int err,
                               const int cache,
                               const uint32_t size,
                               const unsigned long time) {
	try {
		auto real_monitor = ioremap::monitor::get_monitor(n);
		if (real_monitor) {
			real_monitor->get_statistics().command_counter(cmd->cmd, cmd->trans, err, cache, size, time);
			auto top_stats = real_monitor->get_statistics().get_top_stats();
			if (top_stats) {
				top_stats->update_stats(cmd, size);
			}
		}
	} catch (const std::exception &e) {
		DNET_LOG_DEBUG(n, "monitor: failed to update stats: {}", e.what());
	}
}

int dnet_monitor_process_cmd(struct dnet_net_state *orig, struct dnet_cmd *cmd, void *data) {
	if (cmd->size != sizeof(dnet_monitor_stat_request)) {
		DNET_LOG_DEBUG(orig->n, "monitor: {}: {}: process MONITOR_STAT, invalid size: {}",
		               dnet_state_dump_addr(orig), dnet_dump_id(&cmd->id), cmd->size);
		return -EINVAL;
	}

	struct dnet_node *n = orig->n;
	auto req = static_cast<struct dnet_monitor_stat_request *>(data);
	dnet_convert_monitor_stat_request(req);
	static const std::string disabled_reply = ioremap::monitor::compress("{\"monitor_status\":\"disabled\"}");

	DNET_LOG_DEBUG(n, "monitor: {}: {}: process MONITOR_STAT, categories: {:x}, monitor: {:p}",
	               dnet_state_dump_addr(orig), dnet_dump_id(&cmd->id), req->categories, (void *)n->monitor);

	auto real_monitor = ioremap::monitor::get_monitor(n);
	if (!real_monitor)
		return dnet_send_reply(orig, cmd, disabled_reply.c_str(), disabled_reply.size(), 0);

	try {
		auto json = real_monitor->get_statistics().report(req->categories);
		return dnet_send_reply(orig, cmd, &*json.begin(), json.size(), 0);
	} catch(const std::exception &e) {
		const std::string rep =
		        ioremap::monitor::compress("{\"monitor_status\":\"failed: " + std::string(e.what()) + "\"}");
		DNET_LOG_DEBUG(orig->n, "monitor: failed to generate json: {}", e.what());
		return dnet_send_reply(orig, cmd, &*rep.begin(), rep.size(), 0);
	}
}
