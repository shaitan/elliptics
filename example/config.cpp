/*
 * Copyright 2008+ Evgeniy Polyakov <zbr@ioremap.net>
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

#include "config.hpp"

#include <malloc.h>

#include <unordered_set>

#include <blackhole/config/json.hpp>
#include <blackhole/registry.hpp>
#include <blackhole/record.hpp>
#include <blackhole/root.hpp>
#include <blackhole/wrapper.hpp>

#include <kora/config.hpp>

#include "common.h"

#include "elliptics/session.hpp"
#include "library/backend.h"
#include "library/logger.hpp"
#include "monitor/monitor.hpp"

namespace ioremap { namespace elliptics { namespace config {

extern "C" void dnet_config_data_destroy(struct dnet_config_data *config) {
	if (!config)
		return;

	auto data = static_cast<config_data *>(config);

	free(data->cfg_addrs);

	delete data;
}

static blackhole::root_logger_t make_logger(config_data *data, const std::string &name) {
	auto root = blackhole::registry::configured()
	                    ->builder<blackhole::config::json_t>(std::istringstream{data->logger_value})
	                    .build(name);

	const auto &level = data->logger_level;
	root.filter([&level](const blackhole::record_t &record) {
		return log_filter(record.severity(), level);
	});
	return std::move(root);
}

static void parse_logger(config_data *data, const kora::config_t &logger) {
	try {
		const auto level = logger.at<std::string>("level", "info");
		data->logger_level = dnet_log_parse_level(level.c_str());
	} catch (std::exception &e) {
		throw config_error() << "failed to parse log level: " << e.what();
	}

	try {
		data->logger_value = kora::to_json(logger.underlying_object());
	} catch (std::exception &e) {
		throw config_error() << "failed to serialize logger's json: " << e.what();
	}

	try {
		data->root_holder.reset(new blackhole::root_logger_t(make_logger(data, "core")));
		if (logger.has("access"))
			data->access_holder.reset(new blackhole::root_logger_t(make_logger(data, "access")));
		else
			data->access_holder.reset(nullptr);

		auto wrap_logger = [&] (std::unique_ptr<blackhole::root_logger_t> &logger, bool access) -> wrapper_t * {
			std::unique_ptr<dnet_logger> base_wrapper{
				new blackhole::wrapper_t(*logger, {{"source", "elliptics"}})};

			if (access)
				return new wrapper_t{std::move(base_wrapper)};

			std::unique_ptr<wrapper_t> trace_wrapper{new trace_wrapper_t{std::move(base_wrapper)}};
			std::unique_ptr<wrapper_t> pool_wrapper{new pool_wrapper_t{std::move(trace_wrapper)}};
			return new backend_wrapper_t{std::move(pool_wrapper)};
		};

		data->logger.reset(wrap_logger(data->root_holder, false));
		if (data->access_holder)
			data->access_logger.reset(wrap_logger(data->access_holder, true));
		else
			data->access_logger.reset(nullptr);

		data->cfg_state.log = data->logger.get();
		data->cfg_state.access_log = data->access_logger.get();
	} catch (std::exception &e) {
		throw config_error() << "failed to initialize blackhole log: " << e.what();
	}
}

struct dnet_addr_wrap {
	struct dnet_addr	addr;
	int			addr_group;
};

static bool dnet_addr_wrap_less_than(const dnet_addr_wrap &w1, const dnet_addr_wrap &w2) {
	return w1.addr_group < w2.addr_group;
}

static void dnet_set_addr(config_data *data, const std::vector<std::string> &addresses) {
	if (addresses.empty())
		return;

	std::vector<dnet_addr_wrap> wraps;

	for (auto it = addresses.begin(); it != addresses.end(); ++it) {
		try {
			std::string address = *it;
			int group = -1;

			size_t delim_index = address.find_first_of(DNET_CONF_ADDR_DELIM);
			if (delim_index == std::string::npos)
				throw config_error() << "port and address delimiter is missed";

			size_t group_index = address.find_first_of('-', delim_index);

			if (group_index != std::string::npos) {
				try {
					group = stoi(address.substr(group_index + 1));
				} catch (std::exception &exc) {
					throw config_error() << "address group parse error: " << exc.what();
				}

				address.resize(group_index);
			}

			std::vector<char> address_copy(address.begin(), address.end());
			address_copy.push_back('\0');

			int port;
			int family;
			int err = dnet_parse_addr(address_copy.data(), &port, &family);

			if (err) {
				throw config_error() << *it << ": failed to parse address: " << strerror(-err) << ", "
				                     << err;
			}

			data->cfg_state.port = port;
			data->cfg_state.family = family;

			dnet_addr_wrap wrap;
			memset(&wrap, 0, sizeof(wrap));

			wrap.addr.addr_len = sizeof(wrap.addr.addr);
			wrap.addr.family = data->cfg_state.family;
			wrap.addr_group = group;
			err = dnet_fill_addr(&wrap.addr, address_copy.data(), port, SOCK_STREAM, IPPROTO_TCP);

			if (err) {
				throw config_error() << *it << ": could not resolve address: " << strerror(-err) << ", "
				                     << err;
			}

			wraps.push_back(wrap);
		} catch (std::exception &exc) {
			throw config_error() << "'options.address[" << std::distance(addresses.begin(), it) << "]', "
			                     << exc.what();
		}
	}

	if (!wraps.empty()) {
		std::sort(wraps.begin(), wraps.end(), dnet_addr_wrap_less_than);

		data->cfg_addrs = reinterpret_cast<dnet_addr *>(malloc(sizeof(struct dnet_addr) * wraps.size()));
		if (!data->cfg_addrs)
			throw std::bad_alloc();

		for (size_t i = 0; i < wraps.size(); ++i) {
			data->cfg_addrs[i] = wraps[i].addr;
		}
		data->cfg_addr_num = wraps.size();
	}
}

static int dnet_set_malloc_options(config_data *data, unsigned long long value) {
	int err, thr = value;

	err = mallopt(M_MMAP_THRESHOLD, thr);
	if (err < 0) {
		DNET_LOG_ERROR(data->cfg_state.log, "Failed to set mmap threshold to {}: {}", thr, strerror(errno));
		return err;
	}

	DNET_LOG_INFO(data->cfg_state.log, "Set mmap threshold to {}", thr);
	return 0;
}

uint64_t parse_queue_timeout(const kora::config_t &options) {
	if (!options.has("queue_timeout"))
		return 0;

	const auto timeout = options.at<std::string>("queue_timeout");
	const uint64_t queue_timeout = strtoul(timeout.c_str(), NULL, 0);

	const auto scale = [&timeout]() {
		constexpr uint64_t microsecond = 1;
		constexpr uint64_t millisecond = 1000 * microsecond;
		constexpr uint64_t second = 1000 * millisecond;
		constexpr uint64_t minute = 60 * second;
		constexpr uint64_t hour = 60 * minute;
		constexpr uint64_t day = 24 * hour;
		constexpr uint64_t week = 7 * day;

		auto check = [&timeout](const std::string &name) {
			return timeout.find(name) != std::string::npos;
		};

		if (check("us")) return microsecond;
		if (check("ms")) return millisecond;
		if (check("s")) return second;
		if (check("m")) return minute;
		if (check("h")) return hour;
		if (check("d")) return day;
		if (check("w")) return week;

		return second;
	} ();

	return queue_timeout * scale;
}

static void parse_options(config_data *data, const kora::config_t &options) {
	if (options.has("mallopt_mmap_threshold"))
		dnet_set_malloc_options(data, options.at<int>("mallopt_mmap_threshold"));

	data->cfg_state.wait_timeout = options.at("wait_timeout", 0u);
	data->cfg_state.check_timeout = options.at("check_timeout", 0l);
	data->cfg_state.stall_count = options.at("stall_count", DNET_DEFAULT_STALL_TRANSACTIONS);
	data->cfg_state.flags |= (options.at("join", false) ? DNET_CFG_JOIN_NETWORK : 0);
	data->cfg_state.flags |= (options.at("flags", 0) & ~DNET_CFG_JOIN_NETWORK);
	data->cfg_state.io_thread_num = options.at<unsigned>("io_thread_num");
	data->cfg_state.send_limit = options.at<unsigned>("send_limit", DNET_DEFAULT_SEND_LIMIT);
	data->cfg_state.nonblocking_io_thread_num = options.at<unsigned>("nonblocking_io_thread_num");
	data->cfg_state.net_thread_num = options.at<unsigned>("net_thread_num");
	data->cfg_state.bg_ionice_class = options.at("bg_ionice_class", 0);
	data->cfg_state.bg_ionice_prio = options.at("bg_ionice_prio", 0);
	data->cfg_state.removal_delay = options.at("removal_delay", 0);
	data->cfg_state.server_prio = options.at("server_net_prio", 0);
	data->cfg_state.client_prio = options.at("client_net_prio", 0);
	data->parallel_start = options.at("parallel", true);
	snprintf(data->cfg_state.cookie, DNET_AUTH_COOKIE_SIZE, "%s", options.at<std::string>("auth_cookie").c_str());

	dnet_set_addr(data, options.at("address", std::vector<std::string>()));

	const std::vector<std::string> remotes = options.at("remote", std::vector<std::string>());
	for (auto it = remotes.cbegin(); it != remotes.cend(); ++it) {
		try {
			data->remotes.emplace_back(*it);
		} catch (const std::exception &e) {
			DNET_LOG_ERROR(data->cfg_state.log, "Failed to add address to remotes: {}", e.what());
		}
	}

	if (options.has("monitor"))
		data->monitor_config = ioremap::monitor::monitor_config::parse(options["monitor"]);

	if (options.has("handystats_config")) {
		data->cfg_state.handystats_config = strdup(options.at<std::string>("handystats_config").c_str());
		if (!data->cfg_state.handystats_config)
			throw std::bad_alloc();
	}

	if (options.has("cache"))
		data->cache_config = ioremap::cache::cache_config::parse(options["cache"]);

	data->queue_timeout = parse_queue_timeout(options);
}

extern "C" struct dnet_node *dnet_parse_config(const char *file, int mon) {
	dnet_node *node = NULL;
	config_data *data = NULL;

	try {
		data = new(std::nothrow) config_data{file};
		if (!data)
			throw std::bad_alloc();

		const auto root = data->parse_config()->root();
		const auto logger = root["logger"];
		const auto options = root["options"];
		const auto backends = root["backends"];

		data->daemon_mode = options.at("daemon", false);
		if (data->daemon_mode && !mon)
			dnet_background();

		parse_logger(data, logger);
		parse_options(data, options);
		data->parse_backends(backends);

		if (data->daemon_mode && !mon)
			dnet_redirect_std_stream_to_dev_null();

		if (!data->cfg_addr_num)
			throw config_error("no local address specified, exiting");

		node = dnet_server_node_create(data);
		if (!node)
			throw std::runtime_error("failed to create node");

		static_assert(sizeof(dnet_addr) == sizeof(address),
		              "Size of dnet_addr and size of address must be equal");
		if (!data->remotes.empty()) {
			const int err = dnet_add_state(node, reinterpret_cast<const dnet_addr *>(data->remotes.data()),
			                               data->remotes.size(), 0);
			if (err < 0)
				DNET_LOG_WARNING(node->log, "Failed to connect to remote nodes: {}", err);
		}

		return node;

	} catch (const config_error &exc) {
		if (data && data->cfg_state.log) {
			DNET_LOG_ERROR(data->cfg_state.log, "cnf: failed to read config file '{}': {}", file,
			               exc.what());
		} else {
			fprintf(stderr, "cnf: failed to read config file '%s': %s\n", file, exc.what());
			fflush(stderr);
		}

	} catch (const std::exception &exc) {
		if (data && data->cfg_state.log) {
			DNET_LOG_ERROR(data->cfg_state.log, "cnf: {}", exc.what());
		} else {
			fprintf(stderr, "cnf: %s\n", exc.what());
			fflush(stderr);
		}
	}

	if (node) {
		dnet_server_node_destroy(node);
	} else if (data) {
		dnet_config_data_destroy(data);
	}

	return NULL;
}

extern "C" int dnet_node_reset_log(struct dnet_node *n) {
	if (!n || !n->config_data || dnet_need_exit(n))
		return -EINVAL;

	dnet_node_get_config_data(n)->reset_logger();
	return 0;
}

extern "C" int dnet_node_set_verbosity(struct dnet_node *node, enum dnet_log_level level) {
	if (level < 0 || level > DNET_LOG_ERROR)
		return -EINVAL;

	if (!node || !node->config_data || dnet_need_exit(node))
		return -EINVAL;

	dnet_node_get_config_data(node)->logger_level = level;
	node->io->backends_manager->set_verbosity(level);
	return 0;
}

static io_pool_config parse_io_pool_config(const config_data &data, const kora::config_t &config) {
	return {config.at("io_thread_num", data.cfg_state.io_thread_num),
	        config.at("nonblocking_io_thread_num", data.cfg_state.nonblocking_io_thread_num)};
}

static uint64_t parse_queue_timeout(const config_data &data, const kora::config_t &config) {
	return config.has("queue_timeout") ? config::parse_queue_timeout(config) : data.queue_timeout;
}

static dnet_config_backend &get_config_backend(const kora::config_t &config) {
	static const std::unordered_map<std::string, dnet_config_backend *> backends = {
	        {"blob", dnet_eblob_backend_info()}};

	auto it = backends.find(config.at<std::string>("type"));
	if (it == backends.end())
		throw ioremap::elliptics::config::config_error() << config["type"].path() << " is unknown backend";

	return *it->second;
}

static boost::optional<cache::cache_config> parse_cache_config(const config_data &data, const kora::config_t &config) {
	using cache::cache_config;
	return config.has("cache") ? cache_config::parse(config["cache"]) : data.cache_config;
}

backend_config::backend_config(const config_data &data, const kora::config_t &config)
: raw_config{kora::to_json(config.underlying_object())}
, backend_id{config.at<uint32_t>("backend_id")}
, group_id{config.at<uint32_t>("group")}
, history{config.at<std::string>("history")}
, enable_at_start{config.at<bool>("enable", true)}
, read_only_at_start{config.at<bool>("read_only", false)}
, pool_id{config.at<std::string>("pool_id", "")}
, pool_config(parse_io_pool_config(data, config))
, queue_timeout{parse_queue_timeout(data, config)}
, cache_config{parse_cache_config(data, config)}
, config_backend(get_config_backend(config))
, config_backend_buffer(config_backend.size, '\0') {
	config_backend.data = config_backend_buffer.data();
	int err = 0;
	for (int i = 0; i < config_backend.num; ++i) {
		const auto &entry = config_backend.ent[i];
		if (!config.has(entry.key))
			continue;

		const auto value = [&]() {
			std::ostringstream stream;
			stream << config[entry.key];
			return stream.str();
		}();

		if ((err = entry.callback(&config_backend, entry.key, value.data()))) {
			using attrs = blackhole::attribute_list;
			DNET_LOG_ERROR(data.logger, "Failed to parse entry: {}, value: {}: {}[{}]", entry.key, value,
			               strerror(-err), err,  attrs{{"backend_id", backend_id}});
		}
	}
}

config_data::config_data(std::string path)
: m_config_path(std::move(path)) {
	memset(static_cast<dnet_config_data *>(this), 0, sizeof(dnet_config_data));
	dnet_empty_time(&m_config_timestamp);
}

std::shared_ptr<kora::config_parser_t> config_data::parse_config() {
	struct stat st;
	memset(&st, 0, sizeof(st));
	if (stat(m_config_path.c_str(), &st) != 0) {
		const int err = -errno;
		throw config_error() << "failed to get stat of config file'" << m_config_path
		                     << "': " << strerror(-err);
	}

	dnet_time ts{/*tsec*/ (uint64_t)st.st_mtime, /*tnsec*/ 0};

	std::unique_lock<std::mutex> locker(m_parser_mutex);
	if (dnet_time_is_empty(&m_config_timestamp) || dnet_time_before(&m_config_timestamp, &ts)) {
		m_config_timestamp = ts;
		m_parser = std::make_shared<kora::config_parser_t>();
		m_parser->open(m_config_path);
		return m_parser;
	} else {
		return m_parser;
	}
}

void config_data::reset_logger() {
	DNET_LOG_INFO(logger, "resetting logger");
	*root_holder = make_logger(this, "core");
	if (access_holder)
		*access_holder = make_logger(this, "access");
	DNET_LOG_INFO(logger, "logger has been reset");
}

std::shared_ptr<backend_config> config_data::get_backend_config(uint32_t backend_id) {
	auto root = parse_config()->root();
	if (!root.has("backends"))
		return nullptr;

	const auto config = root["backends"];
	for (size_t index = 0; index < config.size(); ++index) {
		if (config[index].at<uint32_t>("backend_id") == backend_id)
			return std::make_shared<backend_config>(*this, config[index]);
	}

	return nullptr;
}

io_pool_config config_data::get_io_pool_config(const std::string &pool_id) {
	const io_pool_config default_config = {cfg_state.io_thread_num, cfg_state.nonblocking_io_thread_num};

	const auto &root = parse_config()->root();
	if (!root.has("options"))
		return default_config;

	const auto &options = root["options"];
	if (!options.has("io_pools"))
		return default_config;

	const auto &io_pools = options["io_pools"];
	if (!io_pools.has(pool_id))
		return default_config;

	return parse_io_pool_config(*this, io_pools[pool_id]);
}

void config_data::parse_backends(const kora::config_t &config) {
	std::unordered_set<uint32_t> backend_ids;
	backend_ids.reserve(config.size());
	backends.reserve(config.size());
	for (size_t index = 0; index < config.size(); ++index) {
		const auto &backend = config[index];
		const uint32_t backend_id = backend.at<uint32_t>("backend_id");

		// check backends' uniqueness
		if (!backend_ids.emplace(backend_id).second) {
			throw ioremap::elliptics::config::config_error() << backend["backend_id"].path()
			                                                 << " duplicates one of previous backend_id";
		}

		backends.emplace_back(std::make_shared<backend_config>(*this, backend));
	}
}

}}} // namespace ioremap::elliptics::config
