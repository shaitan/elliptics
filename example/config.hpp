#pragma once

#include <mutex>
#include <vector>
#include <sstream>
#include <atomic>

#include <boost/optional/optional.hpp>

// TODO: replace by <blackhole/forward.hpp> but currently it leads to compile error
#include <blackhole/root.hpp>

#include "backends/backends.h"
#include "library/elliptics.h"

// forward declaration
namespace kora {
class config_t;
class config_parser_t;
}

namespace ioremap {
namespace elliptics {
class address;
class backend_wrapper_t;
}
namespace monitor {
struct monitor_config;
}}

namespace ioremap { namespace cache {
struct cache_config {
	size_t			size;
	size_t			count;
	unsigned		sync_timeout;
	std::vector<size_t>	pages_proportions;

	static cache_config parse(const kora::config_t &cache);
};
}} /* namespace ioremap::cache */

namespace ioremap { namespace elliptics { namespace config {

class config_error : public std::exception {
public:
	explicit config_error() {}

	config_error(const config_error &other)
	: m_message(other.m_message) {
		m_stream << m_message;
	}

	config_error &operator=(const config_error &other) {
		m_message = other.m_message;
		m_stream << m_message;
		return *this;
	}

	explicit config_error(const std::string &message) {
		m_stream << message;
		m_message = message;
	}

	const char *what() const noexcept {
		return m_message.c_str();
	}

	template <typename T>
	config_error &operator<<(const T &value) {
		m_stream << value;
		m_message = m_stream.str();
		return *this;
	}

	config_error &operator<<(std::ostream &(*handler)(std::ostream &)) {
		m_stream << handler;
		m_message = m_stream.str();
		return *this;
	}

	virtual ~config_error() throw() {}

private:
	std::ostringstream m_stream;
	std::string m_message;
};

struct io_pool_config {
	int io_thread_num;
	int nonblocking_io_thread_num;
};

struct config_data;
struct backend_config {
	backend_config(const config_data &data, const kora::config_t &config);
	backend_config(const backend_config &) = delete;
	backend_config &operator=(const backend_config &) = delete;

	// raw config as it presented in config file
	const std::string				raw_config;

	const uint32_t					backend_id;
	const uint32_t					group_id;
	// path to history directory where ids file is stored
	const std::string				history;

	// used only at node startup and means that the backend should be enabled at startup
	const bool					enable_at_start;
	// if true backend after enabling backend will be in read-only mode
	const bool					read_only_at_start;

	// io_pool options
	// id of shared io pool
	const std::string				pool_id;
	// configuration for individual io pool
	const io_pool_config				pool_config;

	// timeout used for dropping request stuck in a io pool's queue
	const uint64_t					queue_timeout;

	const boost::optional<cache::cache_config>	cache_config;

	dnet_config_backend				config_backend;

private:
	// buffer for backend-specific dnet_config_backend::data.
	std::vector<char>				config_backend_buffer;
};

struct config_data : public dnet_config_data {
	config_data(std::string path);

	std::shared_ptr<kora::config_parser_t> parse_config();

	// reset logger to reopen log file
	void reset_logger();

	// get actual backend's config with re-parsing config file if it was updated
	std::shared_ptr<backend_config> get_backend_config(uint32_t backend_id);

	// load all backends presented in @backends
	void parse_backends(const kora::config_t &backends);

	// get actual io pool's config with re-parsing config file if it was updated
	io_pool_config get_io_pool_config(const std::string &pool_id);

public:
	 // logger section of config file
	std::string					logger_value;
	std::atomic<dnet_log_level>			logger_level;
	// root logger is needed for re-opening log file
	std::unique_ptr<blackhole::root_logger_t>	root_logger;
	// common logger is used by default for all logs
	std::unique_ptr<backend_wrapper_t>		logger;
	// addresses of remote nodes
	std::vector<address>				remotes;
	boost::optional<cache::cache_config>		cache_config;
	// TODO: replace std::unique_ptr by std::optional or boost::optional
	std::unique_ptr<monitor::monitor_config>	monitor_config;
	// timeout used for dropping request stuck in a io pool's queue
	uint64_t					queue_timeout;

	bool						daemon_mode;

	bool						parallel_start;
	// initial backends' configs used only at startup to validate and run enabled backends
	std::vector<std::shared_ptr<backend_config>>	backends;

private:
	// path to config file
	const std::string				m_config_path;
	// timestamp of parsed config file
	dnet_time					m_config_timestamp;
	std::mutex					m_parser_mutex;
	std::shared_ptr<kora::config_parser_t>		m_parser;
};

}}} /* namespace ioremap::elliptics::config */

static inline ioremap::elliptics::config::config_data *dnet_node_get_config_data(struct dnet_node *node) {
	using ioremap::elliptics::config::config_data;
	return static_cast<config_data *>(node->config_data);
}
