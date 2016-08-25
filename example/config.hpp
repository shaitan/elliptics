#ifndef CONFIG_HPP
#define CONFIG_HPP
#include <kora/config.hpp>

#include <blackhole/root.hpp>

#include "elliptics/session.hpp"


#include "library/logger.hpp"
#include "monitor/monitor.hpp"

namespace ioremap { namespace elliptics { namespace config {

class config_error : public std::exception
{
public:
	explicit config_error()
	{
	}

	config_error(const config_error &other) :
		m_message(other.m_message)
	{
		m_stream << m_message;
	}

	config_error &operator =(const config_error &other)
	{
		m_message = other.m_message;
		m_stream << m_message;
		return *this;
	}

	explicit config_error(const std::string &message)
	{
		m_stream << message;
		m_message = message;
	}

	const char *what() const ELLIPTICS_NOEXCEPT
	{
		return m_message.c_str();
	}

	template <typename T>
	config_error &operator <<(const T &value)
	{
		m_stream << value;
		m_message = m_stream.str();
		return *this;
	}

	config_error &operator <<(std::ostream &(*handler)(std::ostream &))
	{
		m_stream << handler;
		m_message = m_stream.str();
		return *this;
	}

	virtual ~config_error() throw()
	{}

private:
	std::stringstream m_stream;
	std::string m_message;
};

struct config_data : public dnet_config_data {
	config_data();

	std::shared_ptr<kora::config_parser_t> parse_config();

	void reset_logger();

	std::string					config_path;
	std::mutex					parser_mutex;
	std::shared_ptr<kora::config_parser_t>		parser;
	dnet_time					config_timestamp;
	dnet_backend_info_manager			backends_guard;
	std::string					logger_value;
	std::atomic<dnet_log_level>			logger_level;
	std::unique_ptr<blackhole::root_logger_t>	root_logger;
	std::unique_ptr<backend_wrapper_t>		logger;
	std::vector<address>				remotes;
	std::unique_ptr<cache::cache_config>		cache_config;
	std::unique_ptr<monitor::monitor_config>	monitor_config;
	uint64_t					queue_timeout;
};

std::shared_ptr<dnet_backend_info> dnet_parse_backend(config_data *data, uint32_t backend_id, const kora::config_t &backend);

} } } // namespace ioremap::elliptics::config

#endif // CONFIG_HPP
