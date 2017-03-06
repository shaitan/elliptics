#include "library/logger.hpp"

#include <stack>
#include <stdarg.h>
#include <iomanip>

#include <blackhole/attribute.hpp>
#include <blackhole/builder.hpp>
#include <blackhole/extensions/writer.hpp>
#include <blackhole/formatter/string.hpp>
#include <blackhole/handler/blocking.hpp>
#include <blackhole/logger.hpp>
#include <blackhole/record.hpp>
#include <blackhole/root.hpp>
#include <blackhole/sink/file.hpp>

#include "example/config.hpp"

namespace ioremap { namespace elliptics {
namespace attributes {
struct trace {
public:
	trace(uint64_t id, bool bit)
	: m_id(id)
	, m_bit(bit) {}

	static uint64_t id() {
		return stack().top().m_id;
	}

	static bool bit() {
		return stack().top().m_bit;
	}

	static void pop() {
		if (stack().size() > 1)
			stack().pop();
	}

	static void push(uint64_t id, bool bit) {
		stack().emplace(id, bit);
	}

private:
	uint64_t m_id;
	bool m_bit;

	static std::stack<trace> &stack() {
		static thread_local std::stack<trace> _stack{std::deque<trace>{{0, false}}};
		return _stack;
	}
};

namespace pool {
	static std::string &id() {
		static thread_local std::string id;
		return id;
	}
} /* namespace pool */

namespace backend {
	static ssize_t &id() {
		static thread_local ssize_t id{-1};
		return id;
	}
} /* namespace backend */

} /* namespace attributes */

bool log_filter(const blackhole::record_t &record, int level) {
	return attributes::trace::bit() || record.severity() >= level;
}

std::unique_ptr<dnet_logger> make_file_logger(const std::string &path, dnet_log_level level) {
	static const std::string pattern =
	        "{timestamp:l} {trace_id:{0:default}0>16}/{thread:d}/{process} {severity}: {message}, attrs: [{...}]";

	static auto sevmap = [](std::size_t severity, const std::string &spec, blackhole::writer_t &writer) {
		static const std::array<const char *, 5> mapping = {{"DEBUG", "NOTICE", "INFO", "WARNING", "ERROR"}};
		if (severity < mapping.size()) {
			writer.write(spec, mapping[severity]);
		} else {
			writer.write(spec, severity);
		}
	};

	std::vector<std::unique_ptr<blackhole::handler_t>> handlers;
	handlers.push_back(
		blackhole::builder<blackhole::handler::blocking_t>()
			.set(blackhole::builder<blackhole::formatter::string_t>(pattern)
				.mapping(sevmap)
				.build())
			.add(blackhole::builder<blackhole::sink::file_t>(path)
				.flush_every(1)
				.build())
			.build()
	);

	std::unique_ptr<blackhole::root_logger_t> logger(new blackhole::root_logger_t(std::move(handlers)));

	logger->filter([level](const blackhole::record_t &record) {
		return log_filter(record, level);
	});

	return std::move(logger);
}

std::string to_hex_string(uint64_t value) {
	std::ostringstream stream;
	stream << std::setfill('0') << std::setw(16) << std::hex << value;
	return stream.str();
}

trace_scope::trace_scope(uint64_t trace_id, bool trace_bit) {
	dnet_logger_set_trace_id(trace_id, trace_bit);
}

trace_scope::~trace_scope() {
	dnet_logger_unset_trace_id();
}

backend_scope::backend_scope(int backend_id) {
	dnet_logger_set_backend_id(backend_id);
}

backend_scope::~backend_scope() {
	dnet_logger_unset_backend_id();
}

static blackhole::attribute_list make_view(const blackhole::attributes_t &attributes) {
	blackhole::attribute_list attr_list;
	for (const auto &attribute : attributes) {
		attr_list.emplace_back(attribute);
	}
	return attr_list;
}

wrapper_t::wrapper_t(std::unique_ptr<dnet_logger> logger)
: m_inner(std::move(logger)) {}

void wrapper_t::log(blackhole::severity_t severity, const blackhole::message_t &message) {
	blackhole::attribute_pack pack;
	auto attr = attributes();
	auto attr_list = make_view(attr);
	pack.push_back(attr_list);
	log(severity, message, pack);
}

void wrapper_t::log(blackhole::severity_t severity,
                    const blackhole::message_t &message,
                    blackhole::attribute_pack &pack) {
	auto attr = attributes();
	auto attr_list = make_view(attr);
	pack.push_back(attr_list);
	m_inner->log(severity, message, pack);
}

void wrapper_t::log(blackhole::severity_t severity,
                    const blackhole::lazy_message_t &message,
                    blackhole::attribute_pack &pack) {
	auto attr = attributes();
	auto attr_list = make_view(attr);
	pack.push_back(attr_list);
	m_inner->log(severity, message, pack);
}

blackhole::scope::manager_t &wrapper_t::manager() {
	return m_inner->manager();
}

dnet_logger *wrapper_t::inner_logger() {
	return m_inner.get();
}

dnet_logger *wrapper_t::base_logger() {
	auto wrapper = dynamic_cast<wrapper_t *>(inner_logger());
	if (wrapper)
		return wrapper->base_logger();

	return inner_logger();
}

trace_wrapper_t::trace_wrapper_t(std::unique_ptr<dnet_logger> logger)
: wrapper_t{std::move(logger)} {}

blackhole::attributes_t trace_wrapper_t::attributes() {
	// should be replaced by plain trace::id() when blackhole gets mapping
	// and cocaine start to specify trace_id as uint64_t
	return attributes::trace::id() ? blackhole::attributes_t{{"trace_id", to_hex_string(attributes::trace::id())}}
	                               : blackhole::attributes_t{};
}

pool_wrapper_t::pool_wrapper_t(std::unique_ptr<dnet_logger> logger)
: wrapper_t{std::move(logger)} {}

blackhole::attributes_t pool_wrapper_t::attributes() {
	return !attributes::pool::id().empty() ? blackhole::attributes_t{{"pool", attributes::pool::id()}}
	                                       : blackhole::attributes_t{};
}

backend_wrapper_t::backend_wrapper_t(std::unique_ptr<dnet_logger> logger)
: wrapper_t{std::move(logger)} {}

blackhole::attributes_t backend_wrapper_t::attributes() {
	return (attributes::backend::id() != -1) ? blackhole::attributes_t{{"backend_id", attributes::backend::id()}}
	                                         : blackhole::attributes_t{};
}

dnet_logger *get_base_logger(dnet_logger *logger) {
	auto wrapper = dynamic_cast<wrapper_t *>(logger);
	if (wrapper)
		return wrapper->base_logger();
	return logger;
}

}} /* namespace ioremap::elliptics */

void dnet_logger_set_trace_id(uint64_t trace_id, int trace_bit) {
	ioremap::elliptics::attributes::trace::push(trace_id, !!trace_bit);
}

void dnet_logger_unset_trace_id() {
	ioremap::elliptics::attributes::trace::pop();
}

uint64_t dnet_logger_get_trace_bit() {
	return ioremap::elliptics::attributes::trace::bit() ? (1ll << 63) : 0;
}

void dnet_logger_set_backend_id(int backend_id) {
	ioremap::elliptics::attributes::backend::id() = backend_id;
}

void dnet_logger_unset_backend_id() {
	ioremap::elliptics::attributes::backend::id() = -1;
}

void dnet_logger_set_pool_id(const char *pool_id) {
	ioremap::elliptics::attributes::pool::id() = pool_id;
}

void dnet_logger_unset_pool_id() {
	ioremap::elliptics::attributes::pool::id().clear();
}

dnet_logger *dnet_node_get_logger(struct dnet_node* node) {
	return node->log;
}

enum dnet_log_level dnet_node_get_verbosity(struct dnet_node *n) {
	if (!n || !n->config_data)
		return DNET_LOG_DEBUG;

	return dnet_node_get_config_data(n)->logger_level;
}

static const std::array<std::string, 5> severity_names = {{"debug", "notice", "info", "warning", "error"}};

enum dnet_log_level dnet_log_parse_level(const char *name) {
	auto it = std::find(severity_names.begin(), severity_names.end(), name);
	if (it == severity_names.end())
		throw std::logic_error(std::string{"Unknown log level: "} + name);

	return static_cast<dnet_log_level>(it - severity_names.begin());
}

const char* dnet_log_print_level(enum dnet_log_level level) {
	if (level > severity_names.size())
		throw std::logic_error(std::string{"Unknown log level: "} + std::to_string(level));

	return severity_names[level].c_str();
}

void dnet_log_raw(dnet_logger *logger, dnet_log_level level, const char *format, ...) {
	if (!logger)
		return;

	char buffer[2048];

	va_list args;
	va_start(args, format);

	/* This lambda will be called by logger after filtering
	 * NB! it is promised that this lambda will be called from this thread
	 */
	auto lazy_format = [&]() -> blackhole::string_view {
		vsnprintf(buffer, sizeof(buffer), format, args);
		size_t length = strlen(buffer);
		while (length && buffer[length - 1] == '\n') {
			--length;
		}
		buffer[length] = '\0';
		return {buffer, length};
	};

	blackhole::lazy_message_t lazy_message{std::string() /* empty pattern */,
	                                       lazy_format /* supplier */};
	blackhole::attribute_pack empty_pack;

	logger->log(level, lazy_message, empty_pack);

	va_end(args);
}
