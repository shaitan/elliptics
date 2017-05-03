#pragma once

#include "elliptics/logger.hpp"

#ifdef __cplusplus
#include <atomic>
#include <blackhole/extensions/facade.hpp>

namespace ioremap { namespace elliptics {

class wrapper_t : public dnet_logger {
public:
	wrapper_t(std::unique_ptr<dnet_logger> logger);

	virtual void log(blackhole::severity_t severity, const blackhole::message_t &message);
	virtual void log(blackhole::severity_t severity,
	                 const blackhole::message_t &message,
	                 blackhole::attribute_pack &pack);
	virtual void log(blackhole::severity_t severity,
	                 const blackhole::lazy_message_t &message,
	                 blackhole::attribute_pack &pack);

	blackhole::scope::manager_t &manager();

	virtual blackhole::attributes_t attributes() = 0;

	dnet_logger *inner_logger();
	dnet_logger *base_logger();

private:
	std::unique_ptr<dnet_logger> m_inner;
};

class trace_wrapper_t : public wrapper_t {
public:
	trace_wrapper_t(std::unique_ptr<dnet_logger> logger);
	virtual blackhole::attributes_t attributes();
};

class pool_wrapper_t : public wrapper_t {
public:
	pool_wrapper_t(std::unique_ptr<dnet_logger> logger);
	virtual blackhole::attributes_t attributes();
};

class backend_wrapper_t : public wrapper_t {
public:
	backend_wrapper_t(std::unique_ptr<dnet_logger> logger);
	virtual blackhole::attributes_t attributes();
};

dnet_logger *get_base_logger(dnet_logger *logger);

bool log_filter(const int severity, const int level);

class session;
struct trace_scope {
	explicit trace_scope(uint64_t trace_id, bool trace_bit);
	explicit trace_scope(const session &s);
	~trace_scope();
};

struct backend_scope {
	explicit backend_scope(int backend_id);
	~backend_scope();
};

std::string to_hex_string(uint64_t value);
}} /* namespace ioremap::elliptics */

extern "C"{
#endif // __cplusplus

void dnet_logger_set_trace_id(uint64_t trace_id, int trace_bit);
void dnet_logger_unset_trace_id();

void dnet_logger_set_backend_id(int backend_id);
void dnet_logger_unset_backend_id();

void dnet_logger_set_pool_id(const char *pool_id);
void dnet_logger_unset_pool_id();

void dnet_log_raw(dnet_logger *logger, enum dnet_log_level level, const char *format, ...)
        __attribute__((format(printf, 3, 4)));

dnet_logger *dnet_node_get_logger(struct dnet_node *node);

#ifdef __cplusplus
} // extern "C"

namespace ioremap { namespace elliptics {

template<class T> inline auto logger_ref(T* const log) -> T& { return *log; }
template<class T> inline auto logger_ref(const std::unique_ptr<T>& log) -> T& { return *log; }
inline dnet_logger& logger_ref(struct dnet_node *node) { return *dnet_node_get_logger(node); }

template <class T> inline blackhole::logger_facade<dnet_logger> make_facade(T &&log) {
	return blackhole::logger_facade<dnet_logger>(logger_ref(log));
}

}} /* namespace ioremap::elliptics */

#define DNET_LOG(__log__, __severity__, ...) \
	ioremap::elliptics::make_facade(__log__).log(__severity__, __VA_ARGS__)

#define DNET_LOG_DEBUG(__log__, ...)	DNET_LOG(__log__, DNET_LOG_DEBUG, __VA_ARGS__)
#define DNET_LOG_NOTICE(__log__, ...)	DNET_LOG(__log__, DNET_LOG_NOTICE, __VA_ARGS__)
#define DNET_LOG_INFO(__log__, ...)	DNET_LOG(__log__, DNET_LOG_INFO, __VA_ARGS__)
#define DNET_LOG_WARNING(__log__, ...)	DNET_LOG(__log__, DNET_LOG_WARNING, __VA_ARGS__)
#define DNET_LOG_ERROR(__log__, ...)	DNET_LOG(__log__, DNET_LOG_ERROR, __VA_ARGS__)

#else
#define DNET_LOG_RAW(...)		dnet_log_raw(__VA_ARGS__)

#define DNET_LOG(__node__, __severity__, ...)								\
	do {												\
		if (dnet_logger_get_trace_bit() ||							\
		    (enum dnet_log_level)(__severity__) >= dnet_node_get_verbosity(__node__)) { 	\
			DNET_LOG_RAW(dnet_node_get_logger(__node__), __severity__, __VA_ARGS__);	\
		}											\
	} while (0)

#define dnet_log(...)			DNET_LOG(__VA_ARGS__)

#define DNET_LOG_DEBUG(log, ...)	DNET_LOG_RAW(log, DNET_LOG_DEBUG, __VA_ARGS__)
#define DNET_LOG_NOTICE(log, ...)	DNET_LOG_RAW(log, DNET_LOG_NOTICE, __VA_ARGS__)
#define DNET_LOG_INFO(log, ...)		DNET_LOG_RAW(log, DNET_LOG_INFO, __VA_ARGS__)
#define DNET_LOG_WARNING(log, ...)	DNET_LOG_RAW(log, DNET_LOG_WARNING, __VA_ARGS__)
#define DNET_LOG_ERROR(log, ...)	DNET_LOG_RAW(log, DNET_LOG_ERROR, __VA_ARGS__)

#define DNET_DEBUG(n, ...)	DNET_LOG(n, DNET_LOG_DEBUG, __VA_ARGS__)
#define DNET_NOTICE(n, ...)	DNET_LOG(n, DNET_LOG_NOTICE, __VA_ARGS__)
#define DNET_INFO(n, ...)	DNET_LOG(n, DNET_LOG_INFO, __VA_ARGS__)
#define DNET_WARNING(n, ...)	DNET_LOG(n, DNET_LOG_WARNING, __VA_ARGS__)
#define DNET_ERROR(n, ...)	DNET_LOG(n, DNET_LOG_ERROR, __VA_ARGS__)
#endif
