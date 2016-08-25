#ifndef __IOREMAP_LOGGER_HPP
#define __IOREMAP_LOGGER_HPP

#ifdef __cplusplus
#include <blackhole/logger.hpp>
#include <blackhole/extensions/facade.hpp>
#include <memory>
typedef blackhole::logger_t dnet_logger;
extern "C" {
#else // __cplusplus
typedef struct cpp_ioremap_elliptics_logger dnet_logger;
#endif // __cplusplus

enum dnet_log_level {
	DNET_LOG_DEBUG = 0,
	DNET_LOG_NOTICE = 1,
	DNET_LOG_INFO = 2,
	DNET_LOG_WARNING = 3,
	DNET_LOG_ERROR = 4
};

enum dnet_log_level dnet_log_parse_level(const char *name);
const char* dnet_log_print_level(enum dnet_log_level level);

void dnet_log_raw(dnet_logger *logger, enum dnet_log_level level, const char *format, ...)
    __attribute__((format(printf, 3, 4)));

dnet_logger *dnet_node_get_logger(struct dnet_node *node);

#ifdef __cplusplus
} // extern "C"

namespace ioremap { namespace elliptics {
std::unique_ptr<dnet_logger> make_file_logger(const std::string &path, dnet_log_level level);

template<class T> inline auto logger_ref(T* const log) -> T& { return *log; }
template<class T> inline auto logger_ref(std::unique_ptr<T>& log) -> T& { return *log; }
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
#define DNET_LOG(node, ...)		DNET_LOG_RAW(dnet_node_get_logger(node), __VA_ARGS__)
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

#endif // __IOREMAP_LOGGER_HPP
