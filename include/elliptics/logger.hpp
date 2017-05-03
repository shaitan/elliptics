#pragma once

enum dnet_log_level {
	DNET_LOG_DEBUG = 0,
	DNET_LOG_NOTICE = 1,
	DNET_LOG_INFO = 2,
	DNET_LOG_WARNING = 3,
	DNET_LOG_ERROR = 4
};

#ifdef __cplusplus

#include <blackhole/logger.hpp>
#include <memory>
typedef blackhole::logger_t dnet_logger;

namespace ioremap { namespace elliptics {
std::unique_ptr<dnet_logger> make_file_logger(const std::string &path, dnet_log_level level);
}} /* namespace ioremap::elliptics */

extern "C" {

#else // __cplusplus
typedef struct cpp_ioremap_elliptics_logger dnet_logger;
#endif // __cplusplus

enum dnet_log_level dnet_log_parse_level(const char *name);
const char* dnet_log_print_level(enum dnet_log_level level);

uint64_t dnet_logger_get_trace_bit();

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus
