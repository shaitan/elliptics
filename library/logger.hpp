#pragma once

#include "elliptics/logger.hpp"

#ifdef __cplusplus
#include <atomic>
#include <blackhole/record.hpp>

namespace ioremap { namespace elliptics {

class wrapper_t: public dnet_logger {
public:
	wrapper_t(std::unique_ptr<dnet_logger> logger);

	virtual void log(blackhole::severity_t severity, const blackhole::message_t &message);
	virtual void log(blackhole::severity_t severity, const blackhole::message_t &message, blackhole::attribute_pack &pack);
	virtual void log(blackhole::severity_t severity, const blackhole::lazy_message_t &message, blackhole::attribute_pack &pack);

	blackhole::scope::manager_t &manager();

	virtual blackhole::attributes_t attributes() = 0;

	dnet_logger *inner_logger();
	dnet_logger *base_logger();
private:
	std::unique_ptr<dnet_logger> m_inner;
};

class trace_wrapper_t: public wrapper_t {
public:
	trace_wrapper_t(std::unique_ptr<dnet_logger> logger);
	virtual blackhole::attributes_t attributes();
};

class backend_wrapper_t: public wrapper_t {
public:
	backend_wrapper_t(std::unique_ptr<dnet_logger> logger);
	virtual blackhole::attributes_t attributes();
};

dnet_logger *get_base_logger(dnet_logger *logger);

bool log_filter(const blackhole::record_t &record, int level);

struct trace_scope {
	explicit trace_scope(uint64_t trace_id, bool trace_bit);
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

void dnet_node_set_trace_id(uint64_t trace_id, int trace_bit);
void dnet_node_unset_trace_id();

uint64_t dnet_node_get_trace_bit();

void dnet_node_set_backend_id(int backend_id);
void dnet_node_unset_backend_id();

#ifdef __cplusplus
} // extern "C"
#endif
