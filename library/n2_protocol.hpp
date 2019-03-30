#pragma once

#include "elliptics/interface.h"
#include "elliptics/utils.hpp"

// Base class for requests and responses
struct n2_message {
	dnet_cmd cmd;
	
	explicit n2_message(const dnet_cmd &cmd);
	virtual ~n2_message() = default;
};

// Base class for requests. Responses are inherited directly from n2_message.
struct n2_request : n2_message {
	dnet_time deadline;
	
	n2_request(const dnet_cmd &cmd, const dnet_time &deadline);
};

// Group of ways to reply on request. Some of replies can be unimplemented, depending on handler.
// n2_repliers::on_reply_error is always implemented. Any replier returns error code. When client side
// implements its replier, its error code is ignored.
struct n2_repliers {
	std::function<int (std::unique_ptr<n2_message>)> on_reply;
	std::function<int (int)> on_reply_error;
	// TODO: add streaming repliers
};

struct n2_request_info {
	// Saved cmd copy. Reason: cmd info must be accessible beyond the lifetime of n2_request_info::request
	// TODO(sabramkin): Don't hold cmd. If command handler needs to save some info from cmd, it must do it itself.
	// TODO: or, maybe use here shared_ptr<dnet_cmd> cmd, which is carried by n2_request too
	dnet_cmd cmd;

	std::unique_ptr<n2_request> request;
	n2_repliers repliers;
};

struct n2_response_info {
	// Saved cmd copy (for logging, etc)
	// TODO(sabramkin): Don't hold cmd. Use accessors for the required info.
	// TODO: or, maybe use here shared_ptr<dnet_cmd> cmd, which is carried by response_holder too
	dnet_cmd cmd;

	std::function<int ()> response_holder;
};

namespace ioremap { namespace elliptics { namespace n2 {

// Abstract interface of protocol
class protocol_interface {
public:
	// Must be implemented on server side
	static int __attribute__((weak)) on_request(dnet_net_state *st, std::unique_ptr<n2_request_info> request_info);

	// Client side
	virtual int send_request(dnet_net_state *st,
	                         std::unique_ptr<n2_request> request,
	                         n2_repliers repliers) = 0;

	virtual ~protocol_interface() = default;
};

// Get connection's protocol
protocol_interface *net_state_get_protocol(dnet_net_state* st);

struct lookup_request : n2_request {
	explicit lookup_request(const dnet_cmd &cmd);
};

struct lookup_response : n2_message {
	uint64_t record_flags;
	uint64_t user_flags;
	std::string path;

	dnet_time json_timestamp;
	uint64_t json_offset;
	uint64_t json_size;
	uint64_t json_capacity;
	std::vector<unsigned char> json_checksum;

	dnet_time data_timestamp;
	uint64_t data_offset;
	uint64_t data_size;
	std::vector<unsigned char> data_checksum;

	// constructor used by deserializer, which fills the other fields manually
	explicit lookup_response(const dnet_cmd &cmd);

	// constructor used by handler
	lookup_response(const dnet_cmd &cmd,
	                uint64_t record_flags,
	                uint64_t user_flags,
	                std::string path,
	                dnet_time json_timestamp,
	                uint64_t json_offset,
	                uint64_t json_size,
	                uint64_t json_capacity,
	                std::vector<unsigned char> json_checksum,
	                dnet_time data_timestamp,
	                uint64_t data_offset,
	                uint64_t data_size,
	                std::vector<unsigned char> data_checksum);
};

}}} // namespace ioremap::elliptics::n2
