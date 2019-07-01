#pragma once

#include "elliptics/interface.h"
#include "elliptics/utils.hpp"

// Base class for message bodies. For different message types bodies have almost nothing in common, so base class is
// a bit degenerated. But we don't use void * instead, because we want:
// * to guarantee safe destruction;
// * to have visible type hierarchy.
struct n2_body {
	virtual ~n2_body() = default;
};

// Base class for requests
struct n2_request {
	// Adopted for broadcast sending: for each send cmd is modified, but body is constant.
	dnet_cmd cmd;
	dnet_time deadline;
	std::shared_ptr<n2_body> body;

	n2_request(const dnet_cmd &cmd, const dnet_time &deadline);

	n2_request(const dnet_cmd &cmd, const dnet_time &deadline, std::shared_ptr<n2_body> body);
};

// Group of ways to reply on request. Some of replies can be unimplemented, depending on handler.
// n2_repliers::on_reply_error is always implemented. Any replier returns error code. When client side
// implements its replier, its error code is ignored.
struct n2_repliers {
	// Here refcounting isn't required, but shared_ptr is used for dynamic destruction and for compatibility
	// with binding to std::function (bound parameter must be copyable).
	std::function<int (const std::shared_ptr<n2_body> &/*body*/, bool /*last*/)> on_reply;

	std::function<int (int /*err*/, bool /*last*/)> on_reply_error;

	// Helpers
	inline int on_last_reply(const std::shared_ptr<n2_body> &body) const {
		return on_reply(body, true);
	}

	inline int on_next_reply(const std::shared_ptr<n2_body> &body) const {
		return on_reply(body, false);
	}

	inline int on_ack(bool last) const {
		return on_reply(nullptr, last);
	}

	inline int on_last_ack() const {
		return on_ack(true);
	}

	inline int on_next_ack() const {
		return on_ack(false);
	}

	inline int on_last_error(int err) const {
		return on_reply_error(err, true);
	}

	inline int on_next_error(int err) const {
		return on_reply_error(err, false);
	}

	// TODO: add streaming repliers
};

struct n2_request_info {
	n2_request request;
	n2_repliers repliers;
};

struct n2_response_info {
	// Saved cmd copy (for logging, etc)
	// TODO(sabramkin): Don't hold cmd. Use accessors for the required info.
	// TODO: or, maybe use here shared_ptr<dnet_cmd> cmd, which is carried by response_holder too
	dnet_cmd cmd;

	std::function<int ()> response_holder;

	n2_response_info() = default;
	n2_response_info(const dnet_cmd &cmd, std::function<int ()> &&response_holder);
};

namespace ioremap { namespace elliptics { namespace n2 {

// Abstract interface of protocol
class protocol_interface {
public:
	// Must be implemented on server side
	static int __attribute__((weak)) on_request(dnet_net_state *st, std::unique_ptr<n2_request_info> request_info);

	// Client side
	virtual int send_request(dnet_net_state *st,
	                         const n2_request &request,
	                         n2_repliers &&repliers) = 0;

	virtual ~protocol_interface() = default;
};

// Get connection's protocol
protocol_interface *net_state_get_protocol(dnet_net_state* st);

dnet_time default_deadline();

struct lookup_response : n2_body {
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

	// constructor used by deserializer
	lookup_response();

	// constructor used by handler
	lookup_response(uint64_t record_flags,
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

struct remove_request : n2_body {
	uint64_t ioflags;
	dnet_time timestamp;

	remove_request();

	remove_request(uint64_t ioflags,
	               dnet_time timestamp);
};

}}} // namespace ioremap::elliptics::n2
