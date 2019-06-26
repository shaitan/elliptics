#pragma once

#include <unordered_map>
#include <unordered_set>

#include "library/n2_protocol.hpp"
#include "repliers.hpp"

namespace ioremap { namespace elliptics { namespace native {

class protocol : public n2::protocol_interface {
public:
	// Client side
	int send_request(dnet_net_state *st,
	                 const n2_request &request,
	                 n2_repliers &&repliers) override;

	// Net side
	int recv_message(dnet_net_state *st, const dnet_cmd &cmd, data_pointer &&body);

private:
	int recv_request(dnet_net_state *st, const dnet_cmd &cmd, data_pointer &&body);
	int recv_response(dnet_net_state *st, const dnet_cmd &cmd, data_pointer &&body);

	int translate_lookup_request(dnet_net_state *st, const dnet_cmd &cmd);
	int translate_lookup_new_request(dnet_net_state *st, const dnet_cmd &cmd);
	int translate_remove_new_request(dnet_net_state *st, const dnet_cmd &cmd, data_pointer &&body);

	template <class Replier>
	int translate_request(dnet_net_state *st, const dnet_cmd &cmd, std::shared_ptr<n2_body> body) {
		auto replier = std::make_shared<Replier>(st, cmd);

		std::unique_ptr<n2_request_info> request_info(
			new n2_request_info{n2_request(cmd, n2::default_deadline(), std::move(body)), n2_repliers()});

		request_info->repliers.on_reply = std::bind(&Replier::reply,
		                                            replier,
		                                            std::placeholders::_1);
		request_info->repliers.on_reply_error = std::bind(&Replier::reply_error,
		                                                  replier,
		                                                  std::placeholders::_1);
		return on_request(st, std::move(request_info));
	}

};

}}} // namespace ioremap::elliptics::native

extern "C" {

struct n2_native_protocol_io {
	ioremap::elliptics::native::protocol protocol;
};

struct n2_recv_buffer {
	ioremap::elliptics::data_pointer buf;
};

} // extern "C"
