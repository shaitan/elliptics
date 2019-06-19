#pragma once

#include <unordered_map>
#include <unordered_set>

#include "library/n2_protocol.hpp"
#include "repliers.hpp"

namespace ioremap { namespace elliptics { namespace n2 {

class old_protocol : public protocol_interface {
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
};

}}} // namespace ioremap::elliptics::n2

extern "C" {

struct n2_old_protocol_io {
	ioremap::elliptics::n2::old_protocol protocol;
};

struct n2_recv_buffer {
	ioremap::elliptics::data_pointer buf;
};

} // extern "C"
