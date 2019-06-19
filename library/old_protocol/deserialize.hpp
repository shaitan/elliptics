#pragma once

#include <memory>

#include "library/n2_protocol.hpp"

namespace ioremap { namespace elliptics { namespace n2 {

int deserialize_lookup_request(dnet_net_state *st, const dnet_cmd &cmd,
                               std::unique_ptr<n2_request> &out_deserialized);
int deserialize_lookup_response(dnet_net_state *st, const dnet_cmd &cmd, data_pointer &&message_buffer,
                                std::unique_ptr<n2_message> &out_deserialized);
int deserialize_lookup_new_response(dnet_net_state *st, const dnet_cmd &cmd, data_pointer &&message_buffer,
                                    std::unique_ptr<n2_message> &out_deserialized);

}}} // namespace ioremap::elliptics::n2
