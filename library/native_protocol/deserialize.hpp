#pragma once

#include <memory>

#include "library/n2_protocol.hpp"

namespace ioremap { namespace elliptics { namespace n2 {

int deserialize_lookup_response_body(dnet_node *n, data_pointer &&message_buffer,
                                     std::shared_ptr<n2_body> &out_deserialized);

template <class Message>
int deserialize_new(dnet_node *n, data_pointer &&message_buffer, std::shared_ptr<n2_body> &out_deserialized);

}}} // namespace ioremap::elliptics::n2
