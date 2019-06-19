#pragma once

#include <atomic>

#include "library/n2_protocol.hpp"

struct n2_serialized {
	dnet_cmd cmd;

	// Typed message usually represented as some struct that references to allocated memory blocks. When we serialize,
	// we don't want to concat large blocks of data to one continuous memory block, since we don't want to copy memory.
	// Instead, we get serialized message as multi-chunk vector, each chunk ot that is a view of particular message part.
	// TODO: Assumed that sendfile'll be supported later, and n2_serialized became vector<some_variant>
	using chunks_t = std::vector<ioremap::elliptics::data_pointer>;
	chunks_t chunks;
};

namespace ioremap { namespace elliptics { namespace native {

// TODO: this function isn't related to serialization process, think about moving it to another module
int enqueue_net(dnet_net_state *st, std::unique_ptr<n2_serialized> serialized);

void serialize_lookup_response_body(dnet_node *n, const dnet_cmd &cmd, const n2_body &raw_body,
                                    n2_serialized::chunks_t &chunks);

template <class Message>
void serialize_new(const n2_body &raw_body, n2_serialized::chunks_t &chunks);

}}} // namespace ioremap::elliptics::native
