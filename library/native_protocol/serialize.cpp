#include "serialize.hpp"

#include <blackhole/attribute.hpp>
#include <msgpack.hpp>

#include "library/common.hpp"
#include "library/elliptics.h"

namespace msgpack {

using namespace ioremap::elliptics;

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const dnet_time &v) {
	o.pack_array(2);
	o.pack_fix_uint64(v.tsec);
	o.pack_fix_uint64(v.tnsec);
	return o;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator<<(msgpack::packer<Stream> &o, const n2::lookup_response &v) {
	o.pack_array(12);

	o.pack(v.record_flags);
	o.pack(v.user_flags);
	o.pack(v.path);

	o.pack(v.json_timestamp);
	o.pack(v.json_offset);
	o.pack(v.json_size);
	o.pack(v.json_capacity);

	o.pack(v.data_timestamp);
	o.pack(v.data_offset);
	o.pack(v.data_size);

	o.pack(v.json_checksum);
	o.pack(v.data_checksum);

	return o;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator<<(msgpack::packer<Stream> &o, const n2::remove_request &v) {
	o.pack_array(2);
	o.pack(v.ioflags);
	o.pack(v.timestamp);

	return o;
}

} // namespace msgpack

namespace ioremap { namespace elliptics { namespace native {

using namespace ioremap::elliptics::n2;

int enqueue_net(dnet_net_state *st, std::unique_ptr<n2_serialized> serialized) {
	auto r = static_cast<dnet_io_req *>(calloc(1, sizeof(dnet_io_req)));
	if (!r)
		return -ENOMEM;

	r->serialized = serialized.release();
	dnet_io_req_enqueue_net(st, r);
	return 0;
}

void serialize_lookup_response_body(dnet_node *n, const dnet_cmd &cmd, const n2_body &raw_body,
                                    n2_serialized::chunks_t &chunks) {
	const auto &body = static_cast<const lookup_response &>(raw_body);

	auto path_size = body.path.size() + 1;  // including 0-byte
	auto data = data_pointer::allocate(sizeof(struct dnet_addr) +
					   sizeof(struct dnet_file_info) +
					   path_size);

	auto addr = data
		.data<dnet_addr>();
	memcpy(addr, &n->addrs[0], sizeof(struct dnet_addr));
	dnet_convert_addr(addr);

	auto file_info = data
		.skip<dnet_addr>()
		.data<dnet_file_info>();
	file_info->flen = path_size;
	file_info->record_flags = body.record_flags;
	file_info->size = body.data_size;
	file_info->offset = body.data_offset;
	file_info->mtime = body.data_timestamp;
	if (cmd.flags & DNET_FLAGS_CHECKSUM) {
		memcpy(file_info->checksum, body.data_checksum.data(), DNET_CSUM_SIZE);
	}
	dnet_convert_file_info(file_info);

	auto path = data
		.skip<dnet_addr>()
		.skip<dnet_file_info>()
		.data<char>();
	memcpy(path, body.path.c_str(), path_size);

	chunks.emplace_back(std::move(data));
}

template <class Message>
void serialize_new(const n2_body &raw_body, n2_serialized::chunks_t &chunks) {
	const auto &body = static_cast<const Message &>(raw_body);

	msgpack::sbuffer msgpack_buffer;
	msgpack::pack(msgpack_buffer, body);
	chunks.emplace_back(data_pointer::copy(msgpack_buffer.data(), msgpack_buffer.size()));
}

template void serialize_new<lookup_response>(const n2_body &, n2_serialized::chunks_t &);
template void serialize_new<remove_request>(const n2_body &, n2_serialized::chunks_t &);

}}} // namespace ioremap::elliptics::native
