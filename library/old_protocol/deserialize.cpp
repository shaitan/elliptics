#include "deserialize.hpp"

#include <blackhole/attribute.hpp>
#include <chrono>
#include <msgpack.hpp>

#include "library/common.hpp"
#include "library/elliptics.h"

namespace msgpack {

using namespace ioremap::elliptics;

inline dnet_time &operator >>(msgpack::object o, dnet_time &v) {
	if (o.type != msgpack::type::ARRAY || o.via.array.size != 2) {
		throw msgpack::type_error();
	}

	object *p = o.via.array.ptr;
	p[0].convert(&v.tsec);
	p[1].convert(&v.tnsec);
	return v;
}

inline n2::lookup_response &operator >>(msgpack::object o, n2::lookup_response &v) {
	if (o.type != msgpack::type::ARRAY || o.via.array.size < 10)
		throw msgpack::type_error();

	object *p = o.via.array.ptr;
	p[0].convert(&v.record_flags);
	p[1].convert(&v.user_flags);
	p[2].convert(&v.path);

	p[3].convert(&v.json_timestamp);
	p[4].convert(&v.json_offset);
	p[5].convert(&v.json_size);
	p[6].convert(&v.json_capacity);

	p[7].convert(&v.data_timestamp);
	p[8].convert(&v.data_offset);
	p[9].convert(&v.data_size);

	if (o.via.array.size > 11) {
		p[10].convert(&v.json_checksum);
		p[11].convert(&v.data_checksum);

		if ((!v.json_checksum.empty() && v.json_checksum.size() != DNET_CSUM_SIZE) ||
		    (!v.data_checksum.empty() && v.data_checksum.size() != DNET_CSUM_SIZE)) {
			throw std::runtime_error("Unexpected checksum size");
		}
	}

	return v;
}

inline n2::remove_request &operator >>(msgpack::object o, n2::remove_request &v) {
	if (o.type != msgpack::type::ARRAY || o.via.array.size < 2)
		throw msgpack::type_error();

	object *p = o.via.array.ptr;
	p[0].convert(&v.ioflags);
	p[1].convert(&v.timestamp);

	return v;
}

} // namespace msgpack

namespace ioremap { namespace elliptics { namespace n2 {

template<typename T>
int unpack(dnet_node *n, const data_pointer &data, T &value, size_t &length_of_packed) {
	try {
		length_of_packed = 0;

		msgpack::unpacked msg;
		msgpack::unpack(&msg, data.data<char>(), data.size(), &length_of_packed);
		msg.get().convert(&value);
		return 0;

	} catch (const std::exception &e) {
		DNET_LOG_ERROR(n, "Failed to unpack msgpack message header: {}", e.what());
		return -EINVAL;
	}
}

int deserialize_lookup_response_body(dnet_node *n, data_pointer &&message_buffer,
                                     std::shared_ptr<n2_body> &out_deserialized) {
	auto body = std::make_shared<lookup_response>();

	try {
		auto file_info = message_buffer
			.skip<struct dnet_addr>()
			.data<struct dnet_file_info>();
		body->path = message_buffer
			.skip<struct dnet_addr>()
			.skip<struct dnet_file_info>()
			.data<char>();
		body->data_offset = file_info->offset;
		body->data_size = file_info->size;
		body->data_timestamp = file_info->mtime;
		body->data_checksum = {file_info->checksum, file_info->checksum + DNET_CSUM_SIZE};
		body->record_flags = file_info->record_flags;
	} catch (const std::exception &e) {
		DNET_LOG_ERROR(n, "Failed to deserialize lookup_response: {}", e.what());
		return -EINVAL;
	}

	out_deserialized = std::move(body);
	return 0;
}

template <class Message>
int deserialize_new(dnet_node *n, data_pointer &&message_buffer, std::shared_ptr<n2_body> &out_deserialized) {
	auto body = std::make_shared<Message>();

	size_t unused_length_of_packed;
	int err = unpack(n, message_buffer, *body, unused_length_of_packed);
	if (err)
		return err;

	out_deserialized = std::move(body);
	return 0;
}

template int deserialize_new<lookup_response>(dnet_node *, data_pointer &&, std::shared_ptr<n2_body> &);
template int deserialize_new<remove_request>(dnet_node *, data_pointer &&, std::shared_ptr<n2_body> &);

}}} // namespace ioremap::elliptics::n2
