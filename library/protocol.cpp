#include "protocol.hpp"

#include <msgpack.hpp>

#include "rapidjson/document.h"

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

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const dnet_time &v) {
	o.pack_array(2);
	o.pack_fix_uint64(v.tsec);
	o.pack_fix_uint64(v.tnsec);
	return o;
}

inline dnet_read_request &operator >>(msgpack::object o, dnet_read_request &v) {
	if (o.type != msgpack::type::ARRAY || o.via.array.size < 4) {
		throw msgpack::type_error();
	}

	object *p = o.via.array.ptr;
	p[0].convert(&v.ioflags);
	p[1].convert(&v.read_flags);
	p[2].convert(&v.data_offset);
	p[3].convert(&v.data_size);

	if (o.via.array.size > 4) {
		p[4].convert(&v.deadline);
	} else {
		// for older protocol
		dnet_empty_time(&v.deadline);
	}

	return v;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const dnet_read_request &v) {
	o.pack_array(5);
	o.pack(v.ioflags);
	o.pack(v.read_flags);
	o.pack(v.data_offset);
	o.pack(v.data_size);
	o.pack(v.deadline);

	return o;
}

inline dnet_read_response &operator >>(msgpack::object o, dnet_read_response &v) {
	if (o.type != msgpack::type::ARRAY || o.via.array.size < 10) {
		throw msgpack::type_error();
	}

	object *p = o.via.array.ptr;
	p[0].convert(&v.record_flags);
	p[1].convert(&v.user_flags);

	p[2].convert(&v.json_timestamp);
	p[3].convert(&v.json_size);
	p[4].convert(&v.json_capacity);
	p[5].convert(&v.read_json_size);

	p[6].convert(&v.data_timestamp);
	p[7].convert(&v.data_size);
	p[8].convert(&v.read_data_offset);
	p[9].convert(&v.read_data_size);

	return v;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const dnet_read_response &v) {
	o.pack_array(10);
	o.pack(v.record_flags);
	o.pack(v.user_flags);

	o.pack(v.json_timestamp);
	o.pack(v.json_size);
	o.pack(v.json_capacity);
	o.pack(v.read_json_size);

	o.pack(v.data_timestamp);
	o.pack(v.data_size);
	o.pack(v.read_data_offset);
	o.pack(v.read_data_size);

	return o;
}

inline dnet_write_request &operator >>(msgpack::object o, dnet_write_request &v) {
	if (o.type != msgpack::type::ARRAY || o.via.array.size < 9)
		throw msgpack::type_error();

	object *p = o.via.array.ptr;
	p[0].convert(&v.ioflags);

	p[1].convert(&v.user_flags);

	p[2].convert(&v.timestamp);

	p[3].convert(&v.json_size);
	p[4].convert(&v.json_capacity);

	p[5].convert(&v.data_offset);
	p[6].convert(&v.data_size);
	p[7].convert(&v.data_capacity);
	p[8].convert(&v.data_commit_size);

	if (o.via.array.size > 9) {
		p[9].convert(&v.json_timestamp);
	} else {
		// older protocol: take json timestamp from data timestamp
		p[2].convert(&v.json_timestamp);
	}

	if (o.via.array.size > 10) {
		p[10].convert(&v.cache_lifetime);
	} else {
		// older protocol
		v.cache_lifetime = 0;
	}

	if (o.via.array.size > 11) {
		p[11].convert(&v.deadline);
	} else {
		// for older protocol
		dnet_empty_time(&v.deadline);
	}

	return v;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const dnet_write_request &v) {
	o.pack_array(12);
	o.pack(v.ioflags);
	o.pack(v.user_flags);

	o.pack(v.timestamp);

	o.pack(v.json_size);
	o.pack(v.json_capacity);

	o.pack(v.data_offset);
	o.pack(v.data_size);
	o.pack(v.data_capacity);
	o.pack(v.data_commit_size);

	o.pack(v.json_timestamp);

	o.pack(v.cache_lifetime);

	o.pack(v.deadline);

	return o;
}

inline dnet_lookup_response &operator >>(msgpack::object o, dnet_lookup_response &v) {
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

	return v;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const dnet_lookup_response &v) {
	o.pack_array(10);
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

	return o;
}

inline dnet_remove_request &operator >>(msgpack::object o, dnet_remove_request &v) {
	if (o.type != msgpack::type::ARRAY || o.via.array.size < 2)
		throw msgpack::type_error();

	object *p = o.via.array.ptr;
	p[0].convert(&v.ioflags);
	p[1].convert(&v.timestamp);

	return v;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const dnet_remove_request &v) {
	o.pack_array(2);
	o.pack(v.ioflags);
	o.pack(v.timestamp);

	return o;
}

inline dnet_json_header &operator >>(msgpack::object o, dnet_json_header &v) {
	if (o.type != msgpack::type::ARRAY || o.via.array.size < 3)
		throw msgpack::type_error();

	object *p = o.via.array.ptr;
	p[0].convert(&v.size);
	p[1].convert(&v.capacity);
	p[2].convert(&v.timestamp);

	return v;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const dnet_json_header &v) {
	o.pack_array(3);
	o.pack_fix_uint64(v.size);
	o.pack_fix_uint64(v.capacity);
	o.pack(v.timestamp);

	return o;
}

inline dnet_raw_id &operator >>(msgpack::object o, dnet_raw_id &v) {
	if (o.type != msgpack::type::RAW || o.via.raw.size != sizeof(v.id)) {
		throw msgpack::type_error();
	}
	memcpy(v.id, o.via.raw.ptr, sizeof(v.id));
	return v;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const dnet_raw_id &v) {
	o.pack_raw(sizeof(v.id));
	o.pack_raw_body(reinterpret_cast<const char *>(v.id), sizeof(v.id));
	return o;
}

inline dnet_id &operator >>(msgpack::object o, dnet_id &v) {
	if (o.type != msgpack::type::ARRAY || o.via.array.size < 2)
		throw msgpack::type_error();

	const object *p = o.via.array.ptr;
	if (p[0].type != msgpack::type::RAW || p[0].via.raw.size != sizeof(v.id)) {
		throw msgpack::type_error();
	}
	memcpy(v.id, p[0].via.raw.ptr, sizeof(v.id));
	p[1].convert(&v.group_id);
	return v;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const dnet_id &v) {
	o.pack_array(2);
	o.pack_raw(sizeof(v.id));
	o.pack_raw_body(reinterpret_cast<const char *>(v.id), sizeof(v.id));
	o.pack(v.group_id);
	return o;
}

inline dnet_iterator_range &operator >>(msgpack::object o, dnet_iterator_range &v) {
	if (o.type != msgpack::type::ARRAY || o.via.array.size != 2)
		throw msgpack::type_error();

	object *p = o.via.array.ptr;
	p[0].convert(&v.key_begin);
	p[1].convert(&v.key_end);

	return v;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const dnet_iterator_range &v) {
	o.pack_array(2);
	o.pack(v.key_begin);
	o.pack(v.key_end);

	return o;
}

inline ioremap::elliptics::dnet_iterator_request &operator >>(msgpack::object o,
                                                              ioremap::elliptics::dnet_iterator_request &v) {
	if (o.type != msgpack::type::ARRAY || o.via.array.size < 8)
		throw msgpack::type_error();

	object *p = o.via.array.ptr;
	p[0].convert(&v.iterator_id);
	p[1].convert(&v.action);
	p[2].convert(&v.type);
	p[3].convert(&v.flags);
	p[4].convert(&v.key_ranges);
	p[5].convert(&std::get<0>(v.time_range));
	p[6].convert(&std::get<1>(v.time_range));
	p[7].convert(&v.groups);

	return v;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o,
                                            const ioremap::elliptics::dnet_iterator_request &v) {
	o.pack_array(8);
	o.pack(v.iterator_id);
	o.pack(v.action);
	o.pack(v.type);
	o.pack(v.flags);
	o.pack(v.key_ranges);
	o.pack(std::get<0>(v.time_range));
	o.pack(std::get<1>(v.time_range));
	o.pack(v.groups);

	return o;
}

inline ioremap::elliptics::dnet_iterator_response &operator >>(msgpack::object o,
                                                               ioremap::elliptics::dnet_iterator_response &v) {
	if (o.type != msgpack::type::ARRAY || o.via.array.size < 14) {
		throw msgpack::type_error();
	}

	object *p = o.via.array.ptr;
	p[0].convert(&v.iterator_id);
	p[1].convert(&v.key);
	p[2].convert(&v.status);
	p[3].convert(&v.iterated_keys);
	p[4].convert(&v.total_keys);
	p[5].convert(&v.record_flags);
	p[6].convert(&v.user_flags);
	p[7].convert(&v.json_timestamp);
	p[8].convert(&v.json_size);
	p[9].convert(&v.json_capacity);
	p[10].convert(&v.read_json_size);
	p[11].convert(&v.data_timestamp);
	p[12].convert(&v.data_size);
	p[13].convert(&v.read_data_size);

	if (o.via.array.size > 15) {
		p[14].convert(&v.data_offset);
		p[15].convert(&v.blob_id);
	} else {
		v.data_offset = 0;
		v.blob_id = 0;
	}

	return v;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o,
                                            const ioremap::elliptics::dnet_iterator_response &v) {
	o.pack_array(16);
	o.pack(v.iterator_id);
	o.pack(v.key);
	o.pack(v.status);
	o.pack(v.iterated_keys);
	o.pack(v.total_keys);
	o.pack(v.record_flags);
	o.pack(v.user_flags);
	o.pack(v.json_timestamp);
	o.pack(v.json_size);
	o.pack(v.json_capacity);
	o.pack(v.read_json_size);
	o.pack(v.data_timestamp);
	o.pack(v.data_size);
	o.pack(v.read_data_size);
	o.pack(v.data_offset);
	o.pack(v.blob_id);

	return o;
}

inline ioremap::elliptics::dnet_server_send_request &operator >>(msgpack::object o,
                                                                 ioremap::elliptics::dnet_server_send_request &v) {
	if (o.type != msgpack::type::ARRAY || o.via.array.size < 3) {
		throw msgpack::type_error();
	}

	object *p = o.via.array.ptr;
	p[0].convert(&v.keys);
	p[1].convert(&v.groups);
	p[2].convert(&v.flags);

	if (o.via.array.size > 3) {
		p[3].convert(&v.chunk_size);
	} else {
		v.chunk_size = DNET_DEFAULT_SERVER_SEND_CHUNK_SIZE;
	}

	if (o.via.array.size > 5) {
		p[4].convert(&v.chunk_write_timeout);
		p[5].convert(&v.chunk_commit_timeout);
	} else {
		v.chunk_write_timeout = DNET_DEFAULT_SERVER_SEND_CHUNK_WRITE_TIMEOUT;
		v.chunk_commit_timeout = DNET_DEFAULT_SERVER_SEND_CHUNK_COMMIT_TIMEOUT;
	}

	return v;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o,
                                            const ioremap::elliptics::dnet_server_send_request &v) {
	o.pack_array(4);
	o.pack(v.keys);
	o.pack(v.groups);
	o.pack(v.flags);
	o.pack(v.chunk_size);
	o.pack(v.chunk_write_timeout);
	o.pack(v.chunk_commit_timeout);

	return o;
}

inline ioremap::elliptics::dnet_bulk_read_request &operator >>(msgpack::object o,
							       ioremap::elliptics::dnet_bulk_read_request &v) {
	if (o.type != msgpack::type::ARRAY || o.via.array.size < 4) {
		throw msgpack::type_error();
	}

	const object *p = o.via.array.ptr;
	p[0].convert(&v.keys);
	p[1].convert(&v.ioflags);
	p[2].convert(&v.read_flags);
	p[3].convert(&v.deadline);

	return v;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o,
                                            const ioremap::elliptics::dnet_bulk_read_request &v) {
	o.pack_array(4);
	o.pack(v.keys);
	o.pack(v.ioflags);
	o.pack(v.read_flags);
	o.pack(v.deadline);

	return o;
}


} // namespace msgpack

namespace ioremap { namespace elliptics {

dnet_iterator_request::dnet_iterator_request()
	: iterator_id{0}
	, action{DNET_ITERATOR_ACTION_START}
	, type{DNET_ITYPE_NETWORK}
	, flags{0}
	, key_ranges{}
	, time_range{dnet_time{0, 0}, dnet_time{0, 0}}
	, groups{} {
}

dnet_iterator_request::dnet_iterator_request(uint32_t type, uint64_t flags,
                                             const std::vector<dnet_iterator_range> &key_ranges,
                                             const std::tuple<dnet_time, dnet_time> &time_range)
	: iterator_id{0}
	, action{DNET_ITERATOR_ACTION_START}
	, type{type}
	, flags{flags}
	, key_ranges{key_ranges}
	, time_range(time_range)
	, groups{} {
}


template<typename T>
data_pointer serialize(const T &value) {
	msgpack::sbuffer buffer;
	msgpack::pack(buffer, value);

	return data_pointer::copy(buffer.data(), buffer.size());
}

template<typename T>
void deserialize(const data_pointer &data, T &value, size_t &offset) {
	offset = 0;

	msgpack::unpacked msg;
	msgpack::unpack(&msg, data.data<char>(), data.size(), &offset);
	msg.get().convert(&value);
}

void validate_json(const std::string &json) {
	if (json.empty())
		return;

	rapidjson::Document doc;
	doc.Parse<0>(json.c_str());

	if (doc.HasParseError() || !doc.IsObject()) {
		throw std::runtime_error(doc.GetParseError());
	}
}

#define DEFINE_HEADER(TYPE) \
template data_pointer serialize<TYPE>(const TYPE &); \
template void deserialize(const data_pointer &data, TYPE &value, size_t &offset);

DEFINE_HEADER(dnet_read_request);
DEFINE_HEADER(dnet_read_response);

DEFINE_HEADER(dnet_write_request);

DEFINE_HEADER(dnet_lookup_response);

DEFINE_HEADER(dnet_remove_request);

DEFINE_HEADER(dnet_iterator_request);
DEFINE_HEADER(dnet_iterator_response);

DEFINE_HEADER(dnet_server_send_request);

DEFINE_HEADER(dnet_bulk_read_request);

DEFINE_HEADER(dnet_json_header);
}} // namespace ioremap::elliptics
