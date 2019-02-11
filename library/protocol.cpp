#include "protocol.hpp"

#include <msgpack.hpp>

#include "rapidjson/document.h"

namespace msgpack {
MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS) {
namespace adaptor {
using namespace ioremap::elliptics;

template<>
struct convert<dnet_time> {
	msgpack::object const& operator()(msgpack::object const& o, dnet_time& v) const {
		if (o.type!=msgpack::type::ARRAY || o.via.array.size != 2) {
			throw msgpack::type_error();
		}

		auto p = o.via.array.ptr;
		p[0].convert(v.tsec);
		p[1].convert(v.tnsec);
		return o;
	}
};

template<>
struct pack<dnet_time> {
	template<typename Stream>
	msgpack::packer<Stream>& operator()(msgpack::packer<Stream>& o, dnet_time const& v) const {
		o.pack_array(2);
		o.pack_fix_uint64(v.tsec);
		o.pack_fix_uint64(v.tnsec);
		return o;
	}
};

template<>
struct convert<dnet_read_request> {
	msgpack::object const& operator()(msgpack::object const& o, dnet_read_request& v) const {
		if (o.type!=msgpack::type::ARRAY || o.via.array.size<4) {
			throw msgpack::type_error();
		}

		auto p = o.via.array.ptr;
		p[0].convert(v.ioflags);
		p[1].convert(v.read_flags);
		p[2].convert(v.data_offset);
		p[3].convert(v.data_size);

		if (o.via.array.size>4) {
			p[4].convert(v.deadline);
		}
		else {
			// for older protocol
			dnet_empty_time(&v.deadline);
		}

		return o;
	}
};

template<>
struct pack<dnet_read_request> {
	template<typename Stream>
	msgpack::packer<Stream>& operator()(msgpack::packer<Stream>& o, dnet_read_request const& v) const {
		o.pack_array(5);
		o.pack(v.ioflags);
		o.pack(v.read_flags);
		o.pack(v.data_offset);
		o.pack(v.data_size);
		o.pack(v.deadline);

		return o;
	}
};

template<>
struct convert<dnet_read_response> {
	msgpack::object const& operator()(msgpack::object const& o, dnet_read_response& v) const {
		if (o.type!=msgpack::type::ARRAY || o.via.array.size<10) {
			throw msgpack::type_error();
		}

		auto p = o.via.array.ptr;
		p[0].convert(v.record_flags);
		p[1].convert(v.user_flags);

		p[2].convert(v.json_timestamp);
		p[3].convert(v.json_size);
		p[4].convert(v.json_capacity);
		p[5].convert(v.read_json_size);

		p[6].convert(v.data_timestamp);
		p[7].convert(v.data_size);
		p[8].convert(v.read_data_offset);
		p[9].convert(v.read_data_size);

		return o;
	}
};

template<>
struct pack<dnet_read_response> {
	template<typename Stream>
	msgpack::packer<Stream>& operator()(msgpack::packer<Stream>& o, dnet_read_response const& v) const {
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
};

template<>
struct convert<dnet_write_request> {
	msgpack::object const& operator()(msgpack::object const& o, dnet_write_request& v) const {
		if (o.type!=msgpack::type::ARRAY || o.via.array.size<9)
			throw msgpack::type_error();

		auto p = o.via.array.ptr;
		p[0].convert(v.ioflags);

		p[1].convert(v.user_flags);

		p[2].convert(v.timestamp);

		p[3].convert(v.json_size);
		p[4].convert(v.json_capacity);

		p[5].convert(v.data_offset);
		p[6].convert(v.data_size);
		p[7].convert(v.data_capacity);
		p[8].convert(v.data_commit_size);

		if (o.via.array.size>9) {
			p[9].convert(v.json_timestamp);
		}
		else {
			// older protocol: take json timestamp from data timestamp
			p[2].convert(v.json_timestamp);
		}

		if (o.via.array.size>10) {
			p[10].convert(v.cache_lifetime);
		}
		else {
			// older protocol
			v.cache_lifetime = 0;
		}

		if (o.via.array.size>11) {
			p[11].convert(v.deadline);
		}
		else {
			// for older protocol
			dnet_empty_time(&v.deadline);
		}

		return o;
	}
};

template<>
struct pack<dnet_write_request> {
	template<typename Stream>
	msgpack::packer<Stream>& operator()(msgpack::packer<Stream>& o, dnet_write_request const& v) const {
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
};

template<>
struct convert<dnet_lookup_response> {
	msgpack::object const& operator()(msgpack::object const& o, dnet_lookup_response& v) const {
		if (o.type!=msgpack::type::ARRAY || o.via.array.size<10)
			throw msgpack::type_error();

		auto p = o.via.array.ptr;
		p[0].convert(v.record_flags);
		p[1].convert(v.user_flags);
		p[2].convert(v.path);

		p[3].convert(v.json_timestamp);
		p[4].convert(v.json_offset);
		p[5].convert(v.json_size);
		p[6].convert(v.json_capacity);

		p[7].convert(v.data_timestamp);
		p[8].convert(v.data_offset);
		p[9].convert(v.data_size);

		if (o.via.array.size>11) {
			p[10].convert(v.json_checksum);
			p[11].convert(v.data_checksum);

			if ((!v.json_checksum.empty() && v.json_checksum.size()!=DNET_CSUM_SIZE) ||
					(!v.data_checksum.empty() && v.data_checksum.size()!=DNET_CSUM_SIZE)) {
				throw std::runtime_error("Unexpected checksum size");
			}
		}

		return o;
	}
};

template<>
struct pack<dnet_lookup_response> {
	template<typename Stream>
	msgpack::packer<Stream>& operator()(msgpack::packer<Stream>& o, dnet_lookup_response const& v) const {
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
};

template<>
struct convert<dnet_remove_request> {
	msgpack::object const& operator()(msgpack::object const& o, dnet_remove_request& v) const {
		if (o.type!=msgpack::type::ARRAY || o.via.array.size<2)
			throw msgpack::type_error();

		auto p = o.via.array.ptr;
		p[0].convert(v.ioflags);
		p[1].convert(v.timestamp);

		return o;
	}
};

template<>
struct pack<dnet_remove_request> {
	template<typename Stream>
	msgpack::packer<Stream>& operator()(msgpack::packer<Stream>& o, dnet_remove_request const& v) const {
		o.pack_array(2);
		o.pack(v.ioflags);
		o.pack(v.timestamp);

		return o;
	}
};

template<>
struct convert<dnet_json_header> {
	msgpack::object const& operator()(msgpack::object const& o, dnet_json_header& v) const {
		if (o.type!=msgpack::type::ARRAY || o.via.array.size<3)
			throw msgpack::type_error();

		auto p = o.via.array.ptr;
		p[0].convert(v.size);
		p[1].convert(v.capacity);
		p[2].convert(v.timestamp);

		return o;
	}
};

template<>
struct pack<dnet_json_header> {
	template<typename Stream>
	msgpack::packer<Stream>& operator()(msgpack::packer<Stream>& o, dnet_json_header const& v) const {
		o.pack_array(3);
		o.pack_fix_uint64(v.size);
		o.pack_fix_uint64(v.capacity);
		o.pack(v.timestamp);

		return o;
	}
};

template<>
struct convert<dnet_raw_id> {
	msgpack::object const& operator()(msgpack::object const& o, dnet_raw_id& v) const {
		if (o.type!=msgpack::type::STR || o.via.array.size!=sizeof(v.id)) {
			throw msgpack::type_error();
		}
		memcpy(v.id, o.via.str.ptr, sizeof(v.id));
		return o;
	}
};

template<>
struct pack<dnet_raw_id> {
	template<typename Stream>
	msgpack::packer<Stream>& operator()(msgpack::packer<Stream>& o, dnet_raw_id const& v) const {
		o.pack_str(sizeof(v.id));
		o.pack_str_body(reinterpret_cast<const char*>(v.id), sizeof(v.id));
		return o;
	}
};

template<>
struct convert<dnet_id> {
	msgpack::object const& operator()(msgpack::object const& o, dnet_id& v) const {
		if (o.type!=msgpack::type::ARRAY || o.via.array.size<2)
			throw msgpack::type_error();

		auto p = o.via.array.ptr;
		if (p[0].type!=msgpack::type::STR || p[0].via.str.size!=sizeof(v.id)) {
			throw msgpack::type_error();
		}
		memcpy(v.id, p[0].via.str.ptr, sizeof(v.id));
		v.group_id = p[1].as<uint32_t>();
		return o;
	}
};

template<>
struct pack<dnet_id> {
	template<typename Stream>
	msgpack::packer<Stream>& operator()(msgpack::packer<Stream>& o, dnet_id const& v) const {
		o.pack_array(2);
		o.pack_str(sizeof(v.id));
		o.pack_str_body(reinterpret_cast<const char*>(v.id), sizeof(v.id));
		o.pack(v.group_id);
		return o;
	}
};

template<>
struct convert<dnet_iterator_range> {
	msgpack::object const& operator()(msgpack::object const& o, dnet_iterator_range& v) const {
		if (o.type!=msgpack::type::ARRAY || o.via.array.size!=2)
			throw msgpack::type_error();

		auto p = o.via.array.ptr;
		p[0].convert(v.key_begin);
		p[1].convert(v.key_end);

		return o;
	}
};

template<>
struct pack<dnet_iterator_range> {
	template<typename Stream>
	msgpack::packer<Stream>& operator()(msgpack::packer<Stream>& o, dnet_iterator_range const& v) const {
		o.pack_array(2);
		o.pack(v.key_begin);
		o.pack(v.key_end);

		return o;
	}
};

template<>
struct convert<ioremap::elliptics::dnet_iterator_request> {
	msgpack::object const& operator()(msgpack::object const& o, ioremap::elliptics::dnet_iterator_request& v) const {
		if (o.type!=msgpack::type::ARRAY || o.via.array.size<8)
			throw msgpack::type_error();

		auto p = o.via.array.ptr;
		p[0].convert(v.iterator_id);
		p[1].convert(v.action);
		p[2].convert(v.type);
		p[3].convert(v.flags);
		p[4].convert(v.key_ranges);
		p[5].convert(std::get<0>(v.time_range));
		p[6].convert(std::get<1>(v.time_range));
		p[7].convert(v.groups);

		return o;
	}
};

template<>
struct pack<ioremap::elliptics::dnet_iterator_request> {
	template<typename Stream>
	msgpack::packer<Stream>& operator()(msgpack::packer<Stream>& o, ioremap::elliptics::dnet_iterator_request const& v) const {
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
};

template<>
struct convert<ioremap::elliptics::dnet_iterator_response> {
	msgpack::object const& operator()(msgpack::object const& o, ioremap::elliptics::dnet_iterator_response& v) const {
		if (o.type!=msgpack::type::ARRAY || o.via.array.size<14) {
			throw msgpack::type_error();
		}

		auto p = o.via.array.ptr;
		p[0].convert(v.iterator_id);
		p[1].convert(v.key);
		p[2].convert(v.status);
		p[3].convert(v.iterated_keys);
		p[4].convert(v.total_keys);
		p[5].convert(v.record_flags);
		p[6].convert(v.user_flags);
		p[7].convert(v.json_timestamp);
		p[8].convert(v.json_size);
		p[9].convert(v.json_capacity);
		p[10].convert(v.read_json_size);
		p[11].convert(v.data_timestamp);
		p[12].convert(v.data_size);
		p[13].convert(v.read_data_size);

		if (o.via.array.size>15) {
			p[14].convert(v.data_offset);
			p[15].convert(v.blob_id);
		}
		else {
			v.data_offset = 0;
			v.blob_id = 0;
		}

		return o;
	}
};

template<>
struct pack<ioremap::elliptics::dnet_iterator_response> {
	template<typename Stream>
	msgpack::packer<Stream>& operator()(msgpack::packer<Stream>& o, ioremap::elliptics::dnet_iterator_response const& v) const {
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
};

template<>
struct convert<ioremap::elliptics::dnet_server_send_request> {
	msgpack::object const& operator()(msgpack::object const& o, ioremap::elliptics::dnet_server_send_request& v) const {
		if (o.type!=msgpack::type::ARRAY || o.via.array.size<3) {
			throw msgpack::type_error();
		}

		auto p = o.via.array.ptr;
		p[0].convert(v.keys);
		p[1].convert(v.groups);
		p[2].convert(v.flags);

		if (o.via.array.size>3) {
			p[3].convert(v.chunk_size);
		}
		else {
			v.chunk_size = DNET_DEFAULT_SERVER_SEND_CHUNK_SIZE;
		}

		if (o.via.array.size>5) {
			p[4].convert(v.chunk_write_timeout);
			p[5].convert(v.chunk_commit_timeout);
		}
		else {
			v.chunk_write_timeout = DNET_DEFAULT_SERVER_SEND_CHUNK_WRITE_TIMEOUT;
			v.chunk_commit_timeout = DNET_DEFAULT_SERVER_SEND_CHUNK_COMMIT_TIMEOUT;
		}

		if (o.via.array.size>6) {
			p[6].convert(v.chunk_retry_count);
		}
		else {
			v.chunk_retry_count = DNET_DEFAULT_SERVER_SEND_CHUNK_RETRY_COUNT;
		}

		return o;
	}
};

template<>
struct pack<ioremap::elliptics::dnet_server_send_request> {
	template<typename Stream>
	msgpack::packer<Stream>& operator()(msgpack::packer<Stream>& o, ioremap::elliptics::dnet_server_send_request const& v) const {
		o.pack_array(7);
		o.pack(v.keys);
		o.pack(v.groups);
		o.pack(v.flags);
		o.pack(v.chunk_size);
		o.pack(v.chunk_write_timeout);
		o.pack(v.chunk_commit_timeout);
		o.pack(v.chunk_retry_count);

		return o;
	}
};

template<>
struct convert<ioremap::elliptics::dnet_bulk_read_request> {
	msgpack::object const& operator()(msgpack::object const& o, ioremap::elliptics::dnet_bulk_read_request& v) const {
		if (o.type != msgpack::type::ARRAY || o.via.array.size < 4) {
			throw msgpack::type_error();
		}

		auto p = o.via.array.ptr;
		p[0].convert(v.keys);
		p[1].convert(v.ioflags);
		p[2].convert(v.read_flags);
		p[3].convert(v.deadline);

		return o;
	}
};

template<>
struct pack<ioremap::elliptics::dnet_bulk_read_request> {
	template<typename Stream>
	msgpack::packer<Stream>& operator()(msgpack::packer<Stream>& o, ioremap::elliptics::dnet_bulk_read_request const& v) const {
		o.pack_array(4);
		o.pack(v.keys);
		o.pack(v.ioflags);
		o.pack(v.read_flags);
		o.pack(v.deadline);

		return o;
	}
};

template<>
struct convert<ioremap::elliptics::dnet_bulk_remove_request> {
	msgpack::object const& operator()(msgpack::object const&o, ioremap::elliptics::dnet_bulk_remove_request& v) const {
		if (o.type!=msgpack::type::ARRAY || o.via.array.size<3) {
			throw msgpack::type_error();
		}

		auto p = o.via.array.ptr;
		p[0].convert(v.ioflags);
		p[1].convert(v.keys);
		p[2].convert(v.timestamps);

		return o;
	}
};

template<>
struct pack<ioremap::elliptics::dnet_bulk_remove_request> {
	template<typename Stream>
	msgpack::packer<Stream>& operator()(msgpack::packer<Stream>& o, ioremap::elliptics::dnet_bulk_remove_request const& v) const {
		o.pack_array(3);
		o.pack(v.ioflags);
		o.pack(v.keys);
		o.pack(v.timestamps);
		return o;
	}
};

} // namespace adaptor
} // MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS)
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

dnet_bulk_remove_request::dnet_bulk_remove_request() {}

dnet_bulk_remove_request::dnet_bulk_remove_request(const std::vector<dnet_id> &keys_in)
	: keys(keys_in) {}

dnet_bulk_remove_request::dnet_bulk_remove_request(const std::vector<std::pair<dnet_id, dnet_time>> &keys_in) {
	ioflags = DNET_IO_FLAGS_CAS_TIMESTAMP;
	keys.reserve(keys_in.size());
	timestamps.reserve(keys_in.size());
	for (auto &key : keys_in) {
		keys.push_back(key.first);
		timestamps.push_back(key.second);
	}
}

bool dnet_bulk_remove_request::is_valid() const {
	return (ioflags & DNET_IO_FLAGS_CAS_TIMESTAMP && (keys.size() == timestamps.size())) ||
		(!(ioflags & DNET_IO_FLAGS_CAS_TIMESTAMP) && (timestamps.size() == 0));
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
	msgpack::unpack(msg, data.data<char>(), data.size(), offset);
	msg.get().convert(value);
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

DEFINE_HEADER(dnet_bulk_remove_request)
DEFINE_HEADER(dnet_remove_request);

DEFINE_HEADER(dnet_iterator_request);
DEFINE_HEADER(dnet_iterator_response);

DEFINE_HEADER(dnet_server_send_request);

DEFINE_HEADER(dnet_bulk_read_request);

DEFINE_HEADER(dnet_json_header);
}} // namespace ioremap::elliptics
