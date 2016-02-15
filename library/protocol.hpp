#ifndef ELLIPTICS_PROTOCOL_HPP
#define ELLIPTICS_PROTOCOL_HPP

#include <elliptics/packet.h>
#include <elliptics/utils.hpp>

namespace ioremap { namespace elliptics {

#define DNET_READ_FLAGS_JSON (1<<0)
#define DNET_READ_FLAGS_DATA (1<<1)

struct dnet_read_request {
	uint64_t ioflags;
	uint64_t read_flags;
	uint64_t data_offset;
	uint64_t data_size;
};

struct dnet_read_response {
	uint64_t record_flags;
	uint64_t user_flags;

	dnet_time json_timestamp;
	uint64_t json_size;
	uint64_t json_capacity;
	uint64_t read_json_size;

	dnet_time data_timestamp;
	uint64_t data_size;
	uint64_t read_data_offset;
	uint64_t read_data_size;
};

struct dnet_write_request {
	uint64_t ioflags;
	uint64_t user_flags;
	dnet_time timestamp;

	uint64_t json_size;
	uint64_t json_capacity;

	uint64_t data_offset;
	uint64_t data_size;
	uint64_t data_capacity;
	uint64_t data_commit_size;
};

struct dnet_lookup_response {
	uint64_t record_flags;
	uint64_t user_flags;
	std::string path;

	dnet_time json_timestamp;
	uint64_t json_offset;
	uint64_t json_size;
	uint64_t json_capacity;

	dnet_time data_timestamp;
	uint64_t data_offset;
	uint64_t data_size;
};

template<typename T>
data_pointer serialize(const T &value);

template<typename T>
void deserialize(const data_pointer &data, T &value, size_t &offset);

template<typename T>
void deserialize(const data_pointer &data, T &value) {
	size_t offset = 0;
	deserialize(data, value, offset);
}

void validate_json(const std::string &json);

}} // namespace ioremap::elliptics

#endif // ELLIPTICS_PROTOCOL_HPP
