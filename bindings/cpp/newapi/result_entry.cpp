#include "elliptics/newapi/result_entry.hpp"
#include "library/protocol.hpp"

namespace ioremap { namespace elliptics { namespace newapi {

data_pointer callback_result_entry::raw() const {
	return ioremap::elliptics::callback_result_entry::raw_data();
}

data_pointer callback_result_entry::raw_data() const {
	return ioremap::elliptics::callback_result_entry::data();
}

std::string lookup_result_entry::path() const {
	dnet_lookup_response response;

	deserialize(raw_data(), response);
	return response.path;
}

dnet_record_info lookup_result_entry::info() const {
	dnet_record_info info;
	memset(&info, 0, sizeof(info));

	dnet_lookup_response response;

	deserialize(raw_data(), response);

	info.record_flags = response.record_flags;
	info.user_flags = response.user_flags;

	info.json_timestamp = response.json_timestamp;
	info.json_offset = response.json_offset;
	info.json_size = response.json_size;
	info.json_capacity = response.json_capacity;

	info.data_timestamp = response.data_timestamp;
	info.data_offset = response.data_offset;
	info.data_size = response.data_size;
	// info.data_capacity = response.data_capacity;

	return info;
}

dnet_record_info read_result_entry::info() const {
	dnet_record_info info;
	memset(&info, 0, sizeof(info));

	dnet_read_response response;

	deserialize(raw_data(), response);

	info.record_flags = response.record_flags;
	info.user_flags = response.user_flags;

	info.json_timestamp = response.json_timestamp;
	info.json_size = response.json_size;
	info.json_capacity = response.json_capacity;

	info.data_timestamp = response.data_timestamp;
	info.data_size = response.data_size;

	return info;
}

data_pointer read_result_entry::json() const {
	size_t offset = 0;
	dnet_read_response response;

	deserialize(raw_data(), response, offset);

	return raw_data().slice(offset, response.read_json_size);
}

data_pointer read_result_entry::data() const {
	size_t offset = 0;
	dnet_read_response response;

	deserialize(raw_data(), response, offset);

	return raw_data().slice(offset + response.read_json_size, response.read_data_size);
}

}}} // namespace ioremap::elliptics::newapi
