#include "test_base.hpp"

#include <fstream>

#include <eblob/blob.h>

#define BOOST_TEST_NO_MAIN
#include <boost/test/included/unit_test.hpp>

#include <boost/program_options.hpp>

#include "elliptics/newapi/session.hpp"

namespace {

namespace bu = boost::unit_test;

std::shared_ptr<tests::nodes_data> servers;

const std::vector<int> groups{1,2,3};

void configure_servers(const std::string &path) {
	servers = [&path] {
		constexpr auto server_config = [](const tests::config_data &c) {
			return tests::server_config::default_value().apply_options(c);
		};

		auto configs = {server_config(tests::config_data()("group", 1)),
		                server_config(tests::config_data()("group", 2)),
		                server_config(tests::config_data()("group", 3))};

		tests::start_nodes_config config(bu::results_reporter::get_stream(),
		                                 configs,
		                                 path);
		config.fork = true;
		return tests::start_nodes(config);
	} ();
}

struct record {
	ioremap::elliptics::key key;
	uint64_t user_flags;
	dnet_time timestamp;
	std::string json;
	uint64_t json_capacity;
	std::string data;
	uint64_t data_capacity;
};

void check_lookup_result(ioremap::elliptics::newapi::async_lookup_result &async,
                         const int command,
                         const record &record,
                         const size_t expected_count) {
	size_t count = 0;
	for (const auto &result: async) {
		(void)result.address();
		BOOST_REQUIRE_EQUAL(result.status(), 0);
		BOOST_REQUIRE_EQUAL(result.command()->cmd, command);
		BOOST_REQUIRE_EQUAL(result.error().code(), 0);
		BOOST_REQUIRE_EQUAL(result.error().message(), "");

		auto record_info = result.record_info();

		BOOST_REQUIRE_EQUAL(record_info.user_flags, record.user_flags);
		BOOST_REQUIRE_EQUAL(record_info.record_flags, DNET_RECORD_FLAGS_EXTHDR | DNET_RECORD_FLAGS_CHUNKED_CSUM);

		BOOST_REQUIRE_EQUAL(dnet_time_cmp(&record_info.json_timestamp, &record.timestamp), 0);
		constexpr uint64_t eblob_headers_size = sizeof(eblob_disk_control) + sizeof(dnet_ext_list_hdr);
		BOOST_REQUIRE(record_info.json_offset >= eblob_headers_size);
		BOOST_REQUIRE_EQUAL(record_info.json_size, record.json.size());
		BOOST_REQUIRE_EQUAL(record_info.json_capacity, record.json_capacity);

		BOOST_REQUIRE_EQUAL(dnet_time_cmp(&record_info.data_timestamp, &record.timestamp), 0);
		BOOST_REQUIRE_EQUAL(record_info.data_offset, record_info.json_offset + record.json_capacity);
		BOOST_REQUIRE_EQUAL(record_info.data_size, record.data.size());

		std::ifstream blob(result.path(), std::ifstream::binary);
		BOOST_REQUIRE(blob);
		{
			blob.seekg(record_info.json_offset);
			auto buffer = ioremap::elliptics::data_pointer::allocate(record.json.size());
			blob.read(buffer.data<char>(), buffer.size());
			BOOST_REQUIRE(blob);
			BOOST_REQUIRE_EQUAL(buffer.to_string(), record.json);
		} {
			blob.seekg(record_info.data_offset);
			auto buffer = ioremap::elliptics::data_pointer::allocate(record.data.size());
			blob.read(buffer.data<char>(), buffer.size());
			BOOST_REQUIRE(blob);
			BOOST_REQUIRE_EQUAL(buffer.to_string(), record.data);
		}

		++count;
	}

	BOOST_REQUIRE_EQUAL(count, expected_count);
}

void test_write(const record &record) {
	ioremap::elliptics::newapi::session s(*servers->node);
	s.set_groups(groups);
	s.set_user_flags(record.user_flags);

	s.set_timestamp(record.timestamp);

	auto async = s.write(record.key,
	                     record.json, record.json_capacity,
	                     record.data, record.data_capacity);

	check_lookup_result(async, DNET_CMD_WRITE_NEW, record, groups.size());
}

void test_lookup(const record &record) {
	ioremap::elliptics::newapi::session s(*servers->node);
	s.set_groups(groups);

	auto async = s.lookup(record.key);

	check_lookup_result(async, DNET_CMD_LOOKUP_NEW, record, 1);
}

void test_read_json(const record &record) {
	ioremap::elliptics::newapi::session s(*servers->node);

	size_t count = 0;

	for (const auto &group : groups) {
		s.set_groups({group});
		auto async = s.read_json(record.key);

		for (const auto &result: async) {
			(void)result.address();
			BOOST_REQUIRE_EQUAL(result.status(), 0);
			BOOST_REQUIRE_EQUAL(result.command()->cmd, DNET_CMD_READ_NEW);
			BOOST_REQUIRE_EQUAL(result.error().code(), 0);
			BOOST_REQUIRE_EQUAL(result.error().message(), "");

			auto info = result.record_info();

			BOOST_REQUIRE_EQUAL(info.user_flags, record.user_flags);
			BOOST_REQUIRE_EQUAL(info.record_flags, DNET_RECORD_FLAGS_EXTHDR | DNET_RECORD_FLAGS_CHUNKED_CSUM);

			BOOST_REQUIRE_EQUAL(dnet_time_cmp(&info.json_timestamp, &record.timestamp), 0);
			BOOST_REQUIRE_EQUAL(info.json_offset, 0);
			BOOST_REQUIRE_EQUAL(info.json_size, record.json.size());
			BOOST_REQUIRE_EQUAL(info.json_capacity, record.json_capacity);

			BOOST_REQUIRE_EQUAL(dnet_time_cmp(&info.data_timestamp, &record.timestamp), 0);
			BOOST_REQUIRE_EQUAL(info.data_offset, 0);
			BOOST_REQUIRE_EQUAL(info.data_size, record.data.size());

			BOOST_REQUIRE_EQUAL(result.json().to_string(), record.json);
			BOOST_REQUIRE(result.data().empty());

			auto io_info = result.io_info();

			BOOST_REQUIRE_EQUAL(io_info.json_size, record.json.size());
			BOOST_REQUIRE_EQUAL(io_info.data_offset, 0);
			BOOST_REQUIRE_EQUAL(io_info.data_size, 0);

			++count;
		}
	}

	BOOST_REQUIRE_EQUAL(count, groups.size());
}

void test_read_data(const record &record, uint64_t offset, uint64_t size) {
	ioremap::elliptics::newapi::session s(*servers->node);

	size_t count = 0;

	for (const auto &group : groups) {
		s.set_groups({group});
		auto async = s.read_data(record.key, offset, size);

		for (const auto &result: async) {
			(void)result.address();
			BOOST_REQUIRE_EQUAL(result.status(), 0);
			BOOST_REQUIRE_EQUAL(result.command()->cmd, DNET_CMD_READ_NEW);
			BOOST_REQUIRE_EQUAL(result.error().code(), 0);
			BOOST_REQUIRE_EQUAL(result.error().message(), "");

			auto record_info = result.record_info();

			BOOST_REQUIRE_EQUAL(record_info.user_flags, record.user_flags);
			BOOST_REQUIRE_EQUAL(record_info.record_flags, DNET_RECORD_FLAGS_EXTHDR | DNET_RECORD_FLAGS_CHUNKED_CSUM);

			BOOST_REQUIRE_EQUAL(dnet_time_cmp(&record_info.json_timestamp, &record.timestamp), 0);
			BOOST_REQUIRE_EQUAL(record_info.json_offset, 0);
			BOOST_REQUIRE_EQUAL(record_info.json_size, record.json.size());
			BOOST_REQUIRE_EQUAL(record_info.json_capacity, record.json_capacity);

			BOOST_REQUIRE_EQUAL(dnet_time_cmp(&record_info.data_timestamp, &record.timestamp), 0);
			BOOST_REQUIRE_EQUAL(record_info.data_offset, 0);
			BOOST_REQUIRE_EQUAL(record_info.data_size, record.data.size());

			BOOST_REQUIRE(result.json().empty());
			auto data_part = record.data.substr(offset, size ? size : std::string::npos);
			BOOST_REQUIRE_EQUAL(result.data().to_string(), data_part);

			auto io_info = result.io_info();

			BOOST_REQUIRE_EQUAL(io_info.json_size, 0);
			BOOST_REQUIRE_EQUAL(io_info.data_offset, offset);
			BOOST_REQUIRE_EQUAL(io_info.data_size, data_part.size());

			++count;
		}
	}

	BOOST_REQUIRE_EQUAL(count, groups.size());
}

void test_read(const record &record, uint64_t offset, uint64_t size) {
	ioremap::elliptics::newapi::session s(*servers->node);

	size_t count = 0;

	for (const auto &group : groups) {
		s.set_groups({group});
		auto async = s.read(record.key, offset, size);

		for (const auto &result: async) {
			(void)result.address();
			BOOST_REQUIRE_EQUAL(result.status(), 0);
			BOOST_REQUIRE_EQUAL(result.command()->cmd, DNET_CMD_READ_NEW);
			BOOST_REQUIRE_EQUAL(result.error().code(), 0);
			BOOST_REQUIRE_EQUAL(result.error().message(), "");

			auto record_info = result.record_info();

			BOOST_REQUIRE_EQUAL(record_info.user_flags, record.user_flags);
			BOOST_REQUIRE_EQUAL(record_info.record_flags, DNET_RECORD_FLAGS_EXTHDR | DNET_RECORD_FLAGS_CHUNKED_CSUM);

			BOOST_REQUIRE_EQUAL(dnet_time_cmp(&record_info.json_timestamp, &record.timestamp), 0);
			BOOST_REQUIRE_EQUAL(record_info.json_offset, 0);
			BOOST_REQUIRE_EQUAL(record_info.json_size, record.json.size());
			BOOST_REQUIRE_EQUAL(record_info.json_capacity, record.json_capacity);

			BOOST_REQUIRE_EQUAL(dnet_time_cmp(&record_info.data_timestamp, &record.timestamp), 0);
			BOOST_REQUIRE_EQUAL(record_info.data_offset, 0);
			BOOST_REQUIRE_EQUAL(record_info.data_size, record.data.size());

			BOOST_REQUIRE_EQUAL(result.json().to_string(), record.json);
			auto data_part = record.data.substr(offset, size ? size : std::string::npos);
			BOOST_REQUIRE_EQUAL(result.data().to_string(), data_part);

			auto io_info = result.io_info();

			BOOST_REQUIRE_EQUAL(io_info.json_size, record.json.size());
			BOOST_REQUIRE_EQUAL(io_info.data_offset, offset);
			BOOST_REQUIRE_EQUAL(io_info.data_size, data_part.size());

			++count;
		}
	}

	BOOST_REQUIRE_EQUAL(count, groups.size());
}

void test_write_chunked(const record &record) {
	ioremap::elliptics::newapi::session s(*servers->node);
	s.set_groups(groups);
	s.set_user_flags(record.user_flags);
	s.set_timestamp(record.timestamp);

	auto async = s.write_prepare(record.key,
	                             std::string{}, record.json_capacity,
	                             record.data, 0, record.data_capacity);

	size_t count = 0;
	for (const auto &result: async) {
		(void)result.address();
		BOOST_REQUIRE_EQUAL(result.status(), 0);
		BOOST_REQUIRE_EQUAL(result.command()->cmd, DNET_CMD_WRITE_NEW);
		BOOST_REQUIRE_EQUAL(result.error().code(), 0);
		BOOST_REQUIRE_EQUAL(result.error().message(), "");

		auto record_info = result.record_info();

		BOOST_REQUIRE_EQUAL(record_info.user_flags, record.user_flags);
		BOOST_REQUIRE_EQUAL(record_info.record_flags, DNET_RECORD_FLAGS_EXTHDR | DNET_RECORD_FLAGS_CHUNKED_CSUM | DNET_RECORD_FLAGS_UNCOMMITTED);

		BOOST_REQUIRE_EQUAL(dnet_time_cmp(&record_info.json_timestamp, &record.timestamp), 0);
		constexpr uint64_t eblob_headers_size = sizeof(eblob_disk_control) + sizeof(dnet_ext_list_hdr);
		BOOST_REQUIRE(record_info.json_offset >= eblob_headers_size);
		BOOST_REQUIRE_EQUAL(record_info.json_size, 0);
		BOOST_REQUIRE_EQUAL(record_info.json_capacity, record.json_capacity);

		BOOST_REQUIRE_EQUAL(dnet_time_cmp(&record_info.data_timestamp, &record.timestamp), 0);
		BOOST_REQUIRE_EQUAL(record_info.data_offset, record_info.json_offset + record.json_capacity);
		BOOST_REQUIRE_EQUAL(record_info.data_size, 0);
		++count;
	}
	BOOST_REQUIRE_EQUAL(count, groups.size());

	async = s.write_plain(record.key,
	                      record.json,
	                      std::string{}, 0);

	count = 0;
	for (const auto &result: async) {
		(void)result.address();
		BOOST_REQUIRE_EQUAL(result.status(), 0);
		BOOST_REQUIRE_EQUAL(result.command()->cmd, DNET_CMD_WRITE_NEW);
		BOOST_REQUIRE_EQUAL(result.error().code(), 0);
		BOOST_REQUIRE_EQUAL(result.error().message(), "");

		auto record_info = result.record_info();

		BOOST_REQUIRE_EQUAL(record_info.user_flags, record.user_flags);
		BOOST_REQUIRE_EQUAL(record_info.record_flags, DNET_RECORD_FLAGS_EXTHDR | DNET_RECORD_FLAGS_CHUNKED_CSUM | DNET_RECORD_FLAGS_UNCOMMITTED);

		BOOST_REQUIRE_EQUAL(dnet_time_cmp(&record_info.json_timestamp, &record.timestamp), 0);
		constexpr uint64_t eblob_headers_size = sizeof(eblob_disk_control) + sizeof(dnet_ext_list_hdr);
		BOOST_REQUIRE(record_info.json_offset >= eblob_headers_size);
		BOOST_REQUIRE_EQUAL(record_info.json_size, record.json.size());
		BOOST_REQUIRE_EQUAL(record_info.json_capacity, record.json_capacity);

		BOOST_REQUIRE_EQUAL(dnet_time_cmp(&record_info.data_timestamp, &record.timestamp), 0);
		BOOST_REQUIRE_EQUAL(record_info.data_offset, record_info.json_offset + record.json_capacity);
		BOOST_REQUIRE_EQUAL(record_info.data_size, 0);
		++count;
	}
	BOOST_REQUIRE_EQUAL(count, groups.size());

	async = s.write_plain(record.key,
	                      std::string{},
	                      record.data, record.data.size());

	count = 0;
	for (const auto &result: async) {
		(void)result.address();
		BOOST_REQUIRE_EQUAL(result.status(), 0);
		BOOST_REQUIRE_EQUAL(result.command()->cmd, DNET_CMD_WRITE_NEW);
		BOOST_REQUIRE_EQUAL(result.error().code(), 0);
		BOOST_REQUIRE_EQUAL(result.error().message(), "");

		auto record_info = result.record_info();

		BOOST_REQUIRE_EQUAL(record_info.user_flags, record.user_flags);
		BOOST_REQUIRE_EQUAL(record_info.record_flags, DNET_RECORD_FLAGS_EXTHDR | DNET_RECORD_FLAGS_CHUNKED_CSUM | DNET_RECORD_FLAGS_UNCOMMITTED);

		BOOST_REQUIRE_EQUAL(dnet_time_cmp(&record_info.json_timestamp, &record.timestamp), 0);
		constexpr uint64_t eblob_headers_size = sizeof(eblob_disk_control) + sizeof(dnet_ext_list_hdr);
		BOOST_REQUIRE(record_info.json_offset >= eblob_headers_size);
		BOOST_REQUIRE_EQUAL(record_info.json_size, record.json.size());
		BOOST_REQUIRE_EQUAL(record_info.json_capacity, record.json_capacity);

		BOOST_REQUIRE_EQUAL(dnet_time_cmp(&record_info.data_timestamp, &record.timestamp), 0);
		BOOST_REQUIRE_EQUAL(record_info.data_offset, record_info.json_offset + record.json_capacity);
		BOOST_REQUIRE_EQUAL(record_info.data_size, 0);
		++count;
	}
	BOOST_REQUIRE_EQUAL(count, groups.size());

	async = s.write_commit(record.key,
	                       record.json,
	                       record.data, 2*record.data.size(), 3*record.data.size());

	count = 0;
	for (const auto &result: async) {
		(void)result.address();
		BOOST_REQUIRE_EQUAL(result.status(), 0);
		BOOST_REQUIRE_EQUAL(result.command()->cmd, DNET_CMD_WRITE_NEW);
		BOOST_REQUIRE_EQUAL(result.error().code(), 0);
		BOOST_REQUIRE_EQUAL(result.error().message(), "");

		auto record_info = result.record_info();

		BOOST_REQUIRE_EQUAL(record_info.user_flags, record.user_flags);
		BOOST_REQUIRE_EQUAL(record_info.record_flags, DNET_RECORD_FLAGS_EXTHDR | DNET_RECORD_FLAGS_CHUNKED_CSUM);

		BOOST_REQUIRE_EQUAL(dnet_time_cmp(&record_info.json_timestamp, &record.timestamp), 0);
		constexpr uint64_t eblob_headers_size = sizeof(eblob_disk_control) + sizeof(dnet_ext_list_hdr);
		BOOST_REQUIRE(record_info.json_offset >= eblob_headers_size);
		BOOST_REQUIRE_EQUAL(record_info.json_size, record.json.size());
		BOOST_REQUIRE_EQUAL(record_info.json_capacity, record.json_capacity);

		BOOST_REQUIRE_EQUAL(dnet_time_cmp(&record_info.data_timestamp, &record.timestamp), 0);
		BOOST_REQUIRE_EQUAL(record_info.data_offset, record_info.json_offset + record.json_capacity);
		BOOST_REQUIRE_EQUAL(record_info.data_size, 3*record.data.size());
		++count;
	}
	BOOST_REQUIRE_EQUAL(count, groups.size());
}

void test_old_write_new_read_compatibility() {
	static const ioremap::elliptics::key key{"test_old_write_new_read_compatibility's key"};
	static const std::string data{"test_old_write_new_read_compatibility's data"};
	constexpr uint64_t user_flags = 0xfc1234;
	constexpr dnet_time timestamp{1, 2};
	constexpr dnet_time empty_time{0, 0};
	constexpr uint64_t record_flags = DNET_RECORD_FLAGS_EXTHDR | DNET_RECORD_FLAGS_CHUNKED_CSUM;
	constexpr uint64_t eblob_headers_size = sizeof(eblob_disk_control) + sizeof(dnet_ext_list_hdr);
	{
		ioremap::elliptics::session s(*servers->node);
		s.set_groups(groups);
		s.set_user_flags(user_flags);
		s.set_timestamp(timestamp);

		auto async = s.write_data(key, data, 0);

		size_t count = 0;
		for (const auto &result: async) {
			(void)result.storage_address();

			auto file_info = result.file_info();
			BOOST_REQUIRE(file_info != nullptr);

			BOOST_REQUIRE_EQUAL(file_info->record_flags, record_flags);
			BOOST_REQUIRE_EQUAL(file_info->size, data.size());
			BOOST_REQUIRE(file_info->offset >= eblob_headers_size);
			BOOST_REQUIRE_EQUAL(dnet_time_cmp(&file_info->mtime, &timestamp), 0);
			++count;
		}

		BOOST_REQUIRE_EQUAL(count, groups.size());
	}

	{
		ioremap::elliptics::newapi::session s(*servers->node);
		s.set_groups(groups);

		auto async = s.lookup(key);

		size_t count = 0;
		for (const auto &result: async) {
			(void)result.address();

			auto record_info = result.record_info();

			BOOST_REQUIRE_EQUAL(record_info.user_flags, user_flags);
			BOOST_REQUIRE_EQUAL(record_info.record_flags, record_flags);

			BOOST_REQUIRE_EQUAL(dnet_time_cmp(&record_info.json_timestamp, &empty_time), 0);
			BOOST_REQUIRE(record_info.json_offset >= eblob_headers_size);
			BOOST_REQUIRE_EQUAL(record_info.json_size, 0);
			BOOST_REQUIRE_EQUAL(record_info.json_capacity, 0);

			BOOST_REQUIRE_EQUAL(dnet_time_cmp(&record_info.data_timestamp, &timestamp), 0);
			BOOST_REQUIRE_EQUAL(record_info.data_offset, record_info.json_offset);
			BOOST_REQUIRE_EQUAL(record_info.data_size, data.size());

			++count;
		}

		BOOST_REQUIRE_EQUAL(count, 1);
	}

	{
		ioremap::elliptics::newapi::session s(*servers->node);
		s.set_groups(groups);

		auto async = s.read_json(key);

		size_t count = 0;
		for (const auto &result: async) {
			(void)result.address();

			auto record_info = result.record_info();

			BOOST_REQUIRE_EQUAL(record_info.user_flags, user_flags);
			BOOST_REQUIRE_EQUAL(record_info.record_flags, record_flags);

			BOOST_REQUIRE_EQUAL(dnet_time_cmp(&record_info.json_timestamp, &empty_time), 0);
			BOOST_REQUIRE_EQUAL(record_info.json_offset, 0);
			BOOST_REQUIRE_EQUAL(record_info.json_size, 0);
			BOOST_REQUIRE_EQUAL(record_info.json_capacity, 0);

			BOOST_REQUIRE_EQUAL(dnet_time_cmp(&record_info.data_timestamp, &timestamp), 0);
			BOOST_REQUIRE_EQUAL(record_info.data_offset, 0);
			BOOST_REQUIRE_EQUAL(record_info.data_size, data.size());

			BOOST_REQUIRE(result.json().empty());
			BOOST_REQUIRE(result.data().empty());

			auto io_info = result.io_info();

			BOOST_REQUIRE_EQUAL(io_info.json_size, 0);
			BOOST_REQUIRE_EQUAL(io_info.data_offset, 0);
			BOOST_REQUIRE_EQUAL(io_info.data_size, 0);

			++count;
		}

		BOOST_REQUIRE_EQUAL(count, 1);
	}

	{
		ioremap::elliptics::newapi::session s(*servers->node);
		s.set_groups(groups);

		auto async = s.read(key, 0, 0);

		size_t count = 0;
		for (const auto &result: async) {
			(void)result.address();
			BOOST_REQUIRE_EQUAL(result.status(), 0);
			BOOST_REQUIRE_EQUAL(result.command()->cmd, DNET_CMD_READ_NEW);
			BOOST_REQUIRE_EQUAL(result.error().code(), 0);
			BOOST_REQUIRE_EQUAL(result.error().message(), "");

			auto record_info = result.record_info();

			BOOST_REQUIRE_EQUAL(record_info.user_flags, user_flags);
			BOOST_REQUIRE_EQUAL(record_info.record_flags, record_flags);

			BOOST_REQUIRE_EQUAL(dnet_time_cmp(&record_info.json_timestamp, &empty_time), 0);
			BOOST_REQUIRE_EQUAL(record_info.json_offset, 0);
			BOOST_REQUIRE_EQUAL(record_info.json_size, 0);
			BOOST_REQUIRE_EQUAL(record_info.json_capacity, 0);

			BOOST_REQUIRE_EQUAL(dnet_time_cmp(&record_info.data_timestamp, &timestamp), 0);
			BOOST_REQUIRE_EQUAL(record_info.data_offset, 0);
			BOOST_REQUIRE_EQUAL(record_info.data_size, data.size());

			BOOST_REQUIRE(result.json().empty());
			BOOST_REQUIRE_EQUAL(result.data().to_string(), data);

			auto io_info = result.io_info();

			BOOST_REQUIRE_EQUAL(io_info.json_size, 0);
			BOOST_REQUIRE_EQUAL(io_info.data_offset, 0);
			BOOST_REQUIRE_EQUAL(io_info.data_size, data.size());

			++count;
		}

		BOOST_REQUIRE_EQUAL(count, 1);
	}
}

void test_new_write_old_read_compatibility() {
	static const ioremap::elliptics::key key{"test_new_write_old_read_compatibility's key"};
	static const std::string json{"{\"some_field\":\"some_field's data\"}"};
	uint64_t json_capacity = 100;
	static const std::string data{"test_new_write_old_read_compatibility's data"};
	uint64_t data_capacity = 200;
	constexpr uint64_t user_flags = 0xfc1234;
	constexpr dnet_time timestamp{1, 2};
	constexpr uint64_t record_flags = DNET_RECORD_FLAGS_EXTHDR | DNET_RECORD_FLAGS_CHUNKED_CSUM;
	constexpr uint64_t eblob_headers_size = sizeof(eblob_disk_control) + sizeof(dnet_ext_list_hdr);

	{
		ioremap::elliptics::newapi::session s(*servers->node);
		s.set_groups(groups);
		s.set_user_flags(user_flags);

		s.set_timestamp(timestamp);

		auto async = s.write(key,
		                     json, json_capacity,
		                     data, data_capacity);
		size_t count = 0;
		for (const auto &result: async) {
			(void)result.address();
			BOOST_REQUIRE_EQUAL(result.status(), 0);
			BOOST_REQUIRE_EQUAL(result.command()->cmd, DNET_CMD_WRITE_NEW);
			BOOST_REQUIRE_EQUAL(result.error().code(), 0);
			BOOST_REQUIRE_EQUAL(result.error().message(), "");

			auto record_info = result.record_info();

			BOOST_REQUIRE_EQUAL(record_info.user_flags, user_flags);
			BOOST_REQUIRE_EQUAL(record_info.record_flags, record_flags);

			BOOST_REQUIRE_EQUAL(dnet_time_cmp(&record_info.json_timestamp, &timestamp), 0);
			BOOST_REQUIRE(record_info.json_offset >= eblob_headers_size);
			BOOST_REQUIRE_EQUAL(record_info.json_size, json.size());
			BOOST_REQUIRE_EQUAL(record_info.json_capacity, json_capacity);

			BOOST_REQUIRE_EQUAL(dnet_time_cmp(&record_info.data_timestamp, &timestamp), 0);
			BOOST_REQUIRE_EQUAL(record_info.data_offset, record_info.json_offset + json_capacity);
			BOOST_REQUIRE_EQUAL(record_info.data_size, data.size());
			++count;
		}

		BOOST_REQUIRE_EQUAL(count, groups.size());
	}

	{
		ioremap::elliptics::session s(*servers->node);
		s.set_groups(groups);

		auto async = s.lookup(key);

		size_t count = 0;
		for (const auto &result: async) {
			(void)result.storage_address();

			auto file_info = result.file_info();
			BOOST_REQUIRE(file_info != nullptr);

			BOOST_REQUIRE_EQUAL(file_info->record_flags, record_flags);
			BOOST_REQUIRE_EQUAL(file_info->size, data.size());
			BOOST_REQUIRE(file_info->offset >= eblob_headers_size);
			BOOST_REQUIRE_EQUAL(dnet_time_cmp(&file_info->mtime, &timestamp), 0);

			++count;
		}

		BOOST_REQUIRE_EQUAL(count, 1);
	}

	{
		ioremap::elliptics::session s(*servers->node);
		s.set_groups(groups);

		auto async = s.read_data(key, 0, 0);

		size_t count = 0;
		for (const auto &result: async) {
			BOOST_REQUIRE_EQUAL(result.file().to_string(), data);

			auto io = result.io_attribute();

			BOOST_REQUIRE(io != nullptr);
			BOOST_REQUIRE_EQUAL(dnet_time_cmp(&io->timestamp, &timestamp), 0);
			BOOST_REQUIRE_EQUAL(io->user_flags, user_flags);
			BOOST_REQUIRE_EQUAL(io->total_size, data.size());
			BOOST_REQUIRE_EQUAL(io->record_flags, record_flags);
			BOOST_REQUIRE_EQUAL(io->offset, 0);
			BOOST_REQUIRE_EQUAL(io->size, data.size());

			++count;
		}

		BOOST_REQUIRE_EQUAL(count, 1);
	}
}

namespace test_all_with_ack_filter {
namespace bu = boost::unit_test;

record record{
	std::string{"test_write_with_all_with_ack_filter::key"},
	0xf1235f12431,
	dnet_time{100, 40},
	std::string{"{\"key\":\"test_write_with_all_with_ack_filter::key\"}"},
	100,
	std::string{"test_write_with_all_with_ack_filter::data"},
	100};

void test_write(ioremap::elliptics::newapi::session &s) {
	auto async = s.write(record.key,
	                     record.json, record.json_capacity,
	                     record.data, record.data_capacity);

	check_lookup_result(async, DNET_CMD_WRITE_NEW, record, groups.size());
}

void test_lookup(ioremap::elliptics::newapi::session &s) {
	auto async = s.lookup(record.key);

	check_lookup_result(async, DNET_CMD_LOOKUP_NEW, record, 1);
}

void test_read(ioremap::elliptics::newapi::session &s) {
		size_t count = 0;

	for (const auto &group : groups) {
		s.set_groups({group});
		auto async = s.read(record.key, 0, 0);

		for (const auto &result: async) {
			(void)result.address();
			BOOST_REQUIRE_EQUAL(result.status(), 0);
			BOOST_REQUIRE_EQUAL(result.command()->cmd, DNET_CMD_READ_NEW);
			BOOST_REQUIRE_EQUAL(result.error().code(), 0);
			BOOST_REQUIRE_EQUAL(result.error().message(), "");

			auto record_info = result.record_info();

			BOOST_REQUIRE_EQUAL(record_info.user_flags, record.user_flags);
			BOOST_REQUIRE_EQUAL(record_info.record_flags, DNET_RECORD_FLAGS_EXTHDR | DNET_RECORD_FLAGS_CHUNKED_CSUM);

			BOOST_REQUIRE_EQUAL(dnet_time_cmp(&record_info.json_timestamp, &record.timestamp), 0);
			BOOST_REQUIRE_EQUAL(record_info.json_offset, 0);
			BOOST_REQUIRE_EQUAL(record_info.json_size, record.json.size());
			BOOST_REQUIRE_EQUAL(record_info.json_capacity, record.json_capacity);

			BOOST_REQUIRE_EQUAL(dnet_time_cmp(&record_info.data_timestamp, &record.timestamp), 0);
			BOOST_REQUIRE_EQUAL(record_info.data_offset, 0);
			BOOST_REQUIRE_EQUAL(record_info.data_size, record.data.size());

			BOOST_REQUIRE_EQUAL(result.json().to_string(), record.json);
			BOOST_REQUIRE_EQUAL(result.data().to_string(), record.data);

			auto io_info = result.io_info();

			BOOST_REQUIRE_EQUAL(io_info.json_size, record.json.size());
			BOOST_REQUIRE_EQUAL(io_info.data_offset, 0);
			BOOST_REQUIRE_EQUAL(io_info.data_size, record.data.size());

			++count;
		}
	}

	BOOST_REQUIRE_EQUAL(count, groups.size());
}

void register_tests(bu::test_suite *suite) {
	ioremap::elliptics::newapi::session s(*servers->node);
	s.set_groups(groups);
	s.set_filter(ioremap::elliptics::filters::all_with_ack);
	s.set_user_flags(record.user_flags);
	s.set_timestamp(record.timestamp);

	ELLIPTICS_TEST_CASE(test_write, s);
	ELLIPTICS_TEST_CASE(test_lookup, s);
	ELLIPTICS_TEST_CASE(test_read, s);
}

} /* namespace test_all_with_ack_filter */

void register_tests(bu::test_suite *suite) {
	record record{
		std::string{"key"},
		0xff1ff2ff3,
		dnet_time{10, 20},
		std::string{"{\"key\": \"key\"}"},
		512,
		std::string{"key data"},
		1024};

	ELLIPTICS_TEST_CASE(test_write, record);
	ELLIPTICS_TEST_CASE(test_lookup, record);
	ELLIPTICS_TEST_CASE(test_read_json, record);
	ELLIPTICS_TEST_CASE(test_read_data, record, 0, 0);
	ELLIPTICS_TEST_CASE(test_read_data, record, 0, 1);
	ELLIPTICS_TEST_CASE(test_read_data, record, 0, std::numeric_limits<uint64_t>::max());
	ELLIPTICS_TEST_CASE(test_read_data, record, 1, 0);
	ELLIPTICS_TEST_CASE(test_read_data, record, 2, 1);
	ELLIPTICS_TEST_CASE(test_read_data, record, 3, std::numeric_limits<uint64_t>::max());
	ELLIPTICS_TEST_CASE(test_read, record, 0, 0);
	ELLIPTICS_TEST_CASE(test_read, record, 0, 1);
	ELLIPTICS_TEST_CASE(test_read, record, 0, std::numeric_limits<uint64_t>::max());
	ELLIPTICS_TEST_CASE(test_read, record, 1, 0);
	ELLIPTICS_TEST_CASE(test_read, record, 2, 1);
	ELLIPTICS_TEST_CASE(test_read, record, 3, std::numeric_limits<uint64_t>::max());

	record.key = {"chunked_key"};
	ELLIPTICS_TEST_CASE(test_write_chunked, record);

	ELLIPTICS_TEST_CASE_NOARGS(test_old_write_new_read_compatibility);
	ELLIPTICS_TEST_CASE_NOARGS(test_new_write_old_read_compatibility);
}

bu::test_suite *setup_tests(int argc, char *argv[]) {
	namespace bpo = boost::program_options;

	bpo::variables_map vm;
	bpo::options_description generic("Test options");

	std::string path;

	generic.add_options()
		("help", "This help message")
		("path", bpo::value(&path), "Path where to store everything")
		;

	bpo::store(bpo::parse_command_line(argc, argv, generic), vm);
	bpo::notify(vm);

	if (vm.count("help")) {
		std::cerr << generic;
		return nullptr;
	}

	auto suite = new bu::test_suite("Local Test Suite");

	configure_servers(path);
	register_tests(suite);
	test_all_with_ack_filter::register_tests(suite);

	return suite;
}

} // namespace

int main(int argc, char *argv[]) {
	atexit([] { servers.reset(); });

	srand(time(0));
	return bu::unit_test_main(setup_tests, argc, argv);
}
