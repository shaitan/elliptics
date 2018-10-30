#include <boost/program_options.hpp>

#define BOOST_TEST_NO_MAIN
#define BOOST_TEST_ALTERNATIVE_INIT_API
#include <boost/test/included/unit_test.hpp>

#include <chrono>
#include <thread>

#include "elliptics/newapi/session.hpp"
#include "example/eblob_backend.h"

#include "test_base.hpp"

namespace {

namespace bu = boost::unit_test;

namespace constants {

static const int src_group = 1;
static const std::vector<int> dst_groups{2/*, 3*/};

static const uint64_t json_capacity = 300;
static const uint64_t data_capacity = 300;

static const char key_prefix[] = "new_api_server_send_test key prefix ";
static const char data_prefix[] = "new_api_server_send_test data prefix ";

}

tests::nodes_data::ptr configure_test_setup(const std::string &path) {
	auto server_config = [] (const tests::config_data &c) {
		return tests::server_config::default_value().apply_options(c);
	};

	// config for a server with backend limited by 1 byte space
	// used for tests that covers -ENOSPC cases
	auto limited_server_config = [&] (const tests::config_data &c) {
		auto server = server_config(c);
		server.backends[0]("blob_size_limit", 1);
		return server;
	};

	auto configs = {
		server_config(tests::config_data()("group", 1)),
		server_config(tests::config_data()("group", 2)),
		server_config(tests::config_data()("group", 3)),
		limited_server_config(tests::config_data()("group", 4)),
	};

	tests::start_nodes_config config{
		bu::results_reporter::get_stream(),
		configs,
		path
	};

	return tests::start_nodes(config);
}

// struct record_state {
// 	enum class freshness {
// 		MISSED,
// 		OLD,
// 		REGULAR,
// 		NEW,
// 	};

// 	freshness json_freshness;
// 	freshness data_freshness;
// 	bool committed;
// };

// static const std::vector<record_state> possible_states{
// {record_state::freshness::MISSED,	record_state::freshness::MISSED,	true},	// nonexistent record
// // state below duplicates state above, because missed key is missed and its commitness does not matter.
// // {record_state::freshness::MISSED,	record_state::freshness::MISSED,	false},	// record does not exist
// {record_state::freshness::MISSED,	record_state::freshness::OLD,		true},	// committed record with old data and without json
// {record_state::freshness::MISSED,	record_state::freshness::OLD,		false},	// uncommitted record with old data and without json
// {record_state::freshness::MISSED,	record_state::freshness::REGULAR,	true},	// committed record with regular data and without json
// {record_state::freshness::MISSED,	record_state::freshness::REGULAR,	false},	// committed record with regular data and without json
// {record_state::freshness::MISSED,	record_state::freshness::NEW,		true},	// committed record with new data and without json
// {record_state::freshness::MISSED,	record_state::freshness::NEW,		false},	// committed record with new data and without json

// {record_state::freshness::OLD,		record_state::freshness::MISSED,	true},	// committed record with old json and without data
// {record_state::freshness::OLD,		record_state::freshness::MISSED,	false},	// uncommitted record with old json and without data
// {record_state::freshness::OLD,		record_state::freshness::OLD,		true},	// committed record with old data and old json
// {record_state::freshness::OLD,		record_state::freshness::OLD,		false},	// uncommitted record with old data and old json
// // states below are disabled because currently it is impossible to make json older than data
// // {record_state::freshness::OLD,	record_state::freshness::REGULAR,	true},	// committed record with regular data and old json
// // {record_state::freshness::OLD,	record_state::freshness::REGULAR,	false},	// committed record with regular data and old json
// // {record_state::freshness::OLD,	record_state::freshness::NEW,		true},	// committed record with new data and old json
// // {record_state::freshness::OLD,	record_state::freshness::NEW,		false},	// committed record with new data and old json

// {record_state::freshness::REGULAR,	record_state::freshness::MISSED,	true},	// committed record with regular json and without data
// {record_state::freshness::REGULAR,	record_state::freshness::MISSED,	false},	// uncommitted record with regular json and without data
// {record_state::freshness::REGULAR,	record_state::freshness::OLD,		true},	// committed record with old data and regular json
// {record_state::freshness::REGULAR,	record_state::freshness::OLD,		false},	// uncommitted record with old data and regular json
// {record_state::freshness::REGULAR,	record_state::freshness::REGULAR,	true},	// committed record with regular data and regular json
// {record_state::freshness::REGULAR,	record_state::freshness::REGULAR,	false},	// committed record with regular data and regular json
// // states below are disabled because currently it is impossible to make json older than data
// // {record_state::freshness::REGULAR,	record_state::freshness::NEW,		true},	// committed record with new data and regular json
// // {record_state::freshness::REGULAR,	record_state::freshness::NEW,		false},	// committed record with new data and regular json

// {record_state::freshness::NEW,		record_state::freshness::MISSED,	true},	// committed record with new json and without data
// {record_state::freshness::NEW,		record_state::freshness::MISSED,	false},	// uncommitted record with new json and without data
// {record_state::freshness::NEW,		record_state::freshness::OLD,		true},	// committed record with old data and new json
// {record_state::freshness::NEW,		record_state::freshness::OLD,		false},	// uncommitted record with old data and new json
// {record_state::freshness::NEW,		record_state::freshness::REGULAR,	true},	// committed record with regular data and new json
// {record_state::freshness::NEW,		record_state::freshness::REGULAR,	false},	// committed record with regular data and new json
// {record_state::freshness::NEW,		record_state::freshness::NEW,		true},	// committed record with new data and new json
// {record_state::freshness::NEW,		record_state::freshness::NEW,		false},	// committed record with new data and new json
// };

// class record {
// public:
// 	record(const ioremap::elliptics::newapi::session &session, size_t state_index, size_t global_index)
// 	: m_session(session)
// 	, m_state(possible_states[state_index])
// 	, m_state_index(state_index)
// 	, m_global_index(global_index) {
// 	}

// 	std::string key() const {
// 		return constants::key_prefix + std::to_string(m_global_index);
// 	}

// 	dnet_raw_id raw_key() const {
// 		dnet_raw_id ret;
// 		m_session.transform(key(), ret);
// 		return ret;
// 	}

// 	std::string json() const {
// 		if (!has_json()) {
// 			return std::string();
// 		}

// 		std::ostringstream str;
// 		str << "{"
// 			<< "\"key\":\"" << key() << "\","
// 			<< "\"index\":\"" << std::to_string(m_global_index) << "\""
// 		<< "}";
// 		return str.str();
// 	}

// 	std::string data() const {
// 		if (!has_data()) {
// 			return std::string();
// 		}
// 		return constants::data_prefix + std::to_string(m_global_index);
// 	}

// 	uint64_t json_capacity() const {
// 		return has_json() ? constants::json_capacity : 0;
// 	}

// 	uint64_t data_capacity() const {
// 		return has_data() ? constants::data_capacity : 0;
// 	}

// 	uint64_t flags() const {
// 		if (is_missed()) {
// 			return 0;
// 		}

// 		uint64_t ret = DNET_RECORD_FLAGS_EXTHDR |
// 		               DNET_RECORD_FLAGS_CHUNKED_CSUM;
// 		if (!m_state.committed) {
// 			ret |= DNET_RECORD_FLAGS_UNCOMMITTED;
// 		}
// 		return ret;
// 	}

// 	dnet_time json_ts() const {
// 		return ts(m_state.json_freshness);
// 	}

// 	dnet_time data_ts() const {
// 		return ts(m_state.data_freshness);
// 	}

// 	bool is_missed() const {
// 		return !has_json() && !has_data();
// 	}

// private:
// 	static dnet_time ts(const record_state::freshness &freshness) {
// 		switch(freshness) {
// 			case record_state::freshness::OLD:
// 				return dnet_time{1, 0};
// 			case record_state::freshness::REGULAR:
// 				return dnet_time{2, 0};
// 			case record_state::freshness::NEW:
// 				return dnet_time{3, 0};
// 			case record_state::freshness::MISSED:
// 			default:
// 				return dnet_time{0, 0};
// 		}
// 	}

// 	static bool has(const record_state::freshness &freshness) {
// 		switch(freshness) {
// 			case record_state::freshness::OLD:
// 			case record_state::freshness::REGULAR:
// 			case record_state::freshness::NEW:
// 				return true;
// 			case record_state::freshness::MISSED:
// 			default:
// 				return false;
// 		}
// 	}

// 	bool has_json() const {
// 		return has(m_state.json_freshness);
// 	}

// 	bool has_data() const {
// 		return has(m_state.data_freshness);
// 	}

// 	const ioremap::elliptics::newapi::session &m_session;
// 	const record_state m_state;
// 	const size_t m_state_index;
// 	const size_t m_global_index;
// };

// class test_dataset {
// public:
// 	test_dataset(const ioremap::elliptics::newapi::session &session, size_t replicas_num)
// 	: m_session(session)
// 	, m_replicas_num(replicas_num) {
// 		assert(m_replicas_num < 4);
// 	}

// 	std::vector<record> replicas(size_t index) const {
// 		std::vector<record> ret;
// 		ret.reserve(m_replicas_num);

// 		const size_t global_index = index;
// 		for (size_t i = 0; i < m_replicas_num; ++i) {
// 			ret.emplace_back(m_session, index % possible_states.size(), global_index);
// 			index /= possible_states.size();
// 		}

// 		return ret;
// 	}

// 	size_t replicas_num() const {
// 		return m_replicas_num;
// 	}

// private:
// 	const ioremap::elliptics::newapi::session &m_session;
// 	const size_t m_replicas_num;
// };

// void test_write(const ioremap::elliptics::newapi::session &session) {
// 	size_t max_index = pow(possible_states.size(), testset.replicas_num());
// 	for (size_t i = 0; i < max_index; ++i) {
// 		for (auto &record: testset.replicas(i)) {
// 			const auto key = record.key();
// 			std::cout << record.key() << " " << record.json_capacity() << " " << record.data_capacity() << ", ";
// 		}
// 		std::cout << std::endl;
// 	}
// }

struct TestKey {
	TestKey(const std::string &id_prefix, const std::string &data_prefix, size_t key_id)
	: id(id_prefix + std::to_string(key_id))
	, data(data_prefix + std::to_string(key_id))
	, json("{\"key\": \"new_api_server_send_test::TestKey\"}")
	, data_capacity(0)
	, json_capacity(0)
	, user_flags(100500) {
	}

	std::string id;
	std::string data;
	std::string json;
	uint64_t data_capacity;
	uint64_t json_capacity;
	uint64_t user_flags;
};

std::vector<TestKey> generate_keys(const std::string &id_prefix, const std::string &data_prefix, size_t num) {
	std::vector<TestKey> keys;
	keys.reserve(num);
	for (size_t i = 0; i < num; ++i) {
		keys.emplace_back(id_prefix, data_prefix, i);
	}
	return keys;
}

void test_insert_keys(const ioremap::elliptics::newapi::session &session, const std::vector<TestKey> &keys,
		      const std::vector<int> &groups) {
	std::vector<ioremap::elliptics::newapi::async_write_result> results;

	auto s = session.clone();
	s.set_trace_id(rand());
	s.set_groups(groups);
	for (const auto &k : keys) {
		s.set_user_flags(k.user_flags);
		results.emplace_back(s.write(k.id,
					     k.json, k.json_capacity,
					     k.data, k.data_capacity));
	}

	for (size_t i = 0; i < keys.size(); ++i) {
		size_t count = 0;
		for (const auto &r : results[i]) {
			BOOST_REQUIRE_EQUAL(r.status(), 0);
			++count;
		}
		BOOST_REQUIRE_EQUAL(count, groups.size());
	}
}

void test_read_keys(const ioremap::elliptics::newapi::session &session, const std::vector<TestKey> &keys,
		    const std::vector<int> &groups) {
	for (int group_id : groups) {
		std::vector<ioremap::elliptics::newapi::async_read_result> results;

		auto s = session.clone();
		s.set_trace_id(rand());
		s.set_groups({group_id});
		for (const auto &k : keys) {
			results.emplace_back(s.read(k.id, 0, 0));
		}

		for (size_t i = 0; i < keys.size(); ++i) {
			auto &async = results[i];
			BOOST_REQUIRE_EQUAL(async.get().size(), 1);

			auto result = async.get()[0];
			BOOST_REQUIRE_EQUAL(result.status(), 0);
			BOOST_REQUIRE_EQUAL(result.json().to_string(), keys[i].json);
			BOOST_REQUIRE_EQUAL(result.data().to_string(), keys[i].data);

			auto info = result.record_info();
			BOOST_REQUIRE_EQUAL(info.user_flags, keys[i].user_flags);
		}
	}
}

void test_read_keys_error(const ioremap::elliptics::newapi::session &session, const std::vector<TestKey> &keys,
			  const std::vector<int> &groups, int expected_error) {
	for (int group_id : groups) {
		std::vector<ioremap::elliptics::newapi::async_read_result> results;

		auto s = session.clone();
		s.set_exceptions_policy(ioremap::elliptics::session::no_exceptions);
		s.set_filter(ioremap::elliptics::filters::all_with_ack);
		s.set_trace_id(rand());
		s.set_groups({group_id});
		for (const auto &k : keys) {
			results.emplace_back(s.read(k.id, 0, 0));
		}

		for (size_t i = 0; i < keys.size(); ++i) {
			auto &async = results[i];
			BOOST_REQUIRE_EQUAL(async.get().size(), 1);
			BOOST_REQUIRE_EQUAL(async.get()[0].status(), expected_error);
		}
	}
}

void test_remove_keys(const ioremap::elliptics::newapi::session &session,
                      const std::vector<TestKey> &keys,
                      const std::vector<int> &groups) {
	for (const auto &group_id : groups) {
		std::vector<ioremap::elliptics::async_remove_result> results;
		auto s = session.clone();
		s.set_filter(ioremap::elliptics::filters::all_with_ack);
		s.set_trace_id(rand());
		s.set_groups({group_id});
		for (const auto &k : keys) {
			results.emplace_back(s.remove(k.id));
		}

		for (auto &result : results) {
			BOOST_REQUIRE_EQUAL(result.get().size(), 1);

			BOOST_REQUIRE_EQUAL(result.get()[0].status(), 0);
		}
	}
}

void test_make_groups_readonly(const ioremap::elliptics::newapi::session &session,
                               const std::vector<int> &groups,
                               bool readonly) {
	std::vector<ioremap::elliptics::async_backend_control_result> results;

	auto s = session.clone();
	for (const auto &group_id : groups) {
		for (const auto &route : s.get_routes()) {
			if (route.group_id == group_id) {
				auto async = readonly ? s.make_readonly(route.addr, route.backend_id)
				                      : s.make_writable(route.addr, route.backend_id);

				BOOST_REQUIRE_EQUAL(async.get().size(), 1);
				BOOST_REQUIRE_EQUAL(async.get()[0].status(), 0);
				break;
			}
		}
	}
}

void test_chunked_server_send(const ioremap::elliptics::newapi::session &session,
                              const std::vector<TestKey> &keys,
                              int src_group,
                              const std::vector<int> &dst_groups,
                              size_t chunk_size,
                              int status) {
	auto s = session.clone();
	s.set_trace_id(rand());
	s.set_groups({src_group});
	s.set_exceptions_policy(ioremap::elliptics::session::no_exceptions);

	std::vector<std::string> key_ids;
	key_ids.reserve(keys.size());
	for (const auto &k : keys) {
		key_ids.push_back(k.id);
	}

	auto async = s.server_send(key_ids,
	                           /*flags*/ 0,
	                           chunk_size,
	                           src_group,
	                           dst_groups,
	                           DNET_DEFAULT_SERVER_SEND_CHUNK_WRITE_TIMEOUT,
	                           DNET_DEFAULT_SERVER_SEND_CHUNK_COMMIT_TIMEOUT);

	size_t counter = 0;
	for (const auto &result : async) {
		BOOST_REQUIRE_EQUAL(result.status(), status);
		++counter;
	}
	BOOST_REQUIRE_EQUAL(keys.size(), counter);
}

void test_simple_server_send(const ioremap::elliptics::newapi::session &session/*, const test_dataset &testset*/) {
	static const std::string key = "new_api_server_send_test::test_simple_server_send key";
	static const std::string json = "{\"key\": \"new_api_server_send_test::test_simple_server_send key\"}";
	static const std::string data = "new_api_server_send_test::test_simple_server_send data";
	static const dnet_time timestamp{10, 0};
	static const uint64_t user_flags = 100500;

	auto s = session.clone();
	s.set_trace_id(rand());
	s.set_groups({constants::src_group});
	s.set_timestamp(timestamp);
	s.set_user_flags(user_flags);

	// write the key into src_group
	{
		ELLIPTICS_REQUIRE(res, s.write(key,
		                               json, 1024,
		                               data, 1024));
	}

	// check via read the key's availability in src_group
	{
		ELLIPTICS_REQUIRE(res, s.read(key, 0, 0));
	}

	s.set_exceptions_policy(ioremap::elliptics::session::no_exceptions);
	// check via read that the key is missed in all dst_groups
	{
		s.set_groups(constants::dst_groups);
		auto async = s.read(key, 0, 0);
		async.wait();
		BOOST_REQUIRE_EQUAL(async.error().code(), -ENOENT);
	}

	// send the key via server_send from src_group to dst_groups
	{
		auto async = s.server_send(std::vector<std::string>{key}, 0 /*flags*/,
		                           DNET_DEFAULT_SERVER_SEND_CHUNK_SIZE,
		                           constants::src_group, constants::dst_groups,
		                           DNET_DEFAULT_SERVER_SEND_CHUNK_WRITE_TIMEOUT,
		                           DNET_DEFAULT_SERVER_SEND_CHUNK_COMMIT_TIMEOUT);

		dnet_raw_id raw_key;
		s.transform(key, raw_key);
		size_t counter = 0;
		for (const auto &result: async) {
			BOOST_REQUIRE_EQUAL(result.iterator_id(), 0);
			BOOST_REQUIRE_EQUAL(result.key(), raw_key);
			BOOST_REQUIRE_EQUAL(result.status(), 0);
			++counter;
		}
		BOOST_REQUIRE_EQUAL(counter, 1);
		// async.wait();
		// BOOST_REQUIRE_EQUAL(async.error().code(), 0);
	}

	// check via read that the key is available and correct in both replicas
	{
		std::vector<int> groups = constants::dst_groups;
		groups.emplace_back(constants::src_group);

		for (const auto &group: groups) {
			s.set_groups({group});
			auto async = s.read(key, 0, 0);

			size_t counter = 0;
			for (const auto &result: async) {
				BOOST_REQUIRE_EQUAL(result.json().to_string(), json);
				BOOST_REQUIRE_EQUAL(result.data().to_string(), data);
				BOOST_REQUIRE_EQUAL(result.record_info().data_timestamp, timestamp);
				BOOST_REQUIRE_EQUAL(result.record_info().json_timestamp, timestamp);
				BOOST_REQUIRE_EQUAL(result.record_info().user_flags, user_flags);
				++counter;
			}
			BOOST_REQUIRE_EQUAL(async.error().code(), 0);
			BOOST_REQUIRE_EQUAL(counter, 1);
		}
	}
}

using namespace tests;

// Check the case when first write is timed-out and second is successful.
// The key should be written.
void test_send_with_successful_retry(ioremap::elliptics::newapi::session &session,
                                     ioremap::elliptics::key key,
                                     const nodes_data *setup,
                                     bool chunked,
                                     uint8_t retry_count) {
	static const std::string json =
		R"({"key": "new_api_server_send_test::test_send_with_successful_retry key"})";
	static const std::string data =
		"new_api_server_send_test::test_send_with_successful_retry data";
	constexpr dnet_time timestamp{11, 0};
	constexpr uint64_t user_flags = 100501;

	constexpr int src_group = 1;
	constexpr int dst_group = 2;

	const auto delayed_remote = setup->nodes[1].remote();
	constexpr uint32_t delayed_backend = 0;

	session.transform(key);
	session.set_exceptions_policy(ioremap::elliptics::session::no_exceptions);
	session.set_groups({src_group});
	session.set_timestamp(timestamp);
	session.set_user_flags(user_flags);

	{
		// write the key into src_group
		ELLIPTICS_REQUIRE(async, session.write(key, json, 1024, data, 1024));
	}

	session.set_delay(delayed_remote, delayed_backend, 3000).wait();

	{
		const uint64_t chunk_size = chunked ? (data.size() / 2) : DNET_DEFAULT_SERVER_SEND_CHUNK_SIZE;
		auto async = session.server_send({key}, 0 /*flags*/,
		                                 chunk_size,
		                                 src_group, std::vector<int>{dst_group},
		                                 2000 /* 1s */,
		                                 2000 /* 1s */,
		                                 retry_count /* chunk_retry_count */);

		// sleep to give a time for server-send to send first write
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
		// reset delay, so when server-send will retry write, it won't be timed-out
		session.set_delay(delayed_remote, delayed_backend, 0).wait();

		auto results = async.get();
		BOOST_REQUIRE_EQUAL(results.size(), 1);
		auto &result = results.front();

		BOOST_REQUIRE_EQUAL(result.iterator_id(), 0);
		BOOST_REQUIRE_EQUAL(result.key(), key.raw_id());
		BOOST_REQUIRE_EQUAL(result.status(), 0);
	}

	// reset delay
	session.set_delay(delayed_remote, delayed_backend, 0).wait();

	{
		constexpr std::array<int, 2> groups{src_group, dst_group};
		for (const auto group: groups) {
			auto s = session.clone();
			s.set_groups({group});
			ELLIPTICS_REQUIRE(async, s.read(key, 0, 0));
			auto result = async.get().front();
			BOOST_REQUIRE_EQUAL(result.data().to_string(), data);
			BOOST_REQUIRE_EQUAL(result.record_info().data_timestamp, timestamp);

			BOOST_REQUIRE_EQUAL(result.json().to_string(), json);
			BOOST_REQUIRE_EQUAL(result.record_info().json_capacity, 1024);
			BOOST_REQUIRE_EQUAL(result.record_info().json_timestamp, timestamp);

			BOOST_REQUIRE_EQUAL(result.record_info().user_flags, user_flags);
		}
	}
}

// Check the case when all tries are failed with -ETIMEDOUT.
// Server-send should respond with -ETIMEDOUT and original replica should be changed.
void test_send_failed_with_ETIMEDOUT(ioremap::elliptics::newapi::session &session,
                                     ioremap::elliptics::key key,
                                     const nodes_data *setup,
                                     bool chunked,
                                     uint8_t retry_count) {
	static const std::string json =
		R"({"key": "new_api_server_send_test::test_send_failed_with_ETIMEDOUT key"})";
	static const std::string data =
		"new_api_server_send_test::test_send_failed_with_ETIMEDOUT data";
	constexpr dnet_time timestamp{11, 0};
	constexpr uint64_t user_flags = 100501;

	constexpr int src_group = 1;
	constexpr int dst_group = 2;

	const auto delayed_remote = setup->nodes[1].remote();
	constexpr uint32_t delayed_backend = 0;

	session.transform(key);
	session.set_exceptions_policy(ioremap::elliptics::session::no_exceptions);
	session.set_groups({src_group});
	session.set_timestamp(timestamp);
	session.set_user_flags(user_flags);

	{
		// write the key into src_group
		ELLIPTICS_REQUIRE(async, session.write(key, json, 1024, data, 1024));
	}

	session.set_delay(delayed_remote, delayed_backend, 2000).wait();

	{
		const uint64_t chunk_size = chunked ? (data.size() / 2) : DNET_DEFAULT_SERVER_SEND_CHUNK_SIZE;
		auto async = session.server_send({key}, 0 /*flags*/,
		                                 chunk_size,
		                                 src_group, std::vector<int>{dst_group},
		                                 1000 /* 1s */,
		                                 1000 /* 1s */,
		                                 retry_count /* chunk_retry_count */);

		auto results = async.get();
		BOOST_REQUIRE_EQUAL(results.size(), 1);
		auto &result = results.front();

		BOOST_REQUIRE_EQUAL(result.iterator_id(), 0);
		BOOST_REQUIRE_EQUAL(result.key(), key.raw_id());
		BOOST_REQUIRE_EQUAL(result.status(), -ETIMEDOUT);
	}

	// reset delay
	session.set_delay(delayed_remote, delayed_backend, 0).wait();

	{
		auto s = session.clone();
		s.set_groups({src_group});
		ELLIPTICS_REQUIRE(async, s.read(key, 0, 0));
		auto result = async.get().front();
		BOOST_REQUIRE_EQUAL(result.data().to_string(), data);
		BOOST_REQUIRE_EQUAL(result.record_info().data_timestamp, timestamp);

		BOOST_REQUIRE_EQUAL(result.json().to_string(), json);
		BOOST_REQUIRE_EQUAL(result.record_info().json_capacity, 1024);
		BOOST_REQUIRE_EQUAL(result.record_info().json_timestamp, timestamp);

		BOOST_REQUIRE_EQUAL(result.record_info().user_flags, user_flags);
	}

	// sleep for removing affects from hanging request
	// sleep for 1 second, because server_send retried write once and it took double delay (3 seconds)
	// to handle them, but 2 seconds has already passed by server-send
	std::this_thread::sleep_for(std::chrono::seconds{retry_count + 1});

}

// Check the case when destination group aren't available(corresponding backend is disabled).
// Server-send should respond with -ENXIO and original replica shouldn't be changed.
void test_send_failed_with_ENXIO(ioremap::elliptics::newapi::session &session,
                                 ioremap::elliptics::key key,
                                 const nodes_data *setup,
                                 bool chunked,
                                 uint8_t retry_count) {
	static const std::string json = R"({"key": "test_send_failed_with_ENXIO key"})";
	static const std::string data = "test_send_failed_with_ENXIO data";
	constexpr dnet_time timestamp{11, 0};
	constexpr uint64_t user_flags = 100501;

	constexpr int src_group = 1;
	constexpr int dst_group = 2;

	// victim's address and backend_id
	const auto victim_address = setup->nodes[1].remote();
	constexpr uint32_t victim_backend_id = 0;

	session.transform(key);
	session.set_exceptions_policy(ioremap::elliptics::session::no_exceptions);
	session.set_groups({src_group});
	session.set_timestamp(timestamp);
	session.set_user_flags(user_flags);

	{
		// write the key into src_group
		ELLIPTICS_REQUIRE(async, session.write(key, json, 1024, data, 1024));
	}

	// disable backend, so victim_group become unavailable
	session.disable_backend(victim_address, victim_backend_id).wait();

	{
		const uint64_t chunk_size = chunked ? (data.size() / 2) : DNET_DEFAULT_SERVER_SEND_CHUNK_SIZE;
		auto async = session.server_send({key}, 0 /*flags*/,
		                                 chunk_size,
		                                 src_group, std::vector<int>{dst_group},
		                                 1000 /* 1s */,
		                                 1000 /* 1s */,
		                                 retry_count /* chunk_retry_count */);

		auto results = async.get();
		BOOST_REQUIRE_EQUAL(results.size(), 1);
		auto &result = results.front();

		BOOST_REQUIRE_EQUAL(result.iterator_id(), 0);
		BOOST_REQUIRE_EQUAL(result.key(), key.raw_id());
		BOOST_REQUIRE_EQUAL(result.status(), -ENXIO);

		// backend's absence should be checked fast and without retries
		BOOST_REQUIRE_EQUAL(async.elapsed_time().tsec, 0);
	} {
		auto s = session.clone();
		s.set_groups({src_group});
		ELLIPTICS_REQUIRE(async, s.read(key, 0, 0));
		auto result = async.get().front();
		BOOST_REQUIRE_EQUAL(result.data().to_string(), data);
		BOOST_REQUIRE_EQUAL(result.record_info().data_timestamp, timestamp);

		BOOST_REQUIRE_EQUAL(result.json().to_string(), json);
		BOOST_REQUIRE_EQUAL(result.record_info().json_capacity, 1024);
		BOOST_REQUIRE_EQUAL(result.record_info().json_timestamp, timestamp);

		BOOST_REQUIRE_EQUAL(result.record_info().user_flags, user_flags);
	}

	// enable backend back
	session.enable_backend(victim_address, victim_backend_id).wait();
}

// Check the case when destination group is in read-only mode.
// Server-send should fail with -EROFS and original replica should be changed.
void test_send_failed_with_EROFS(ioremap::elliptics::newapi::session &session,
                                 ioremap::elliptics::key key,
                                 const nodes_data *setup,
                                 bool chunked,
                                 uint8_t retry_count) {
	static const std::string json = R"({"key": "test_send_failed_with_EROFS key"})";
	static const std::string data = "test_send_failed_with_EROFS data";
	constexpr dnet_time timestamp{11, 0};
	constexpr uint64_t user_flags = 100501;

	constexpr int src_group = 1;
	constexpr int dst_group = 2;

	// victim's address and backend_id
	const auto victim_address = setup->nodes[1].remote();
	constexpr uint32_t victim_backend_id = 0;

	session.transform(key);
	session.set_exceptions_policy(ioremap::elliptics::session::no_exceptions);
	session.set_groups({src_group});
	session.set_timestamp(timestamp);
	session.set_user_flags(user_flags);

	{
		// write the key into src_group
		ELLIPTICS_REQUIRE(async, session.write(key, json, 1024, data, 1024));
	}

	// turn RO on backend
	session.make_readonly(victim_address, victim_backend_id).wait();

	{
		const uint64_t chunk_size = chunked ? (data.size() / 2) : DNET_DEFAULT_SERVER_SEND_CHUNK_SIZE;
		auto async = session.server_send({key}, 0 /*flags*/,
		                                 chunk_size,
		                                 src_group, std::vector<int>{dst_group},
		                                 1000 /* 1s */,
		                                 1000 /* 1s */,
		                                 retry_count /* chunk_retry_count */);

		auto results = async.get();
		BOOST_REQUIRE_EQUAL(results.size(), 1);
		auto &result = results.front();

		BOOST_REQUIRE_EQUAL(result.iterator_id(), 0);
		BOOST_REQUIRE_EQUAL(result.key(), key.raw_id());
		BOOST_REQUIRE_EQUAL(result.status(), -EROFS);

		// backend's absence should be checked fast and without retries
		BOOST_REQUIRE_EQUAL(async.elapsed_time().tsec, 0);
	} {
		auto s = session.clone();
		s.set_groups({src_group});
		ELLIPTICS_REQUIRE(async, s.read(key, 0, 0));
		auto result = async.get().front();
		BOOST_REQUIRE_EQUAL(result.data().to_string(), data);
		BOOST_REQUIRE_EQUAL(result.record_info().data_timestamp, timestamp);

		BOOST_REQUIRE_EQUAL(result.json().to_string(), json);
		BOOST_REQUIRE_EQUAL(result.record_info().json_capacity, 1024);
		BOOST_REQUIRE_EQUAL(result.record_info().json_timestamp, timestamp);

		BOOST_REQUIRE_EQUAL(result.record_info().user_flags, user_flags);
	}

	// revert RO on backend
	session.make_writable(victim_address, victim_backend_id).wait();
}

// Check the case when destination group has newer replica.
// Server-send should respond with -EBADFD and both replicas shouldn't be changed.
void test_send_failed_with_EBADFD(ioremap::elliptics::newapi::session &session,
                                  ioremap::elliptics::key key,
                                  bool chunked,
                                  uint8_t retry_count) {
	static const std::string json = R"({"key": "test_send_failed_with_EBADFD key"})";
	static const std::string data = "test_send_failed_with_EBADFD data";

	constexpr dnet_time src_timestamp{11, 0};
	constexpr dnet_time dst_timestamp{src_timestamp.tsec, src_timestamp.tnsec + 1};

	constexpr uint64_t src_user_flags = 100501;
	constexpr uint64_t dst_user_flags = src_user_flags + 1;

	constexpr int src_group = 1;
	constexpr int dst_group = 2;

	session.transform(key);
	session.set_exceptions_policy(ioremap::elliptics::session::no_exceptions);
	session.set_groups({src_group});
	session.set_timestamp(src_timestamp);
	session.set_user_flags(src_user_flags);

	{
		// write the key into src_group
		ELLIPTICS_REQUIRE(async, session.write(key, json, 1024, data, 1024));
	} {
		// write the key into dst_group with higher timestamp
		auto s = session.clone();
		s.set_timestamp(dst_timestamp);
		s.set_groups({dst_group});
		s.set_user_flags(dst_user_flags);
		ELLIPTICS_REQUIRE(async, s.write(key, json, 1024, data, 1024));
	} {
		const uint64_t chunk_size = chunked ? (data.size() / 2) : DNET_DEFAULT_SERVER_SEND_CHUNK_SIZE;
		auto async = session.server_send({key}, 0 /*flags*/,
		                                 chunk_size,
		                                 src_group, std::vector<int>{dst_group},
		                                 1000 /* 1s */,
		                                 1000 /* 1s */,
		                                 retry_count /* chunk_retry_count */);

		auto results = async.get();
		BOOST_REQUIRE_EQUAL(results.size(), 1);
		auto &result = results.front();

		BOOST_REQUIRE_EQUAL(result.iterator_id(), 0);
		BOOST_REQUIRE_EQUAL(result.key(), key.raw_id());
		BOOST_REQUIRE_EQUAL(result.status(), -EBADFD);

		// backend's absence should be checked fast and without retries
		BOOST_REQUIRE_EQUAL(async.elapsed_time().tsec, 0);
	} {
		auto s = session.clone();
		s.set_groups({src_group});
		ELLIPTICS_REQUIRE(async, s.read(key, 0, 0));
		auto result = async.get().front();
		BOOST_REQUIRE_EQUAL(result.data().to_string(), data);
		BOOST_REQUIRE_EQUAL(result.record_info().data_timestamp, src_timestamp);

		BOOST_REQUIRE_EQUAL(result.json().to_string(), json);
		BOOST_REQUIRE_EQUAL(result.record_info().json_capacity, 1024);
		BOOST_REQUIRE_EQUAL(result.record_info().json_timestamp, src_timestamp);

		BOOST_REQUIRE_EQUAL(result.record_info().user_flags, src_user_flags);
	} {
		auto s = session.clone();
		s.set_groups({dst_group});
		ELLIPTICS_REQUIRE(async, s.read(key, 0, 0));
		auto result = async.get().front();
		BOOST_REQUIRE_EQUAL(result.data().to_string(), data);
		BOOST_REQUIRE_EQUAL(result.record_info().data_timestamp, dst_timestamp);

		BOOST_REQUIRE_EQUAL(result.json().to_string(), json);
		BOOST_REQUIRE_EQUAL(result.record_info().json_capacity, 1024);
		BOOST_REQUIRE_EQUAL(result.record_info().json_timestamp, dst_timestamp);

		BOOST_REQUIRE_EQUAL(result.record_info().user_flags, dst_user_flags);
	}
}

// Check the case when destination group doesn't have enough space.
// Server-send should respond with -ENOSPC and original replica shouldn't be changed.
void test_send_failed_with_ENOSPC(ioremap::elliptics::newapi::session &session,
                                  ioremap::elliptics::key key,
                                  bool chunked,
                                  uint8_t retry_count) {
	static const std::string json = R"({"key": "test_send_failed_with_ENOSPC key"})";
	static const std::string data = "test_send_failed_with_ENOSPC data";
	constexpr dnet_time timestamp{11, 0};
	constexpr uint64_t user_flags = 100501;

	constexpr int src_group = 1;
	constexpr int dst_group = 4; // backend with limited size

	session.transform(key);
	session.set_exceptions_policy(ioremap::elliptics::session::no_exceptions);
	session.set_groups({src_group});
	session.set_timestamp(timestamp);
	session.set_user_flags(user_flags);

	{
		// write the key into src_group
		ELLIPTICS_REQUIRE(async, session.write(key, json, 1024, data, 1024));
	} {
		const uint64_t chunk_size = chunked ? (data.size() / 2) : DNET_DEFAULT_SERVER_SEND_CHUNK_SIZE;
		auto async = session.server_send({key}, 0 /*flags*/,
		                                 chunk_size,
		                                 src_group, std::vector<int>{dst_group},
		                                 1000 /* 1s */,
		                                 1000 /* 1s */,
		                                 retry_count /* chunk_retry_count */);

		auto results = async.get();
		BOOST_REQUIRE_EQUAL(results.size(), 1);
		auto &result = results.front();

		BOOST_REQUIRE_EQUAL(result.iterator_id(), 0);
		BOOST_REQUIRE_EQUAL(result.key(), key.raw_id());
		BOOST_REQUIRE_EQUAL(result.status(), -ENOSPC);

		// backend's absence should be checked fast and without retries
		BOOST_REQUIRE_EQUAL(async.elapsed_time().tsec, 0);
	} {
		auto s = session.clone();
		s.set_groups({src_group});
		ELLIPTICS_REQUIRE(async, s.read(key, 0, 0));
		auto result = async.get().front();
		BOOST_REQUIRE_EQUAL(result.data().to_string(), data);
		BOOST_REQUIRE_EQUAL(result.record_info().data_timestamp, timestamp);

		BOOST_REQUIRE_EQUAL(result.json().to_string(), json);
		BOOST_REQUIRE_EQUAL(result.record_info().json_capacity, 1024);
		BOOST_REQUIRE_EQUAL(result.record_info().json_timestamp, timestamp);

		BOOST_REQUIRE_EQUAL(result.record_info().user_flags, user_flags);
	} {
		auto s = session.clone();
		s.set_groups({dst_group});
		ELLIPTICS_REQUIRE_ERROR(async, s.lookup(key), -ENOENT);
	}
}

static void corrupt_record(const std::string &path, off_t offset, const std::string &injection) {
	int fd = open(path.c_str(), O_RDWR, 0644);

	BOOST_REQUIRE(fd > 0);
	BOOST_REQUIRE_EQUAL(pwrite(fd, injection.c_str(), injection.size(), offset), injection.size());

	close(fd);
}

// Check the case when original replica is corrupted.
// Server-send should respond with -EILSEQ, original replica should remain corrupted and
// destination replica shouldn't exist.
void test_send_failed_with_EILSEQ(ioremap::elliptics::newapi::session &session,
                                  ioremap::elliptics::key key,
                                  bool chunked,
                                  uint8_t retry_count) {
	static const std::string json = R"({"key": "test_send_failed_with_EILSEQ key"})";
	static const std::string data = "test_send_failed_with_EILSEQ data";
	constexpr dnet_time timestamp{11, 0};
	constexpr uint64_t user_flags = 100501;

	constexpr int src_group = 1;
	constexpr int dst_group = 2; // backend with limited size

	session.transform(key);
	session.set_exceptions_policy(ioremap::elliptics::session::no_exceptions);
	session.set_groups({src_group});
	session.set_timestamp(timestamp);
	session.set_user_flags(user_flags);

	{
		// write the key into src_group
		ELLIPTICS_REQUIRE(async, session.write(key, json, 1024, data, 1024));

		// corrupt
		auto result = async.get()[0];
		corrupt_record(result.path(), result.record_info().data_offset, "xx");
	} {
		const uint64_t chunk_size = chunked ? (data.size() / 2) : DNET_DEFAULT_SERVER_SEND_CHUNK_SIZE;
		auto async = session.server_send({key}, 0 /*flags*/,
		                                 chunk_size,
		                                 src_group, std::vector<int>{dst_group},
		                                 1000 /* 1s */,
		                                 1000 /* 1s */,
		                                 retry_count /* chunk_retry_count */);

		auto results = async.get();
		BOOST_REQUIRE_EQUAL(results.size(), 1);
		auto &result = results.front();

		BOOST_REQUIRE_EQUAL(result.iterator_id(), 0);
		BOOST_REQUIRE_EQUAL(result.key(), key.raw_id());
		BOOST_REQUIRE_EQUAL(result.status(), -EILSEQ);

		// backend's absence should be checked fast and without retries
		BOOST_REQUIRE_EQUAL(async.elapsed_time().tsec, 0);
	} {
		auto s = session.clone();
		s.set_groups({src_group});
		ELLIPTICS_REQUIRE_ERROR(async, s.read(key, 0, 0), -EILSEQ);
	} {
		auto s = session.clone();
		s.set_groups({dst_group});
		ELLIPTICS_REQUIRE_ERROR(async, s.lookup(key), -ENOENT);
	}
}

// Check the case when original replica is corrupted with stamp.
// Server-send should respond with -EILSEQ, original replica should remain corrupted and
// destination replica shouldn't exist.
void test_send_failed_with_EILSEQ_stamp(ioremap::elliptics::newapi::session &session,
                                        ioremap::elliptics::key key,
                                        bool chunked,
                                        uint8_t retry_count) {
	constexpr int src_group = 1;
	constexpr int dst_group = 2; // backend with limited size

	session.transform(key);
	session.set_exceptions_policy(ioremap::elliptics::session::no_exceptions);
	session.set_groups({src_group});
	session.set_timestamp({DNET_SERVER_SEND_BUGFIX_TIMESTAMP, 0});

	{
		static const std::string json = R"({"key": "test_send_failed_with_EILSEQ_stamp key"})";

		constexpr auto data_size = sizeof(eblob_disk_control) + sizeof(dnet_ext_list_hdr);
		auto data = ioremap::elliptics::data_pointer::allocate(data_size);
		auto dc = data.data<eblob_disk_control>();
		auto ehdr = data.skip<eblob_disk_control>().data<dnet_ext_list_hdr>();

		dc->flags = BLOB_DISK_CTL_CHUNKED_CSUM;
		dc->disk_size = 1024;
		dc->data_size = 100;
		dc->position = 0;

		ehdr->version = DNET_EXT_VERSION_V1;
		ehdr->timestamp = {DNET_SERVER_SEND_BUGFIX_TIMESTAMP, 0};
		ehdr->__pad1[0] = ehdr->__pad1[1] = ehdr->__pad1[2] = 0;
		ehdr->__pad2[0] = ehdr->__pad2[1] = 0;

		// write the key into src_group
		ELLIPTICS_REQUIRE(async, session.write(key, json, 1024, data, 1024));
	} {
		const uint64_t chunk_size = chunked ? 1 : DNET_DEFAULT_SERVER_SEND_CHUNK_SIZE;
		auto async = session.server_send({key}, 0 /*flags*/,
		                                 chunk_size,
		                                 src_group, std::vector<int>{dst_group},
		                                 1000 /* 1s */,
		                                 1000 /* 1s */,
		                                 retry_count /* chunk_retry_count */);

		auto results = async.get();
		BOOST_REQUIRE_EQUAL(results.size(), 1);
		auto &result = results.front();

		BOOST_REQUIRE_EQUAL(result.iterator_id(), 0);
		BOOST_REQUIRE_EQUAL(result.key(), key.raw_id());
		BOOST_REQUIRE_EQUAL(result.status(), -EILSEQ);

		// backend's absence should be checked fast and without retries
		BOOST_REQUIRE_EQUAL(async.elapsed_time().tsec, 0);
	} {
		auto s = session.clone();
		s.set_groups({src_group});
		ELLIPTICS_REQUIRE_ERROR(async, s.read(key, 0, 0), -EILSEQ);
	} {
		auto s = session.clone();
		s.set_groups({dst_group});
		ELLIPTICS_REQUIRE_ERROR(async, s.lookup(key), -ENOENT);
	}
}

// Check the case when original replica has corrupted record headers.
// Server-send should respond with -EINVAL, original replica should remain corrupted and
// destination replica shouldn't exist.
void test_send_failed_with_EINVAL(ioremap::elliptics::newapi::session &session,
                                  ioremap::elliptics::key key,
                                  bool chunked,
                                  uint8_t retry_count) {
	static const std::string json = R"({"key": "test_send_failed_with_EINVAL key"})";
	static const std::string data = "test_send_failed_with_EINVAL data";
	constexpr dnet_time timestamp{11, 0};
	constexpr uint64_t user_flags = 100501;

	constexpr int src_group = 1;
	constexpr int dst_group = 2; // backend with limited size

	session.transform(key);
	session.set_exceptions_policy(ioremap::elliptics::session::no_exceptions);
	session.set_groups({src_group});
	session.set_timestamp(timestamp);
	session.set_user_flags(user_flags);

	{
		// write the key into src_group
		ELLIPTICS_REQUIRE(async, session.write(key, json, 1024, data, 1024));

		// corrupt, 90 is empirical value
		auto result = async.get()[0];
		corrupt_record(result.path(), result.record_info().json_offset - 90, "x");
	}

	{
		const uint64_t chunk_size = chunked ? (data.size() / 2) : DNET_DEFAULT_SERVER_SEND_CHUNK_SIZE;
		auto async = session.server_send({key}, 0 /*flags*/,
		                                 chunk_size,
		                                 src_group, std::vector<int>{dst_group},
		                                 1000 /* 1s */,
		                                 1000 /* 1s */,
		                                 retry_count /* chunk_retry_count */);

		auto results = async.get();
		BOOST_REQUIRE_EQUAL(results.size(), 1);
		auto &result = results.front();

		BOOST_REQUIRE_EQUAL(result.iterator_id(), 0);
		BOOST_REQUIRE_EQUAL(result.key(), key.raw_id());
		BOOST_REQUIRE_EQUAL(result.status(), -EINVAL);

		// backend's absence should be checked fast and without retries
		BOOST_REQUIRE_EQUAL(async.elapsed_time().tsec, 0);
	} {
		auto s = session.clone();
		s.set_groups({src_group});
		ELLIPTICS_REQUIRE_ERROR(async, s.read(key, 0, 0), -EINVAL);
	} {
		auto s = session.clone();
		s.set_groups({dst_group});
		ELLIPTICS_REQUIRE_ERROR(async, s.lookup(key), -ENOENT);
	}
}

/* This case cover server-send that should copy the key into 2 groups: normal and with timeout. */
// Check the case when one of destination group are succeeded only at second write.
// The key should be written into both replicas.
void test_send_0_successful_retry(ioremap::elliptics::newapi::session &session,
                                  ioremap::elliptics::key key,
                                  const nodes_data *setup,
                                  bool chunked,
                                  uint8_t retry_count) {
	static const std::string json =
		R"({"key": "new_api_server_send_test::test_send_0_successful_retry key"})";
	static const std::string data =
		"new_api_server_send_test::test_send_0_successful_retry data";
	constexpr dnet_time timestamp{11, 0};
	constexpr uint64_t user_flags = 100501;

	constexpr int src_group = 1;
	constexpr int normal_group = 2;
	constexpr int delayed_group = 3;

	const auto delayed_remote = setup->nodes[2].remote();
	constexpr uint32_t delayed_backend = 0;

	session.transform(key);
	session.set_exceptions_policy(ioremap::elliptics::session::no_exceptions);
	session.set_groups({src_group});
	session.set_timestamp(timestamp);
	session.set_user_flags(user_flags);

	{
		// write the key into src_group
		ELLIPTICS_REQUIRE(async, session.write(key, json, 1024, data, 1024));
	}

	session.set_delay(delayed_remote, delayed_backend, 3000).wait();

	{
		const uint64_t chunk_size = chunked ? (data.size() / 2) : DNET_DEFAULT_SERVER_SEND_CHUNK_SIZE;
		auto async = session.server_send({key}, 0 /*flags*/,
		                                 chunk_size,
		                                 src_group, std::vector<int>{normal_group, delayed_group},
		                                 2000 /* 1s */,
		                                 2000 /* 1s */,
		                                 retry_count /* chunk_retry_count */);

		// sleep to give a time for server-send to send first write
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
		// reset delay, so when server-send will retry write, it won't be timeouted
		session.set_delay(delayed_remote, delayed_backend, 0).wait();

		auto results = async.get();
		BOOST_REQUIRE_EQUAL(results.size(), 1);
		auto &result = results.front();

		BOOST_REQUIRE_EQUAL(result.iterator_id(), 0);
		BOOST_REQUIRE_EQUAL(result.key(), key.raw_id());
		BOOST_REQUIRE_EQUAL(result.status(), 0);
	}

	// reset delay
	session.set_delay(delayed_remote, delayed_backend, 0).wait();

	{
		// the key should be available and correct in all groups.
		constexpr std::array<int, 3> groups{src_group, normal_group, delayed_group};
		for (auto group: groups) {
			session.set_groups({group});
			const auto &results = session.read(key, 0, 0).get();
			const auto &result = results.front();

			BOOST_REQUIRE_EQUAL(result.data().to_string(), data);
			BOOST_REQUIRE_EQUAL(result.record_info().data_timestamp, timestamp);

			BOOST_REQUIRE_EQUAL(result.json().to_string(), json);
			BOOST_REQUIRE_EQUAL(result.record_info().json_capacity, 1024);
			BOOST_REQUIRE_EQUAL(result.record_info().json_timestamp, timestamp);

			BOOST_REQUIRE_EQUAL(result.record_info().user_flags, user_flags);
		}
	}

}

// Check the case when one of destination groups is timed-out.
// Server-send should respond with -ETIMEDOUT, but the key should be written into another destination replica.
void test_send_0_ETIMEDOUT(ioremap::elliptics::newapi::session &session,
                           ioremap::elliptics::key key,
                           const nodes_data *setup,
                           bool chunked,
                           uint8_t retry_count) {
	static const std::string json =
		R"({"key": "new_api_server_send_test::test_send_0_ETIMEDOUT key"})";
	static const std::string data =
		"new_api_server_send_test::test_send_0_ETIMEDOUT data";
	constexpr dnet_time timestamp{11, 0};
	constexpr uint64_t user_flags = 100501;

	constexpr int src_group = 1;
	constexpr int normal_group = 2;
	constexpr int delayed_group = 3;

	const auto delayed_remote = setup->nodes[2].remote();
	constexpr uint32_t delayed_backend = 0;

	session.transform(key);
	session.set_exceptions_policy(ioremap::elliptics::session::no_exceptions);
	session.set_groups({src_group});
	session.set_timestamp(timestamp);
	session.set_user_flags(user_flags);

	{
		// write the key into src_group
		ELLIPTICS_REQUIRE(async, session.write(key, json, 1024, data, 1024));
	}

	session.set_delay(delayed_remote, delayed_backend, 2000).wait();

	{
		const uint64_t chunk_size = chunked ? (data.size() / 2) : DNET_DEFAULT_SERVER_SEND_CHUNK_SIZE;
		auto async = session.server_send({key}, 0 /*flags*/,
		                                 chunk_size,
		                                 src_group, std::vector<int>{normal_group, delayed_group},
		                                 1000 /* 1s */,
		                                 1000 /* 1s */,
		                                 retry_count /* chunk_retry_count */);

		auto results = async.get();
		BOOST_REQUIRE_EQUAL(results.size(), 1);
		auto &result = results.front();

		BOOST_REQUIRE_EQUAL(result.iterator_id(), 0);
		BOOST_REQUIRE_EQUAL(result.key(), key.raw_id());
		// aggregated result for this key should be -ETIMEDOUT
		BOOST_REQUIRE_EQUAL(result.status(), -ETIMEDOUT);
	}

	// reset delay
	session.set_delay(delayed_remote, delayed_backend, 0).wait();

	// sleep for removing affects from hanging request
	// sleep for 1 second, because server_send retried write once and it took double delay (3 seconds)
	// to handle them, but 2 seconds has already passed by server-send
	std::this_thread::sleep_for(std::chrono::seconds{retry_count + 1});

	{
		// the key should be available and correct in src and normal group, there is
		// no guarantee about delayed group, because request to it can be dropped.
		constexpr std::array<int, 2> groups{src_group, normal_group};
		for (auto group: groups) {
			session.set_groups({group});
			const auto &results = session.read(key, 0, 0).get();
			const auto &result = results.front();

			BOOST_REQUIRE_EQUAL(result.data().to_string(), data);
			BOOST_REQUIRE_EQUAL(result.record_info().data_timestamp, timestamp);

			BOOST_REQUIRE_EQUAL(result.json().to_string(), json);
			BOOST_REQUIRE_EQUAL(result.record_info().json_capacity, 1024);
			BOOST_REQUIRE_EQUAL(result.record_info().json_timestamp, timestamp);

			BOOST_REQUIRE_EQUAL(result.record_info().user_flags, user_flags);
		}
	}
}

// Check the case when one of destination groups is unavailable.
// Server-send should respond with -ENXIO, but the key should be written into another destination replica.
void test_send_0_ENXIO(ioremap::elliptics::newapi::session &session,
                       ioremap::elliptics::key key,
                       const nodes_data *setup,
                       bool chunked,
                       uint8_t retry_count) {
	static const std::string json = R"({"key": "test_send_0_ENXIO key"})";
	static const std::string data = "test_send_0_ENXIO data";
	constexpr dnet_time timestamp{11, 0};
	constexpr uint64_t user_flags = 100501;

	constexpr int src_group = 1;
	constexpr int normal_group = 2;
	constexpr int victim_group = 3;

	// victim's address and backend_id
	const auto victim_address = setup->nodes[2].remote();
	constexpr uint32_t victim_backend_id = 0;

	session.transform(key);
	session.set_exceptions_policy(ioremap::elliptics::session::no_exceptions);
	session.set_groups({src_group});
	session.set_timestamp(timestamp);
	session.set_user_flags(user_flags);

	{
		// write the key into src_group
		ELLIPTICS_REQUIRE(async, session.write(key, json, 1024, data, 1024));
	}

	// disable backend
	session.disable_backend(victim_address, victim_backend_id).wait();

	{
		const uint64_t chunk_size = chunked ? (data.size() / 2) : DNET_DEFAULT_SERVER_SEND_CHUNK_SIZE;
		auto async = session.server_send({key}, 0 /*flags*/,
		                                 chunk_size,
		                                 src_group, std::vector<int>{normal_group, victim_group},
		                                 1000 /* 1s */,
		                                 1000 /* 1s */,
		                                 retry_count /* chunk_retry_count */);

		auto results = async.get();
		BOOST_REQUIRE_EQUAL(results.size(), 1);
		auto &result = results.front();

		BOOST_REQUIRE_EQUAL(result.iterator_id(), 0);
		BOOST_REQUIRE_EQUAL(result.key(), key.raw_id());
		BOOST_REQUIRE_EQUAL(result.status(), -ENXIO);

		// backend's absence should be checked fast and without retries
		BOOST_REQUIRE_EQUAL(async.elapsed_time().tsec, 0);
	}

	// enable backend back
	session.enable_backend(victim_address, victim_backend_id).wait();

	{
		// the key should be available and correct in src and normal groups
		constexpr std::array<int, 2> groups{src_group, normal_group};
		for (auto group: groups) {
			session.set_groups({group});
			const auto &results = session.read(key, 0, 0).get();
			const auto &result = results.front();

			BOOST_REQUIRE_EQUAL(result.data().to_string(), data);
			BOOST_REQUIRE_EQUAL(result.record_info().data_timestamp, timestamp);

			BOOST_REQUIRE_EQUAL(result.json().to_string(), json);
			BOOST_REQUIRE_EQUAL(result.record_info().json_capacity, 1024);
			BOOST_REQUIRE_EQUAL(result.record_info().json_timestamp, timestamp);

			BOOST_REQUIRE_EQUAL(result.record_info().user_flags, user_flags);
		}
	} {
		session.set_filter(ioremap::elliptics::filters::all_with_ack);
		session.set_groups({victim_group});
		auto async = session.read(key, 0, 0);
		const auto &results = async.get();
		BOOST_REQUIRE_EQUAL(results.size(), 1);
		const auto &result = results.front();

		BOOST_REQUIRE_EQUAL(result.status(), -ENOENT);
	}
}


// Check the case when one of destination groups is in read-only mode.
// Server-send should respond with -EROFS, but the key should be written into another destination replica.
void test_send_0_EROFS(ioremap::elliptics::newapi::session &session,
                       ioremap::elliptics::key key,
                       const nodes_data *setup,
                       bool chunked,
                       uint8_t retry_count) {
	static const std::string json = R"({"key": "test_send_0_EROFS key"})";
	static const std::string data = "test_send_0_EROFS data";
	constexpr dnet_time timestamp{11, 0};
	constexpr uint64_t user_flags = 100501;

	constexpr int src_group = 1;
	constexpr int normal_group = 2;
	constexpr int victim_group = 3;

	// victim's address and backend_id
	const auto victim_address = setup->nodes[2].remote();
	constexpr uint32_t victim_backend_id = 0;

	session.transform(key);
	session.set_exceptions_policy(ioremap::elliptics::session::no_exceptions);
	session.set_groups({src_group});
	session.set_timestamp(timestamp);
	session.set_user_flags(user_flags);

	{
		// write the key into src_group
		ELLIPTICS_REQUIRE(async, session.write(key, json, 1024, data, 1024));
	}

	// turn RO on backend
	session.make_readonly(victim_address, victim_backend_id).wait();

	{
		const uint64_t chunk_size = chunked ? (data.size() / 2) : DNET_DEFAULT_SERVER_SEND_CHUNK_SIZE;
		auto async = session.server_send({key}, 0 /*flags*/,
		                                 chunk_size,
		                                 src_group, std::vector<int>{normal_group, victim_group},
		                                 1000 /* 1s */,
		                                 1000 /* 1s */,
		                                 retry_count /* chunk_retry_count */);

		auto results = async.get();
		BOOST_REQUIRE_EQUAL(results.size(), 1);
		auto &result = results.front();

		BOOST_REQUIRE_EQUAL(result.iterator_id(), 0);
		BOOST_REQUIRE_EQUAL(result.key(), key.raw_id());
		BOOST_REQUIRE_EQUAL(result.status(), -EROFS);

		// backend's absence should be checked fast and without retries
		BOOST_REQUIRE_EQUAL(async.elapsed_time().tsec, 0);
	}

	// revert RO on backend
	session.make_writable(victim_address, victim_backend_id).wait();

	{
		// the key should be available and correct in src and normal groups
		constexpr std::array<int, 2> groups{src_group, normal_group};
		for (auto group: groups) {
			session.set_groups({group});
			const auto &results = session.read(key, 0, 0).get();
			const auto &result = results.front();

			BOOST_REQUIRE_EQUAL(result.data().to_string(), data);
			BOOST_REQUIRE_EQUAL(result.record_info().data_timestamp, timestamp);

			BOOST_REQUIRE_EQUAL(result.json().to_string(), json);
			BOOST_REQUIRE_EQUAL(result.record_info().json_capacity, 1024);
			BOOST_REQUIRE_EQUAL(result.record_info().json_timestamp, timestamp);

			BOOST_REQUIRE_EQUAL(result.record_info().user_flags, user_flags);
		}
	} {
		session.set_filter(ioremap::elliptics::filters::all_with_ack);
		session.set_groups({victim_group});
		auto async = session.read(key, 0, 0);
		const auto &results = async.get();
		BOOST_REQUIRE_EQUAL(results.size(), 1);
		const auto &result = results.front();

		BOOST_REQUIRE_EQUAL(result.status(), -ENOENT);
	}
}


// Check the case when one of destination groups has newer key replica.
// Server-send should respond with -EBADFD, but the key should be written into another destination replica.
// Newer key replica shouldn't be overwritten.
void test_send_0_EBADFD(ioremap::elliptics::newapi::session &session,
                        ioremap::elliptics::key key,
                        bool chunked,
                        uint8_t retry_count) {
	static const std::string json = R"({"key": "test_send_0_EBADFD key"})";
	static const std::string data = "test_send_0_EBADFD data";

	constexpr dnet_time src_timestamp{11, 0};
	constexpr dnet_time victim_timestamp{src_timestamp.tsec, src_timestamp.tnsec + 1};

	constexpr uint64_t src_user_flags = 100501;
	constexpr uint64_t victim_user_flags = src_user_flags + 1;

	constexpr int src_group = 1;
	constexpr int normal_group = 2;
	constexpr int victim_group = 3;

	session.transform(key);
	session.set_exceptions_policy(ioremap::elliptics::session::no_exceptions);
	session.set_groups({src_group});
	session.set_timestamp(src_timestamp);
	session.set_user_flags(src_user_flags);

	{
		// write the key into src_group
		ELLIPTICS_REQUIRE(async, session.write(key, json, 1024, data, 1024));
	} {
		// write the key into victim_group with higher timestamp
		auto s = session.clone();
		s.set_timestamp(victim_timestamp);
		s.set_groups({victim_group});
		s.set_user_flags(victim_user_flags);
		ELLIPTICS_REQUIRE(async, s.write(key, json, 1024, data, 1024));
	}

	{
		const uint64_t chunk_size = chunked ? (data.size() / 2) : DNET_DEFAULT_SERVER_SEND_CHUNK_SIZE;
		auto async = session.server_send({key}, 0 /*flags*/,
		                                 chunk_size,
		                                 src_group, std::vector<int>{normal_group, victim_group},
		                                 1000 /* 1s */,
		                                 1000 /* 1s */,
		                                 retry_count /* chunk_retry_count */);

		auto results = async.get();
		BOOST_REQUIRE_EQUAL(results.size(), 1);
		auto &result = results.front();

		BOOST_REQUIRE_EQUAL(result.iterator_id(), 0);
		BOOST_REQUIRE_EQUAL(result.key(), key.raw_id());
		BOOST_REQUIRE_EQUAL(result.status(), -EBADFD);

		// backend's absence should be checked fast and without retries
		BOOST_REQUIRE_EQUAL(async.elapsed_time().tsec, 0);
	}

	{
		constexpr std::array<int, 2> groups{src_group, normal_group};
		for (const auto group: groups) {
			auto s = session.clone();
			s.set_groups({group});
			ELLIPTICS_REQUIRE(async, s.read(key, 0, 0));
			auto result = async.get().front();
			BOOST_REQUIRE_EQUAL(result.data().to_string(), data);
			BOOST_REQUIRE_EQUAL(result.record_info().data_timestamp, src_timestamp);

			BOOST_REQUIRE_EQUAL(result.json().to_string(), json);
			BOOST_REQUIRE_EQUAL(result.record_info().json_capacity, 1024);
			BOOST_REQUIRE_EQUAL(result.record_info().json_timestamp, src_timestamp);

			BOOST_REQUIRE_EQUAL(result.record_info().user_flags, src_user_flags);
		}
	} {
		auto s = session.clone();
		s.set_groups({victim_group});
		ELLIPTICS_REQUIRE(async, s.read(key, 0, 0));
		auto result = async.get().front();
		BOOST_REQUIRE_EQUAL(result.data().to_string(), data);
		BOOST_REQUIRE_EQUAL(result.record_info().data_timestamp, victim_timestamp);

		BOOST_REQUIRE_EQUAL(result.json().to_string(), json);
		BOOST_REQUIRE_EQUAL(result.record_info().json_capacity, 1024);
		BOOST_REQUIRE_EQUAL(result.record_info().json_timestamp, victim_timestamp);

		BOOST_REQUIRE_EQUAL(result.record_info().user_flags, victim_user_flags);
	}
}

// Check the case when one of destination groups has no enough space.
// Server-send should respond with -ENOSPC, but the key should be written into another destination replica.
void test_send_0_ENOSPC(ioremap::elliptics::newapi::session &session,
                        ioremap::elliptics::key key,
                        bool chunked,
                        uint8_t retry_count) {
	static const std::string json = R"({"key": "test_send_0_ENOSPC key"})";
	static const std::string data = "test_send_0_ENOSPC data";
	constexpr dnet_time timestamp{11, 0};
	constexpr uint64_t user_flags = 100501;

	constexpr int src_group = 1;
	constexpr int normal_group = 2;
	constexpr int victim_group = 4;

	session.transform(key);
	session.set_exceptions_policy(ioremap::elliptics::session::no_exceptions);
	session.set_groups({src_group});
	session.set_timestamp(timestamp);
	session.set_user_flags(user_flags);

	{
		// write the key into src_group
		ELLIPTICS_REQUIRE(async, session.write(key, json, 1024, data, 1024));
	}

	{
		const uint64_t chunk_size = chunked ? (data.size() / 2) : DNET_DEFAULT_SERVER_SEND_CHUNK_SIZE;
		auto async = session.server_send({key}, 0 /*flags*/,
		                                 chunk_size,
		                                 src_group, std::vector<int>{normal_group, victim_group},
		                                 1000 /* 1s */,
		                                 1000 /* 1s */,
		                                 retry_count /* chunk_retry_count */);

		auto results = async.get();
		BOOST_REQUIRE_EQUAL(results.size(), 1);
		auto &result = results.front();

		BOOST_REQUIRE_EQUAL(result.iterator_id(), 0);
		BOOST_REQUIRE_EQUAL(result.key(), key.raw_id());
		BOOST_REQUIRE_EQUAL(result.status(), -ENOSPC);

		// backend's absence should be checked fast and without retries
		BOOST_REQUIRE_EQUAL(async.elapsed_time().tsec, 0);
	}

	{
		constexpr std::array<int, 2> groups{src_group, normal_group};
		for (const auto group: groups) {
			auto s = session.clone();
			s.set_groups({group});
			ELLIPTICS_REQUIRE(async, s.read(key, 0, 0));
			auto result = async.get().front();
			BOOST_REQUIRE_EQUAL(result.data().to_string(), data);
			BOOST_REQUIRE_EQUAL(result.record_info().data_timestamp, timestamp);

			BOOST_REQUIRE_EQUAL(result.json().to_string(), json);
			BOOST_REQUIRE_EQUAL(result.record_info().json_capacity, 1024);
			BOOST_REQUIRE_EQUAL(result.record_info().json_timestamp, timestamp);

			BOOST_REQUIRE_EQUAL(result.record_info().user_flags, user_flags);
		}
	} {
		auto s = session.clone();
		s.set_groups({victim_group});
		ELLIPTICS_REQUIRE_ERROR(async, s.lookup(key), -ENOENT);
	}
}

bool register_tests(const nodes_data *setup) {
	auto n = setup->node->get_native();

	// test_dataset testset{session, 2};
	ELLIPTICS_TEST_CASE(test_simple_server_send, use_session(n)/*, testset*/);

	/* Writes many keys to a single group, then checks that they have been successfully written
	   to the single group only.
	   Calls server send to copy by chunks keys to other groups.
	   Checks that all keys are written to all groups.
	 */
	size_t num_keys = 100;

	size_t data_size = 64 * 1024; // 64 Kb
	size_t chunk_size = 1021; // prime number
	std::string id_prefix("newapi server send id");
	std::string data_prefix(data_size, 'd');
	auto keys = generate_keys(id_prefix, data_prefix, num_keys);

	ELLIPTICS_TEST_CASE(test_insert_keys, use_session(n), keys, std::vector<int>({constants::src_group}));
	ELLIPTICS_TEST_CASE(test_read_keys, use_session(n), keys, std::vector<int>({constants::src_group}));
	ELLIPTICS_TEST_CASE(test_read_keys_error, use_session(n), keys, constants::dst_groups, -ENOENT);

	ELLIPTICS_TEST_CASE(test_chunked_server_send, use_session(n), keys, constants::src_group, constants::dst_groups,
	                    chunk_size, 0);

	std::vector<int> all_groups = constants::dst_groups;
	all_groups.emplace_back(constants::src_group);

	ELLIPTICS_TEST_CASE(test_read_keys, use_session(n), keys, all_groups);

	ELLIPTICS_TEST_CASE(test_remove_keys, use_session(n), keys, constants::dst_groups);
	ELLIPTICS_TEST_CASE(test_make_groups_readonly, use_session(n), constants::dst_groups, true);

	ELLIPTICS_TEST_CASE(test_chunked_server_send, use_session(n), keys, constants::src_group, constants::dst_groups,
	                    chunk_size, -EROFS);

	ELLIPTICS_TEST_CASE(test_make_groups_readonly, use_session(n), constants::dst_groups, false);

	static const auto make_unique_key = [] {
		static const std::string key_prefix = "newapi server_send failures";
		static size_t key_idx = 0;
		return key_prefix + std::to_string(key_idx++);
	};
	constexpr std::array<bool, 2> variants_for_chunked{false, true};
	constexpr std::array<uint8_t, 2> variants_for_retries{0, 1};
	for (const auto chunked: variants_for_chunked) {
		for (const auto retries: variants_for_retries) {
			// collection of server-send tests with single destination group and specified retries
			if (retries) {
				ELLIPTICS_TEST_CASE(test_send_with_successful_retry, use_session(n), make_unique_key(),
				                    setup, chunked, retries);
			}

			// collection of server-send test with single destination group and specified retries,
			// but with failures that shouldn't be retried
			ELLIPTICS_TEST_CASE(test_send_failed_with_ETIMEDOUT, use_session(n), make_unique_key(), setup,
			                    chunked, retries);
			ELLIPTICS_TEST_CASE(test_send_failed_with_ENXIO, use_session(n), make_unique_key(), setup,
			                    chunked, retries);
			ELLIPTICS_TEST_CASE(test_send_failed_with_EROFS, use_session(n), make_unique_key(), setup,
			                    chunked, retries);
			ELLIPTICS_TEST_CASE(test_send_failed_with_EBADFD, use_session(n), make_unique_key(), chunked,
			                    retries);
			ELLIPTICS_TEST_CASE(test_send_failed_with_ENOSPC, use_session(n), make_unique_key(), chunked,
			                    retries);
			ELLIPTICS_TEST_CASE(test_send_failed_with_EILSEQ, use_session(n), make_unique_key(), chunked,
			                    retries);
			ELLIPTICS_TEST_CASE(test_send_failed_with_EILSEQ_stamp, use_session(n), make_unique_key(), chunked,
			                    retries);
			ELLIPTICS_TEST_CASE(test_send_failed_with_EINVAL, use_session(n), make_unique_key(), chunked,
			                    retries);

			// collection of server-send tests with two destination groups and specified retries
			if (retries) {
				ELLIPTICS_TEST_CASE(test_send_0_successful_retry, use_session(n), make_unique_key(),
				                    setup, chunked, retries);
			}

			ELLIPTICS_TEST_CASE(test_send_0_ETIMEDOUT, use_session(n), make_unique_key(), setup,
			                    chunked, retries);
			ELLIPTICS_TEST_CASE(test_send_0_ENXIO, use_session(n), make_unique_key(), setup, chunked,
			                    retries);
			ELLIPTICS_TEST_CASE(test_send_0_EROFS, use_session(n), make_unique_key(), setup, chunked,
			                    retries);
			ELLIPTICS_TEST_CASE(test_send_0_EBADFD, use_session(n), make_unique_key(), chunked, retries);
			ELLIPTICS_TEST_CASE(test_send_0_ENOSPC, use_session(n), make_unique_key(), chunked, retries);
		}
	}

	// TODO(shaitan): test server_send with zero chunk_size
	return true;
}

tests::nodes_data::ptr configure_test_setup_from_args(int argc, char *argv[]) {
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

	return configure_test_setup(path);
}

} /* namespace */


/*
 * Common test initialization routine.
 */
using namespace tests;
using namespace boost::unit_test;

/*FIXME: forced to use global variable and plain function wrapper
 * because of the way how init_test_main works in boost.test,
 * introducing a global fixture would be a proper way to handle
 * global test setup
 */
namespace {

std::shared_ptr<nodes_data> setup;

bool init_func()
{
	return register_tests(setup.get());
}

}

int main(int argc, char *argv[])
{
	srand(time(nullptr));

	// we own our test setup
	setup = configure_test_setup_from_args(argc, argv);

	int result = unit_test_main(init_func, argc, argv);

	// disassemble setup explicitly, to be sure about where its lifetime ends
	setup.reset();

	return result;
}
