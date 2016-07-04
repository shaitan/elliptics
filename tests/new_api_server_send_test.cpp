#include <boost/program_options.hpp>

#define BOOST_TEST_NO_MAIN
#define BOOST_TEST_ALTERNATIVE_INIT_API
#include <boost/test/included/unit_test.hpp>

#include "elliptics/newapi/session.hpp"

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
	constexpr auto server_config = [] (const tests::config_data &c) {
		return tests::server_config::default_value().apply_options(c);
	};

	auto configs = {
		server_config(tests::config_data()("group", 1)),
		server_config(tests::config_data()("group", 2)),
		// server_config(tests::config_data()("group", 3)),
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
		                           constants::src_group, constants::dst_groups);

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

bool register_tests(const nodes_data *setup) {
	auto n = setup->node->get_native();

	// test_dataset testset{session, 2};
	ELLIPTICS_TEST_CASE(test_simple_server_send, use_session(n)/*, testset*/);

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
