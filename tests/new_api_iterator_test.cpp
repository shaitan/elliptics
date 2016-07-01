#include <boost/program_options.hpp>

#define BOOST_TEST_NO_MAIN
#define BOOST_TEST_ALTERNATIVE_INIT_API
#include <boost/test/included/unit_test.hpp>

#include "elliptics/newapi/session.hpp"

#include "test_base.hpp"

namespace {

tests::nodes_data* get_setup();

}

namespace tests {

namespace bu = boost::unit_test;

nodes_data::ptr configure_test_setup(const std::string &path) {
	constexpr auto server_config = [] (const tests::config_data &c) {
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
}

}

namespace {

namespace constants {
	namespace numberof {
		static constexpr size_t duplicates = 10;
		namespace committed {
			static constexpr size_t records_with_json = duplicates;
			static constexpr size_t records_without_json = duplicates;
			static constexpr size_t records_without_data = duplicates;
			static constexpr size_t all = records_with_json +
			                              records_without_json +
			                              records_without_data;
		} /* namespace committed */
		namespace uncommitted {
			static constexpr size_t records_with_json = duplicates;
			static constexpr size_t records_without_json = duplicates;
			static constexpr size_t records_without_data = duplicates;
			static constexpr size_t all = records_with_json +
			                              records_without_json +
			                              records_without_data;
		} /* namespace uncommitted */
		static constexpr size_t all = committed::all +
		                              uncommitted::all;
	} /* namespace numberof */

	static constexpr char key_prefix[] = "new_api_iterator_test key prefix";
	static constexpr char data_prefix[] = "new_api_iterator_test data prefix";

	static constexpr uint64_t user_flags = 0x123f24acb;

	static constexpr int src_group = 1;
	// static constexpr int dst_groups[]{2, 3};

	static constexpr uint64_t json_capacity = 300;
	static constexpr uint64_t data_capacity = 300;
} /* namespace constants */


class record {
public:
	record(const ioremap::elliptics::newapi::session &session, size_t index)
	: m_session(session)
	, m_index(index) {
	}

	std::string key() const {
		return constants::key_prefix + std::to_string(m_index);
	}

	dnet_raw_id raw_key() const {
		dnet_raw_id ret;
		m_session.transform(key(), ret);
		return ret;
	}

	std::string json() const {
		if (!has_json()) {
			return std::string{};
		}

		std::ostringstream str;
		str << "{"
			<< "\"key\":\"" << key() << "\","
			<< "\"index\":\"" << std::to_string(m_index) << "\""
		 << "}";
		return str.str();
	}

	std::string data() const {
		if (!has_data()) {
			return std::string{};
		}
		return constants::data_prefix + std::to_string(m_index);
	}

	uint64_t json_capacity() const {
		return has_json() ? constants::json_capacity : 0;
	}

	uint64_t data_capacity() const {
		return has_data() ? constants::data_capacity : 0;
	}

	uint64_t flags() const {
		uint64_t ret = DNET_RECORD_FLAGS_EXTHDR |
		               DNET_RECORD_FLAGS_CHUNKED_CSUM;

		if (!is_committed()) {
			ret |= DNET_RECORD_FLAGS_UNCOMMITTED;
		}
		return ret;
	}

	bool is_committed() const;

	dnet_time data_ts() const {
		return dnet_time{m_index, 0};
	}

	dnet_time json_ts() const {
		if (!has_json()) {
			return dnet_time{0, 0};
		}

		return data_ts();
	}

private:
	bool has_json() const;
	bool has_data() const;

private:
	const ioremap::elliptics::newapi::session &m_session;
	const size_t m_index;
};

bool record::has_json() const {
	using namespace constants::numberof;
	assert(m_index < all);

	auto index = m_index;

	if (index < committed::records_with_json) {
		return true;
	}
	index -= committed::records_with_json;

	if (index < committed::records_without_json) {
		return false;
	}
	index -= committed::records_without_json;

	if (index < committed::records_without_data) {
		return true;
	}
	index -= committed::records_without_data;

	if (index < uncommitted::records_with_json) {
		return true;
	}
	index -= uncommitted::records_with_json;

	if (index < uncommitted::records_without_json) {
		return false;
	}
	index -= uncommitted::records_without_json;

	BOOST_REQUIRE_LT(index, uncommitted::records_without_data);
	return true;
}

bool record::has_data() const {
	using namespace constants::numberof;
	assert(m_index < all);

	auto index = m_index;

	if (index < committed::records_with_json) {
		return true;
	}
	index -= committed::records_with_json;

	if (index < committed::records_without_json) {
		return true;
	}
	index -= committed::records_without_json;

	if (index < committed::records_without_data) {
		return false;
	}
	index -= committed::records_without_data;

	if (index < uncommitted::records_with_json) {
		return true;
	}
	index -= uncommitted::records_with_json;

	if (index < uncommitted::records_without_json) {
		return true;
	}
	index -= uncommitted::records_without_json;

	BOOST_REQUIRE_LT(index, uncommitted::records_without_data);
	return false;
}

bool record::is_committed() const {
	using namespace constants::numberof;
	assert(m_index < all);

	auto index = m_index;

	if (index < committed::all) {
		return true;
	}
	index -= committed::all;

	BOOST_REQUIRE_LT(index, uncommitted::all);
	return false;
}

void test_write_keys(const ioremap::elliptics::newapi::session &session) {
	auto s = session.clone();
	s.set_trace_id(rand());
	s.set_user_flags(constants::user_flags);
	s.set_groups({constants::src_group});

	ioremap::elliptics::newapi::async_write_result async;
	for (size_t index = 0; index < constants::numberof::all; ++index) {
		const record record{s, index};
		s.set_timestamp(record.data_ts());

		if (record.is_committed()) {
			ELLIPTICS_REQUIRE(res, s.write(record.key(),
			                               record.json(), record.json_capacity(),
			                               record.data(), record.data_capacity())
			                 );
		} else {
			ELLIPTICS_REQUIRE(res,
			                  s.write_prepare(record.key(), record.json(), record.json_capacity(),
			                                  record.data(), 0 /* data_offset*/, record.data_capacity()));
		}
	}
}

void test_iterator(const ioremap::elliptics::newapi::session &session) {
	auto s = session.clone();
	s.set_trace_id(rand());
	s.set_groups({constants::src_group});

	static const auto time_range = std::make_tuple(dnet_time{0, 0}, dnet_time{0, 0});
	auto async = s.start_iterator(get_setup()->nodes[0].remote(), 0, 0, {}, time_range);

	size_t index = 0;
	for (const auto &result: async) {
		const record record{s, index};

		BOOST_REQUIRE_EQUAL(result.key(), record.raw_key());
		BOOST_REQUIRE_EQUAL(result.iterator_id(), 0); // it's the first iterator.
		BOOST_REQUIRE_EQUAL(result.status(), 0);

		const auto record_info = result.record_info();
		BOOST_REQUIRE_BITWISE_EQUAL(record_info.user_flags, constants::user_flags);
		BOOST_REQUIRE_BITWISE_EQUAL(record_info.record_flags, record.flags());

		BOOST_REQUIRE_EQUAL(record_info.json_timestamp, record.json_ts());
		BOOST_REQUIRE_EQUAL(record_info.json_size, record.json().size());
		BOOST_REQUIRE_EQUAL(record_info.json_capacity, record.json_capacity());

		BOOST_REQUIRE_EQUAL(record_info.data_timestamp, record.data_ts());
		BOOST_REQUIRE_EQUAL(record_info.data_size, record.is_committed() ? record.data().size() : 0);

		BOOST_REQUIRE_EQUAL(result.json().size(), 0);
		BOOST_REQUIRE_EQUAL(result.data().size(), 0);

		BOOST_REQUIRE_EQUAL(result.iterated_keys(), ++index);
		BOOST_REQUIRE_EQUAL(result.total_keys(), constants::numberof::all);
	}

	BOOST_REQUIRE_EQUAL(index, constants::numberof::all);
}

void test_iterator_with_data(const ioremap::elliptics::newapi::session &session) {
	auto s = session.clone();
	s.set_trace_id(rand());
	s.set_groups({constants::src_group});

	static const auto time_range = std::make_tuple(dnet_time{0, 0}, dnet_time{0, 0});
	uint64_t flags = DNET_IFLAGS_DATA;
	auto async = s.start_iterator(get_setup()->nodes[0].remote(), 0, flags, {}, time_range);

	size_t index = 0;
	for (const auto &result: async) {
		const record record{s, index};

		BOOST_REQUIRE_EQUAL(result.key(), record.raw_key());
		BOOST_REQUIRE_EQUAL(result.iterator_id(), 0); // it's the first iterator.
		BOOST_REQUIRE_EQUAL(result.status(), 0);

		const auto record_info = result.record_info();
		BOOST_REQUIRE_BITWISE_EQUAL(record_info.user_flags, constants::user_flags);
		BOOST_REQUIRE_BITWISE_EQUAL(record_info.record_flags, record.flags());

		BOOST_REQUIRE_EQUAL(record_info.json_timestamp, record.json_ts());
		BOOST_REQUIRE_EQUAL(record_info.json_size, record.json().size());
		BOOST_REQUIRE_EQUAL(record_info.json_capacity, record.json_capacity());

		BOOST_REQUIRE_EQUAL(record_info.data_timestamp, record.data_ts());
		BOOST_REQUIRE_EQUAL(record_info.data_size, record.is_committed() ? record.data().size() : 0);

		BOOST_REQUIRE_EQUAL(result.json().size(), 0);
		BOOST_REQUIRE_EQUAL(result.data().size(), record.is_committed() ? record.data().size() : 0);
		BOOST_REQUIRE_EQUAL(result.data().to_string(), record.is_committed() ? record.data(): std::string());

		BOOST_REQUIRE_EQUAL(result.iterated_keys(), ++index);
		BOOST_REQUIRE_EQUAL(result.total_keys(), constants::numberof::all);
	}

	BOOST_REQUIRE_EQUAL(index, constants::numberof::all);
}

void test_iterator_with_json(const ioremap::elliptics::newapi::session &session) {
	auto s = session.clone();
	s.set_trace_id(rand());
	s.set_groups({constants::src_group});

	static const auto time_range = std::make_tuple(dnet_time{0, 0}, dnet_time{0, 0});
	static const uint64_t flags = DNET_IFLAGS_JSON;
	auto async = s.start_iterator(get_setup()->nodes[0].remote(), 0, flags, {}, time_range);

	size_t index = 0;
	for (const auto &result: async) {
		const record record{s, index};

		BOOST_REQUIRE_EQUAL(result.key(), record.raw_key());
		BOOST_REQUIRE_EQUAL(result.iterator_id(), 0); // it's the first iterator.
		BOOST_REQUIRE_EQUAL(result.status(), 0);

		const auto record_info = result.record_info();
		BOOST_REQUIRE_BITWISE_EQUAL(record_info.user_flags, constants::user_flags);
		BOOST_REQUIRE_BITWISE_EQUAL(record_info.record_flags, record.flags());

		BOOST_REQUIRE_EQUAL(record_info.json_timestamp, record.json_ts());
		BOOST_REQUIRE_EQUAL(record_info.json_size, record.json().size());
		BOOST_REQUIRE_EQUAL(record_info.json_capacity, record.json_capacity());

		BOOST_REQUIRE_EQUAL(record_info.data_timestamp, record.data_ts());
		BOOST_REQUIRE_EQUAL(record_info.data_size, record.is_committed() ? record.data().size() : 0);

		BOOST_REQUIRE_EQUAL(result.json().size(), record.json().size());
		BOOST_REQUIRE_EQUAL(result.json().to_string(), record.json());
		BOOST_REQUIRE_EQUAL(result.data().size(), 0);


		BOOST_REQUIRE_EQUAL(result.iterated_keys(), ++index);
		BOOST_REQUIRE_EQUAL(result.total_keys(), constants::numberof::all);
	}

	BOOST_REQUIRE_EQUAL(index, constants::numberof::all);
}

void test_iterator_with_json_and_data(const ioremap::elliptics::newapi::session &session) {
	auto s = session.clone();
	s.set_trace_id(rand());
	s.set_groups({constants::src_group});

	static const auto time_range = std::make_tuple(dnet_time{0, 0}, dnet_time{0, 0});
	static const uint64_t flags = DNET_IFLAGS_JSON | DNET_IFLAGS_DATA;
	auto async = s.start_iterator(get_setup()->nodes[0].remote(), 0, flags, {}, time_range);

	size_t index = 0;
	for (const auto &result: async) {
		const record record{s, index};

		BOOST_REQUIRE_EQUAL(result.key(), record.raw_key());
		BOOST_REQUIRE_EQUAL(result.iterator_id(), 0); // it's the first iterator.
		BOOST_REQUIRE_EQUAL(result.status(), 0);

		const auto record_info = result.record_info();
		BOOST_REQUIRE_BITWISE_EQUAL(record_info.user_flags, constants::user_flags);
		BOOST_REQUIRE_BITWISE_EQUAL(record_info.record_flags, record.flags());

		BOOST_REQUIRE_EQUAL(record_info.json_timestamp, record.json_ts());
		BOOST_REQUIRE_EQUAL(record_info.json_size, record.json().size());
		BOOST_REQUIRE_EQUAL(record_info.json_capacity, record.json_capacity());

		BOOST_REQUIRE_EQUAL(record_info.data_timestamp, record.data_ts());
		BOOST_REQUIRE_EQUAL(record_info.data_size, record.is_committed() ? record.data().size() : 0);

		BOOST_REQUIRE_EQUAL(result.json().size(), record.json().size());
		BOOST_REQUIRE_EQUAL(result.json().to_string(), record.json());
		BOOST_REQUIRE_EQUAL(result.data().size(), record.is_committed() ? record.data().size() : 0);
		BOOST_REQUIRE_EQUAL(result.data().to_string(), record.is_committed() ? record.data() : std::string());


		BOOST_REQUIRE_EQUAL(result.iterated_keys(), ++index);
		BOOST_REQUIRE_EQUAL(result.total_keys(), constants::numberof::all);
	}

	BOOST_REQUIRE_EQUAL(index, constants::numberof::all);
}

void test_iterator_with_time_range(const ioremap::elliptics::newapi::session &session,
                                   size_t first_index, size_t last_index) {
	auto s = session.clone();
	s.set_trace_id(rand());
	s.set_groups({constants::src_group});

	const auto time_range = std::make_tuple(record{s, first_index}.data_ts(),
	                                        record{s, last_index}.data_ts());
	static const uint64_t flags = DNET_IFLAGS_TS_RANGE;
	auto async = s.start_iterator(get_setup()->nodes[0].remote(), 0, flags, {}, time_range);

	size_t index = first_index;
	for (const auto &result: async) {
		const record record{s, index};

		BOOST_REQUIRE_EQUAL(result.key(), record.raw_key());
		BOOST_REQUIRE_EQUAL(result.iterator_id(), 0); // it's the first iterator.
		BOOST_REQUIRE_EQUAL(result.status(), 0);

		const auto record_info = result.record_info();
		BOOST_REQUIRE_BITWISE_EQUAL(record_info.user_flags, constants::user_flags);
		BOOST_REQUIRE_BITWISE_EQUAL(record_info.record_flags, record.flags());

		BOOST_REQUIRE_EQUAL(record_info.json_timestamp, record.json_ts());
		BOOST_REQUIRE_EQUAL(record_info.json_size, record.json().size());
		BOOST_REQUIRE_EQUAL(record_info.json_capacity, record.json_capacity());

		BOOST_REQUIRE_EQUAL(record_info.data_timestamp, record.data_ts());
		BOOST_REQUIRE_EQUAL(record_info.data_size, record.is_committed() ? record.data().size() : 0);

		BOOST_REQUIRE_EQUAL(result.json().size(), 0);
		BOOST_REQUIRE_EQUAL(result.data().size(), 0);

		BOOST_REQUIRE_EQUAL(result.iterated_keys(), ++index - first_index);
		BOOST_REQUIRE_EQUAL(result.total_keys(), constants::numberof::all);
	}

	BOOST_REQUIRE_EQUAL(index, last_index + 1);
}

void test_iterator_no_meta(const ioremap::elliptics::newapi::session &session) {
	auto s = session.clone();
	s.set_trace_id(rand());
	s.set_groups({constants::src_group});

	static const dnet_time null_ts{0, 0};
	static const auto time_range = std::make_tuple(null_ts, null_ts);
	static const uint64_t flags = DNET_IFLAGS_NO_META;
	auto async = s.start_iterator(get_setup()->nodes[0].remote(), 0, flags, {}, time_range);

	size_t index = 0;
	for (const auto &result: async) {
		const record record{s, index};

		BOOST_REQUIRE_EQUAL(result.key(), record.raw_key());
		BOOST_REQUIRE_EQUAL(result.iterator_id(), 0); // it's the first iterator.
		BOOST_REQUIRE_EQUAL(result.status(), 0);

		const auto record_info = result.record_info();
		BOOST_REQUIRE_BITWISE_EQUAL(record_info.user_flags, uint64_t{0}); // user_flags are stored in meta
		BOOST_REQUIRE_BITWISE_EQUAL(record_info.record_flags, record.flags());

		BOOST_REQUIRE_EQUAL(record_info.json_timestamp, null_ts); // timestamp is stored in meta
		BOOST_REQUIRE_EQUAL(record_info.json_size, 0); // size of json is stored in meta
		BOOST_REQUIRE_EQUAL(record_info.json_capacity, 0); // capacity of json is stored in meta

		BOOST_REQUIRE_EQUAL(record_info.data_timestamp, null_ts); // timestamp is stored in meta

		/* since iterator is run with no_meta flags, it will not read meta and
		 * will not know what is actually stored in the record.
		 */
		const auto minimal_size = [&] () -> uint64_t {
			if (record.is_committed()) {
				return record.json_capacity() + record.data().size();
			} else {
				return 0;
			}
		} ();
		BOOST_REQUIRE_GE(record_info.data_size, minimal_size);

		BOOST_REQUIRE_EQUAL(result.json().size(), 0);
		BOOST_REQUIRE_EQUAL(result.json().to_string(), std::string());
		BOOST_REQUIRE_EQUAL(result.data().size(), 0);
		BOOST_REQUIRE_EQUAL(result.data().to_string(), std::string());


		BOOST_REQUIRE_EQUAL(result.iterated_keys(), ++index);
		BOOST_REQUIRE_EQUAL(result.total_keys(), constants::numberof::all);
	}

	BOOST_REQUIRE_EQUAL(index, constants::numberof::all);
}


bool register_tests(const tests::nodes_data *setup) {
	using namespace tests;

	auto n = setup->node->get_native();

	ELLIPTICS_TEST_CASE(test_write_keys, use_session(n));

	ELLIPTICS_TEST_CASE(test_iterator, use_session(n));
	ELLIPTICS_TEST_CASE(test_iterator_with_data, use_session(n));
	ELLIPTICS_TEST_CASE(test_iterator_with_json, use_session(n));
	ELLIPTICS_TEST_CASE(test_iterator_with_json_and_data, use_session(n));

	{
		using namespace constants::numberof;
		// iterate first 2 keys
		ELLIPTICS_TEST_CASE(test_iterator_with_time_range, use_session(n), 0, 1);
		// iterate some 2 keys
		ELLIPTICS_TEST_CASE(test_iterator_with_time_range, use_session(n), 10, 11);
		// iterate all committed keys
		ELLIPTICS_TEST_CASE(test_iterator_with_time_range, use_session(n), 0, committed::all - 1);
		// iterate all uncommitted keys
		ELLIPTICS_TEST_CASE(test_iterator_with_time_range, use_session(n), committed::all, all - 1);
		// iterate all keys
		ELLIPTICS_TEST_CASE(test_iterator_with_time_range, use_session(n), 0, all - 1);
	}

	ELLIPTICS_TEST_CASE(test_iterator_no_meta, use_session(n));

	/* TODO:
	 * * iterate with time range and json
	 * * iterate with time range and data
	 * * iterate with time range, json and data
	 * * iterate with no_meta and time_range
	 * * iterate with no_meta and json
	 * * iterate with no_meta and data
	 * * iterate with no_meta, json and data
	 * * iterate with no_meta, time_range and json
	 * * iterate with no_meta, time_range and data
	 * * iterate with no_meta, time_range, json and data
	 * * iterate with key_range
	 * * iterate with few key_ranges
	 * * iterate with no_meta and few key_ranges
	 * * iterate with time_range and few key_ranges
	 * * iterate with no_meta, time_range, and few key_ranges
	 * * examine all combination of time_range, key_ranges, no_meta, json and data
	 */

	return true;
}

} /* namespace */


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

	return tests::configure_test_setup(path);
}


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

nodes_data* get_setup()
{
	return setup.get();
}

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
