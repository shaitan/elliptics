#include <cerrno>
#include <cstring>
#include <vector>
#include <random>

#include <boost/program_options.hpp>

#define BOOST_TEST_NO_MAIN
#define BOOST_TEST_ALTERNATIVE_INIT_API
#include <boost/test/included/unit_test.hpp>

#include <eblob/blob.h>

#include "elliptics/newapi/session.hpp"
#include "example/eblob_backend.h"
#include "library/common.hpp"

#include "test_base.hpp"

namespace constants {
constexpr auto HEADERS_SIZE = sizeof(eblob_disk_control) + sizeof(dnet_ext_list_hdr);
constexpr auto group_id = 1;
}

namespace tests {

namespace bu = boost::unit_test;

nodes_data::ptr configure_test_setup(const std::string &path) {
	auto server_config = [] (int group) {
		return tests::server_config::default_value().apply_options(tests::config_data() ("group", group));
	};

	/* Create 1 server node containing one groups.
	 */
	auto configs = {server_config(constants::group_id)};

	start_nodes_config config(bu::results_reporter::get_stream(), configs, path);
	config.fork = true;

	return start_nodes(config);
}

} // namespace tests


namespace {

struct headers_test_case {
	int expected_status;

	uint64_t dc_flags;
	uint64_t dc_data_size;
	uint64_t dc_disk_size;

	uint8_t ehdr_version;
	uint64_t ehdr_timestamp_seconds;

	uint8_t pad1[3];
	uint64_t pad2[2];
};

std::vector<headers_test_case> marginal_cases = {
	// 'Valid header in user data' cases.
	{-EILSEQ, 1, 100, 100, DNET_EXT_VERSION_V1, 0, {0}, {0}},
	{-EILSEQ, 1, 100, 100, DNET_EXT_VERSION_V1, DNET_SERVER_SEND_BUGFIX_TIMESTAMP, {0}, {0}},
	{-EILSEQ, 1, 100, 101, DNET_EXT_VERSION_V1, DNET_SERVER_SEND_BUGFIX_TIMESTAMP, {0}, {0}},
	{-EILSEQ, (1 << 9) - 1, 100, 101, DNET_EXT_VERSION_V1, DNET_SERVER_SEND_BUGFIX_TIMESTAMP, {0}, {0}},
	{-EILSEQ, (1 << 9) - 1, 1, 1024, DNET_EXT_VERSION_V1, DNET_SERVER_SEND_BUGFIX_TIMESTAMP, {0}, {0}},

	// Non-valid cases: this stamps look like headers in general, but have some not allowed fields values.
	// Flags not in range
	{0, 0, 100, 100, DNET_EXT_VERSION_V1, 0, {0}, {0}},
	{0, 1 << 9, 100, 100, DNET_EXT_VERSION_V1, 0, {0}, {0}},

	// data_size <= disk_size
	{0, 1, 100, 99, DNET_EXT_VERSION_V1, 0, {0}, {0}},
	{0, 1 << 9, 100, 42, DNET_EXT_VERSION_V1, 0, {0}, {0}},

	// disk_size == 0
	{0, 1, 0, 99, DNET_EXT_VERSION_V1, 0, {0}, {0}},
	// version != 1
	{0, 1, 1, 99, 0, 0, {0}, {0}},
	{0, 1, 1, 99, 2, 0, {0}, {0}},
	// timestamp out of range.
	{0, 1, 100, 101, DNET_EXT_VERSION_V1, DNET_SERVER_SEND_BUGFIX_TIMESTAMP + 1, {0}, {0}},
	{0, 1, 100, 101, DNET_EXT_VERSION_V1, DNET_SERVER_SEND_BUGFIX_TIMESTAMP + 42, {0}, {0}},
	{0, 1, 100, 101, DNET_EXT_VERSION_V1, DNET_SERVER_SEND_BUGFIX_TIMESTAMP + 100500, {0}, {0}},
	// broken timestamp + some padding
	{0, 1, 100, 101, DNET_EXT_VERSION_V1, DNET_SERVER_SEND_BUGFIX_TIMESTAMP + 1, {1, 0, 1}, {1, 1}},

	// Broken on padding
	{0, 1, 42, 42, DNET_EXT_VERSION_V1, 0, {1, 0, 0}, {0, 0}},
	{0, 1, 42, 42, DNET_EXT_VERSION_V1, 0, {0, 1, 0}, {0, 0}},
	{0, 1, 42, 42, DNET_EXT_VERSION_V1, 0, {0, 0, 1}, {0, 0}},
	{0, 1, 42, 42, DNET_EXT_VERSION_V1, 0, {0, 0, 0}, {1, 0}},
	{0, 1, 42, 42, DNET_EXT_VERSION_V1, 0, {0, 0, 0}, {0, 1}},
	{0, 1, 42, 42, DNET_EXT_VERSION_V1, 0, {0, 0, 0}, {1, 1}},
	{0, 1, 42, 42, DNET_EXT_VERSION_V1, 0, {1, 1, 1}, {0, 0}},
	{0, 1, 42, 42, DNET_EXT_VERSION_V1, 0, {1, 0, 1}, {0, 0}},
	{0, 1, 42, 42, DNET_EXT_VERSION_V1, 0, {1, 1, 1}, {1, 0}},
	{0, 1, 42, 42, DNET_EXT_VERSION_V1, 0, {1, 1, 1}, {0, 1}},
	{0, 1, 42, 42, DNET_EXT_VERSION_V1, 0, {1, 0, 1}, {1, 0}},
	{0, 1, 42, 42, DNET_EXT_VERSION_V1, 0, {1, 0, 1}, {0, 1}}
};

std::vector<headers_test_case> functional_cases = {
	{-EILSEQ, 1, 100, 100, DNET_EXT_VERSION_V1, 0, {0}, {0}},
	{0, 1, 100, 99, DNET_EXT_VERSION_V1, 0, {0}, {0}},

	{-EILSEQ, 1, 100, 100, DNET_EXT_VERSION_V1, 0, {0}, {0}},
	{0, 1 << 9, 100, 42, DNET_EXT_VERSION_V1, 0, {0}, {0}},

	{-EILSEQ, 1, 100, 100, DNET_EXT_VERSION_V1, DNET_SERVER_SEND_BUGFIX_TIMESTAMP, {0}, {0}},
	// disk_size == 0
	{0, 1, 0, 99, DNET_EXT_VERSION_V1, 0, {0}, {0}},
	// Broken padding
	{0, 1, 0, 99, DNET_EXT_VERSION_V1, 0, {0, 1, 0}, {0}},
};
}

namespace tests {

void test_random_valid_headers(unsigned int number) {
	std::default_random_engine random_generator;

	std::uniform_int_distribution<uint64_t> flags_distribution(1, (1 << 9) - 1);
	std::uniform_int_distribution<uint64_t> disk_size_distribution(1, std::numeric_limits<uint64_t>::max() - 4096);
	std::uniform_int_distribution<uint64_t> data_size_distribution(0, 4096);
	std::uniform_int_distribution<uint64_t> timestamp_distribution(0, DNET_SERVER_SEND_BUGFIX_TIMESTAMP);

	// Create valid headers stamp.
	const auto make_random_header = [&] (const size_t to_add = 0) {
		auto buffer = data_pointer::allocate(constants::HEADERS_SIZE + to_add);

		auto dc = buffer.data<eblob_disk_control>();
		auto ehdr = buffer.skip<eblob_disk_control>().data<dnet_ext_list_hdr>();

		dc->flags = flags_distribution(random_generator);
		dc->disk_size = disk_size_distribution(random_generator);
		dc->data_size = dc->disk_size - data_size_distribution(random_generator);
		dc->position = 0;

		ehdr->version = DNET_EXT_VERSION_V1;
		ehdr->timestamp.tsec = timestamp_distribution(random_generator);
		ehdr->timestamp.tnsec = timestamp_distribution(random_generator);

		ehdr->__pad1[0] = 0;
		ehdr->__pad1[1] = 0;
		ehdr->__pad1[2] = 0;

		ehdr->__pad2[0] = 0;
		ehdr->__pad2[1] = 0;

		return buffer;
	};

	while(number--) {
		const auto hdr = make_random_header(number);
		BOOST_REQUIRE_EQUAL(blob_check_corrupted_stamp(hdr.data(), hdr.size()), -EILSEQ);
	}
}

data_pointer make_headers_stamp(const headers_test_case &test_case, size_t to_add = 0, size_t to_back_remove = 0) {
	auto buffer = data_pointer::allocate(constants::HEADERS_SIZE + to_add);

	memset(buffer.data(), 0, constants::HEADERS_SIZE);

	auto dc = buffer.data<eblob_disk_control>();
	auto ehdr = buffer.skip<eblob_disk_control>().data<dnet_ext_list_hdr>();

	dc->flags = test_case.dc_flags;
	dc->data_size = test_case.dc_data_size;
	dc->disk_size = test_case.dc_disk_size;

	ehdr->version = test_case.ehdr_version;
	ehdr->timestamp.tsec = test_case.ehdr_timestamp_seconds;
	ehdr->timestamp.tnsec = test_case.ehdr_timestamp_seconds ^ 1; // just for completeness.

	memcpy(ehdr->__pad1, test_case.pad1, sizeof(test_case.pad1));
	memcpy(ehdr->__pad2, test_case.pad2, sizeof(test_case.pad2));

	return data_pointer::copy(buffer.slice(0, constants::HEADERS_SIZE + to_add - to_back_remove));
}

// Test valid headers with explicitly set fields, most checks for marginal headers fields values.
void test_explicit_headers() {
	for(const auto &test_case : marginal_cases) {
		const auto stamp = make_headers_stamp(test_case);

		BOOST_REQUIRE_EQUAL(blob_check_corrupted_stamp(stamp.data(), stamp.size()), test_case.expected_status);
		BOOST_REQUIRE_EQUAL(blob_check_corrupted_stamp(stamp.data(), stamp.size() - 1), 0);
	}
}


// TODO(karapuz): recreate blob file with different offsets.
void test_read_corrupted_stamp(ioremap::elliptics::newapi::session &s) {
	using namespace ioremap::elliptics;

	s.set_groups({constants::group_id});

	struct test_write_result {
		std::string key;
		int expected_status;
		size_t data_size;
		newapi::async_write_result async_result;
	};

	const auto make_write_result = [&] (const std::string &key_prefix,
	                                    const headers_test_case &test_case,
	                                    int ec,
	                                    bool with_json = false,
	                                    size_t to_add = 0,
	                                    size_t to_remove = 0) {
		std::ostringstream key;
		key << key_prefix
			<< " expected error: " << ec
			<< " to add: " << to_add
			<< " to_remove " << to_remove;

		if (with_json) {
			key << " with_json";
		}

		auto k = key.str();
		auto data = make_headers_stamp(test_case, to_add, to_remove);

		auto async = with_json ?
			s.write(k, R"json({"some": {"json": "value"}})json", 1024 - 1, data, 0) :
			s.write(k, "", 0, data, 0);

		return test_write_result{std::move(k),
		                         ec,
		                         constants::HEADERS_SIZE + to_add - to_remove,
		                         std::move(async)};
	};

	std::vector<test_write_result> write_results;

	for (const auto &test_case : functional_cases) {
		write_results.push_back(make_write_result("normal case", test_case, test_case.expected_status, false));
		write_results.push_back(make_write_result("normal case", test_case, test_case.expected_status, true));

		write_results.push_back(
			make_write_result("normal case (+1b)", test_case, test_case.expected_status, false, 1));
		write_results.push_back(
			make_write_result("normal case (+1b)", test_case, test_case.expected_status, true, 1));

		write_results.push_back(
			make_write_result("normal case (+2b)", test_case, test_case.expected_status, false, 2));
		write_results.push_back(
			make_write_result("normal case (+2b)", test_case, test_case.expected_status, true, 2));

		write_results.push_back(
			make_write_result("normal case (+3b)", test_case, test_case.expected_status, false, 2));
		write_results.push_back(
			make_write_result("normal case (+3b)", test_case, test_case.expected_status, true, 2));

		write_results.push_back(
			make_write_result("normal case (+1kb)", test_case, test_case.expected_status, false, 1024));
		write_results.push_back(
			make_write_result("normal case (+1kb)", test_case, test_case.expected_status, true, 1024));

		write_results.push_back(make_write_result("normal case (-1b)", test_case, 0, false, 0, 1));
		write_results.push_back(make_write_result("normal case (-1b)", test_case, 0, true, 0, 1));

		write_results.push_back(make_write_result("normal case (-2b)", test_case, 0, false, 0, 2));
		write_results.push_back(make_write_result("normal case (-2b)", test_case, 0, true, 0, 2));

		write_results.push_back(make_write_result("normal case (-3b)", test_case, 0, false, 0, 3));
		write_results.push_back(make_write_result("normal case (-3b)", test_case, 0, true, 0, 3));

		write_results.push_back(
			make_write_result("normal case (sizeof(eblob_disk_control))",
			                  test_case,
			                  0,
					  false,
			                  0,
			                  sizeof(dnet_ext_list_hdr)));

		write_results.push_back(
			make_write_result("normal case (with_json, sizeof(eblob_disk_control))",
			                  test_case,
			                  0,
			                  true,
			                  0,
			                  sizeof(dnet_ext_list_hdr)));


		write_results.push_back(
			make_write_result("one byte data", test_case, 0, false, 0, constants::HEADERS_SIZE - 1));
		write_results.push_back(
			make_write_result("one byte data", test_case, 0, true, 0, constants::HEADERS_SIZE - 1));

	}

	session lookup_session{s.get_native_node()};
	lookup_session.set_exceptions_policy(session::no_exceptions);
	lookup_session.set_groups(s.get_groups());
	auto lookup_csum_session = lookup_session.clone();
	lookup_csum_session.set_cflags(lookup_csum_session.get_cflags() | DNET_FLAGS_CHECKSUM);

	auto new_lookup_session = s.clone();
	auto new_lookup_csum_session = s.clone();
	new_lookup_csum_session.set_cflags(new_lookup_csum_session.get_cflags() | DNET_FLAGS_CHECKSUM);

	for (auto &write_result : write_results) {
		write_result.async_result.wait();

		{
			auto async = s.read_data(write_result.key, 0, 0);
			ELLIPTICS_REQUIRE_ERROR(res, std::move(async), write_result.expected_status);
		} {
			auto async = s.read(write_result.key, 0, 0);
			ELLIPTICS_REQUIRE_ERROR(res, std::move(async), write_result.expected_status);
		} {
			auto async = s.read_json(write_result.key);
			ELLIPTICS_REQUIRE(res, std::move(async));
		} {
			auto async = lookup_session.lookup(write_result.key);
			ELLIPTICS_REQUIRE(res, std::move(async));
		} {
			auto async = lookup_csum_session.lookup(write_result.key);
			ELLIPTICS_REQUIRE_ERROR(res, std::move(async), write_result.expected_status);
		} {
			auto async = new_lookup_session.lookup(write_result.key);
			ELLIPTICS_REQUIRE(res, std::move(async));
		} {
			auto async = new_lookup_csum_session.lookup(write_result.key);
			// new commands don't support returning checksums yet
			ELLIPTICS_REQUIRE(res, std::move(async));
		}

		if (write_result.data_size <= sizeof(eblob_disk_control)) {
			continue;
		}

		//
		// Different offests and data size requests.
		//
		{
			auto async = s.read_data(write_result.key, 11, 101);
			ELLIPTICS_REQUIRE_ERROR(res, std::move(async), write_result.expected_status);
		} {
			auto async = s.read_data(write_result.key, 1, constants::HEADERS_SIZE - 1);
			ELLIPTICS_REQUIRE_ERROR(res, std::move(async), write_result.expected_status);
		} {
			auto async = s.read_data(write_result.key, 1, constants::HEADERS_SIZE - 2);
			ELLIPTICS_REQUIRE_ERROR(res, std::move(async), write_result.expected_status);
		} {
			auto async = s.read_data(write_result.key, 101, 1);
			ELLIPTICS_REQUIRE_ERROR(res, std::move(async), write_result.expected_status);
		} {
			auto async = s.read_data(write_result.key, 101, 3);
			ELLIPTICS_REQUIRE_ERROR(res, std::move(async), write_result.expected_status);
		} {
			auto async = s.read(write_result.key, 11, 101);
			ELLIPTICS_REQUIRE_ERROR(res, std::move(async), write_result.expected_status);
		} {
			auto async = s.read(write_result.key, 101, 3);
			ELLIPTICS_REQUIRE_ERROR(res, std::move(async), write_result.expected_status);
		} {
			auto async = s.read(write_result.key, 4096, 3);
			auto ec = write_result.expected_status ? write_result.expected_status : -E2BIG;
			ELLIPTICS_REQUIRE_ERROR(res, std::move(async), ec);
		}
	} // for write results

	//
	// Bulk reads.
	//
	std::vector<dnet_id> all_illigal_stamp;
	std::vector<dnet_id> all_normal_data;
	std::vector<dnet_id> mixed;
	std::vector<int> mixed_statuses;

	for (const auto& wr : write_results) {
		key k(wr.key);

		k.transform(s);
		k.set_group_id(constants::group_id);

		const auto id = k.id();

		mixed.emplace_back(id);
		mixed_statuses.emplace_back(wr.expected_status);

		switch (wr.expected_status) {
		case 0:
			all_normal_data.emplace_back(id);
			break;
		case -EILSEQ:
			all_illigal_stamp.emplace_back(id);
			break;
		}
	}

	// Mixture of corrupted data chunks and normal data.
	int index = 0;
	for (const auto &r : s.bulk_read(mixed)) {
		BOOST_REQUIRE_EQUAL(r.status(), mixed_statuses[index]);
		++index;
	}

	for (const auto &r: s.bulk_read_json(mixed)) {
		BOOST_REQUIRE_EQUAL(r.status(), 0);
	}

	index = 0;
	for (const auto &r: s.bulk_read_data(mixed)) {
		BOOST_REQUIRE_EQUAL(r.status(), mixed_statuses[index]);
		++index;
	}

	// Corrupted data chunk.
	for (const auto &r: s.bulk_read(all_illigal_stamp)) {
		BOOST_REQUIRE_EQUAL(r.status(), -EILSEQ);
	}

	for (const auto &r: s.bulk_read_json(all_illigal_stamp)) {
		BOOST_REQUIRE_EQUAL(r.status(), 0);
	}

	for (const auto &r: s.bulk_read_data(all_illigal_stamp)) {
		BOOST_REQUIRE_EQUAL(r.status(), -EILSEQ);
	}

	// Normal data
	for (const auto &r: s.bulk_read(all_normal_data)) {
		BOOST_REQUIRE_EQUAL(r.status(), 0);
	}

	for (const auto &r: s.bulk_read_json(all_normal_data)) {
		BOOST_REQUIRE_EQUAL(r.status(), 0);
	}

	for (const auto &r: s.bulk_read_data(all_normal_data)) {
		BOOST_REQUIRE_EQUAL(r.status(), 0);
	}
}

} // namespace tests


bool register_tests(const tests::nodes_data *setup) {
	auto n = setup->node->get_native();

	// Test headers stamp for validity.
	ELLIPTICS_TEST_CASE(tests::test_random_valid_headers, 20000);
	ELLIPTICS_TEST_CASE(tests::test_explicit_headers);

	// Light functional tests to write/read some data.
	ELLIPTICS_TEST_CASE(tests::test_read_corrupted_stamp, tests::use_session(n));

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

	return tests::configure_test_setup(path);
}

/*
 * Common test initialization routine.
 */
using namespace tests;
using namespace boost::unit_test;

namespace {

std::shared_ptr<nodes_data> setup;

bool init_func()
{
	return register_tests(setup.get());
}

} // namespace

int main(int argc, char *argv[])
{
	// we own our test setup
	setup = configure_test_setup_from_args(argc, argv);

	int result = unit_test_main(init_func, argc, argv);

	// disassemble setup explicitly, to be sure about where its lifetime ends
	setup.reset();

	return result;
}
