#include <boost/program_options.hpp>

#define BOOST_TEST_NO_MAIN
#define BOOST_TEST_ALTERNATIVE_INIT_API
#include <boost/test/included/unit_test.hpp>

#include "test_base.hpp"

namespace tests {
namespace bu = boost::unit_test;

const uint32_t test_group = 1;

nodes_data::ptr configure_test_setup(const std::string &path) {
	auto server_config = [](const std::vector<int> &groups) {
		auto ret = server_config::default_value();
		ret.backends.resize(groups.size(), ret.backends.front());
		for (size_t i = 0; i < groups.size(); ++i) {
			ret.backends[i]("group", groups[i]);
		}
		return ret;
	};

	/* Create 3 server nodes each containing two groups.
	 * Groups 1, 2, 3 are used in all tests, while 4, 5, 6 are bulk_read-specific.
	 */
	auto configs = {server_config({test_group})};

	start_nodes_config config(bu::results_reporter::get_stream(), configs, path);
	config.fork = true;

	return start_nodes(config);
}

static void test_read_from_disk_via_cache(ioremap::elliptics::newapi::session &session,
                                          std::string &&key,
                                          std::string &&json,
                                          std::string &&data) {
	session.set_namespace("test_read_from_disk_via_cache" + key);
	session.set_exceptions_policy(ioremap::elliptics::session::exceptions_policy::default_exceptions);
	session.set_ioflags(0);
	session.set_cflags(DNET_FLAGS_NOCACHE);
	session.write(key, json, 0, data, 0).wait();

	session.set_ioflags(DNET_IO_FLAGS_CACHE);
	session.set_cflags(0);
	auto results = session.read(key, 0, 0).get();
	BOOST_REQUIRE_EQUAL(results.size(), 1);

	const auto &result = results[0];
	BOOST_REQUIRE_EQUAL(result.json().to_string(), json);
	BOOST_REQUIRE_EQUAL(result.data().to_string(), data);

}

static void test_read_from_disk_via_cache_with_offset_and_size(ioremap::elliptics::newapi::session &session,
                                                               std::string &&key,
                                                               std::string &&json,
                                                               std::string &&data) {
	session.set_namespace("test_read_from_disk_via_cache_with_offset_and_size" + key);
	session.set_exceptions_policy(ioremap::elliptics::session::exceptions_policy::default_exceptions);

	for (const uint64_t &offset : {uint64_t{0}, uint64_t{data.size() / 2}, uint64_t{data.size() - 1}}) {
		for (const uint64_t &size :
		     {uint64_t{0}, uint64_t{(data.size() - offset) / 2}, uint64_t{data.size() - offset}}) {
			key += "new"; // make key differ in each case
			session.set_ioflags(0);
			session.set_cflags(DNET_FLAGS_NOCACHE);
			session.write(key, json, 0, data, 0).wait();

			session.set_ioflags(DNET_IO_FLAGS_CACHE);
			session.set_cflags(0);
			auto results = session.read(key, offset, size).get();
			BOOST_REQUIRE_EQUAL(results.size(), 1);

			const auto &result = results[0];
			BOOST_REQUIRE_EQUAL(result.json().to_string(), json);
			BOOST_REQUIRE_EQUAL(result.data().to_string(),
			                    data.substr(offset, size == 0 ? std::string::npos : size));
		}
	}
}

static void test_write_via_cache(ioremap::elliptics::newapi::session &session,
                                 std::string &&key,
                                 std::string &&json,
                                 std::string &&data) {
	/* write @key into cache */
	session.set_namespace("test_write_via_cache" + key);
	session.set_exceptions_policy(ioremap::elliptics::session::exceptions_policy::default_exceptions);
	session.set_cflags(0);
	session.set_ioflags(DNET_IO_FLAGS_CACHE);
	session.write(key, json, 0, data, 0).wait();

	/* remove @key from cache only to make cache sync it to backend */
	session.set_ioflags(DNET_IO_FLAGS_CACHE_ONLY);
	session.remove(key).wait();

	/* read @key from disk */
	session.set_ioflags(0);
	session.set_cflags(DNET_FLAGS_NOCACHE);
	auto results = session.read(key, 0, 0).get();
	BOOST_REQUIRE_EQUAL(results.size(), 1);

	const auto &result = results[0];
	BOOST_REQUIRE_EQUAL(result.json().to_string(), json);
	BOOST_REQUIRE_EQUAL(result.data().to_string(), data);
}

bool register_tests(const nodes_data *setup) {
	auto n = setup->node->get_native();

	// test with json only
	ELLIPTICS_TEST_CASE(test_read_from_disk_via_cache, use_session(n, {test_group}),
	                    /*key*/ "key_with_json",
	                    /*json*/ "{\"key\":\"value\"}",
	                    /*data*/ "");
	// test with data only
	ELLIPTICS_TEST_CASE(test_read_from_disk_via_cache, use_session(n, {test_group}),
	                    /*key*/ "key_with_data",
	                    /*json*/ "",
	                    /*data*/ "data");
	// test with json & data
	ELLIPTICS_TEST_CASE(test_read_from_disk_via_cache, use_session(n, {test_group}),
	                    /*key*/ "key_with_json&data",
	                    /*json*/ "{\"key\":\"value\"}",
	                    /*data*/ "data");

	ELLIPTICS_TEST_CASE(test_read_from_disk_via_cache_with_offset_and_size, use_session(n, {test_group}),
	                    /*key*/ "key_with_json&data",
	                    /*json*/ "{\"key\":\"value\"}",
	                    /*data*/ "big data to cover case with offset");

	// test with json only
	ELLIPTICS_TEST_CASE(test_write_via_cache, use_session(n, {test_group}),
	                    /*key*/ "keys_with_json",
	                    /*json*/ "{\"key\":\"value\"}",
	                    /*data*/ "");
	// test with data only
	ELLIPTICS_TEST_CASE(test_write_via_cache, use_session(n, {test_group}),
	                    /*key*/ "keys_with_data",
	                    /*json*/ "",
	                    /*data*/ "data");
	// test with json & data
	ELLIPTICS_TEST_CASE(test_write_via_cache, use_session(n, {test_group}),
	                    /*key*/ "keys_with_json&data",
	                    /*json*/ "{\"key\":\"value\"}",
	                    /*data*/ "data");

	return true;
}

} /* namespace tests */


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
	return tests::register_tests(setup.get());
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
