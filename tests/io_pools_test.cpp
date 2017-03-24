#include <fstream>

#include <kora/dynamic.hpp>

#include <boost/program_options.hpp>

#define BOOST_TEST_NO_MAIN
#define BOOST_TEST_ALTERNATIVE_INIT_API
#include <boost/test/included/unit_test.hpp>

#include "test_base.hpp"

using namespace tests;
namespace bu = boost::unit_test;

nodes_data::ptr configure_test_setup(const std::string &path) {
	auto server_config = []() {
		auto ret = server_config::default_value();
		ret.backends.clear();
		return ret;
	} ();

	start_nodes_config config(bu::results_reporter::get_stream(), {server_config}, path);
	config.fork = true;

	return start_nodes(config);
}

static void enable_backend(ioremap::elliptics::newapi::session &s, const nodes_data *setup, uint32_t backend_id) {
	auto remote = setup->nodes.front().remote();
	ELLIPTICS_REQUIRE(async, s.enable_backend(remote, backend_id));
	BOOST_REQUIRE_EQUAL(async.get().size(), 1);
}

static void disable_backend(ioremap::elliptics::newapi::session &s, const nodes_data *setup, uint32_t backend_id) {
	auto remote = setup->nodes.front().remote();
	ELLIPTICS_REQUIRE(async, s.disable_backend(remote, backend_id));
	BOOST_REQUIRE_EQUAL(async.get().size(), 1);
}

static void remove_backend(ioremap::elliptics::newapi::session &s, const nodes_data *setup, uint32_t backend_id) {
	auto remote = setup->nodes.front().remote();
	ELLIPTICS_REQUIRE(async, s.remove_backend(remote, backend_id));
	BOOST_REQUIRE_EQUAL(async.get().size(), 1);
}

static void check_statistics(ioremap::elliptics::newapi::session &s, std::vector<std::tuple<uint32_t, std::string>> enabled_backends, std::vector<std::tuple<uint32_t, std::string>> disabled_backends) {
	if (enabled_backends.empty())
		// routes should be empty if no backends are enabled
		BOOST_REQUIRE_EQUAL(s.get_routes().size(), 0);

	ELLIPTICS_REQUIRE(async, s.monitor_stat(DNET_MONITOR_IO | DNET_MONITOR_BACKEND));
	auto results = async.get();
	BOOST_REQUIRE_EQUAL(results.size(), 1); // the only node is run

	auto statistics = [&results]() {
		auto json = results[0].statistics();
		std::istringstream stream(json);
		return kora::dynamic::read_json(stream);
	}();
	BOOST_REQUIRE(statistics.is_object());

	const auto &backends = statistics.as_object()["backends"];
	BOOST_REQUIRE(backends.is_object());
	BOOST_REQUIRE_EQUAL(backends.as_object().size(), enabled_backends.size() + disabled_backends.size());

	auto check_backend = [&backends](const std::tuple<uint32_t, std::string> tuple, bool enabled) {
		const auto backend_id = std::get<0>(tuple);
		const auto &pool_id = std::get<1>(tuple).empty() ? std::to_string(backend_id) : std::get<1>(tuple);

		const auto &backend = backends.as_object()[std::to_string(backend_id)];
		BOOST_REQUIRE(backend.is_object());
		BOOST_REQUIRE_EQUAL(backend.as_object()["backend_id"].as_uint(), backend_id);

		const auto &status = backend.as_object()["status"];
		BOOST_REQUIRE(status.is_object());
		BOOST_REQUIRE_EQUAL(status.as_object()["backend_id"].as_uint(), backend_id);
		BOOST_REQUIRE_EQUAL(status.as_object()["state"].as_uint(),
		                    enabled ? DNET_BACKEND_ENABLED : DNET_BACKEND_DISABLED);
		BOOST_REQUIRE_EQUAL(status.as_object()["pool_id"].as_string(), enabled ? pool_id : "");
		BOOST_REQUIRE_EQUAL(status.as_object()["group"].as_uint(), 1000 + backend_id);

		if (!enabled) {
			BOOST_REQUIRE(backend.as_object().find("io") == backend.as_object().end());
			return;
		}

		const auto &io = backend.as_object()["io"];
		BOOST_REQUIRE(io.is_object());

		const auto &blocking = io.as_object()["blocking"];
		BOOST_REQUIRE(blocking.is_object());
		BOOST_REQUIRE_EQUAL(blocking.as_object()["current_size"].as_uint(), 0);

		const auto &nonblocking = io.as_object()["nonblocking"];
		BOOST_REQUIRE(nonblocking.is_object());
		BOOST_REQUIRE_EQUAL(nonblocking.as_object()["current_size"].as_uint(), 0);
	};

	for (const auto &tuple : enabled_backends) {
		check_backend(tuple, true);
	}

	for (const auto &tuple : disabled_backends) {
		check_backend(tuple, false);
	}

	const auto &io = statistics.as_object()["io"];
	BOOST_REQUIRE(io.is_object());

	const auto &pools_stats = io.as_object()["pools"];
	BOOST_REQUIRE(pools_stats.is_object());

	auto pools = [&enabled_backends]() {
		std::unordered_set<std::string> ret;
		for (const auto &tuple : enabled_backends) {
			const auto &pool_id = std::get<1>(tuple);
			if (!pool_id.empty())
				ret.emplace(pool_id);
		}
		return std::move(ret);
	}();
	BOOST_REQUIRE_EQUAL(pools_stats.as_object().size(), pools.size());

	for (const auto &pool_id: pools) {
		const auto &pool = pools_stats.as_object()[pool_id];
		BOOST_REQUIRE(pool.is_object());
		{
			const auto &blocking = pool.as_object()["blocking"];
			BOOST_REQUIRE(blocking.is_object());
			BOOST_REQUIRE_EQUAL(blocking.as_object()["current_size"].as_uint(), 0);

			const auto &nonblocking = pool.as_object()["nonblocking"];
			BOOST_REQUIRE(nonblocking.is_object());
			BOOST_REQUIRE_EQUAL(nonblocking.as_object()["current_size"].as_uint(), 0);
		}
	}
}

static void test_empy_node(ioremap::elliptics::newapi::session &s) {
	check_statistics(s, {}, {});
}

static void add_backends_to_config(const nodes_data *setup, std::vector<std::tuple<uint32_t, std::string>> backends_to_add) {
	auto config_path = setup->nodes.front().config_path();

	auto config = [&config_path]() {
		// read and parse server config
		std::ifstream stream(config_path);
		return kora::dynamic::read_json(stream);
	}();
	auto &backends = config.as_object()["backends"];

	BOOST_REQUIRE(backends.is_array());
	BOOST_REQUIRE_EQUAL(backends.as_array().size(), 0);

	for (const auto &backend_to_add : backends_to_add) {
		const auto &backend_id = std::get<0>(backend_to_add);
		const auto &pool_id = std::get<1>(backend_to_add);

		// prepare directory for the backend
		std::string prefix = config_path.substr(0, config_path.find_last_of('/')) + '/' + std::to_string(backend_id);
		create_directory(prefix);
		create_directory(prefix + "/history");
		create_directory(prefix + "/blob");

		// add backend with individual pool
		kora::dynamic_t::object_t backend;
		backend["type"] = "blob";
		backend["backend_id"] = backend_id;
		backend["history"] = prefix + "/history";
		backend["data"] = prefix + "/blob";
		backend["group"] = 1000 + backend_id;
		if (!pool_id.empty())
			backend["pool_id"] = pool_id;
		backends.as_array().emplace_back(std::move(backend));
	}

	std::ofstream stream(config_path);
	kora::write_pretty_json(stream, config);
}

static void test_one_backend_with_individual_pool(ioremap::elliptics::newapi::session &s, const nodes_data *setup) {
	static const uint32_t backend_id = 1;

	// add backend with @backend_id and individual pool to config
	add_backends_to_config(setup, {std::make_tuple(backend_id, "")});
	// nothing should happen after config update
	check_statistics(s, {}, {});

	// repeat enabled/disable/remove 20 times
	// for (size_t i = 0; i < 20; ++i) {
		enable_backend(s, setup, backend_id);
		check_statistics(s, {std::make_tuple(backend_id, "")}, {});

		disable_backend(s, setup, backend_id);
		check_statistics(s, {}, {std::make_tuple(backend_id, "")});

		remove_backend(s, setup, backend_id);
		check_statistics(s, {}, {});
	// }

	// revert on-disk config to original one
	setup->nodes.front().config().write(setup->nodes.front().config_path());
}

static void test_one_backend_with_shared_pool(ioremap::elliptics::newapi::session &s, const nodes_data *setup) {
	static const uint32_t backend_id = 1;
	static const std::string pool_id = "bla";

	// add backend with @backend_id and shared pool to config
	add_backends_to_config(setup, {std::make_tuple(backend_id, pool_id)});
	// nothing should happen after config update
	check_statistics(s, {}, {});

	// repeat enabled/disable/remove 20 times
	// for (size_t i = 0; i < 20; ++i) {
		enable_backend(s, setup, backend_id);
		check_statistics(s, {std::make_tuple(backend_id, pool_id)}, {});

		disable_backend(s, setup, backend_id);
		check_statistics(s, {}, {std::make_tuple(backend_id, pool_id)});

		remove_backend(s, setup, backend_id);
		check_statistics(s, {}, {});
	// }

	// revert on-disk config to original one
	setup->nodes.front().config().write(setup->nodes.front().config_path());
}

static void test_two_backends_with_one_shared_pool(ioremap::elliptics::newapi::session &s, const nodes_data *setup) {
	static const std::array<uint32_t, 2> backends = {1, 2};
	static const std::string pool_id = "bla";

	// add backend with @backend_id and shared pool to config
	add_backends_to_config(setup, {std::make_tuple(backends[0], pool_id), std::make_tuple(backends[1], pool_id)});
	// nothing should happen after config update
	check_statistics(s, {}, {});

	// enable one by one backends

	enable_backend(s, setup, backends[0]);
	check_statistics(s, {std::make_tuple(backends[0], pool_id)}, {});

	enable_backend(s, setup, backends[1]);
	check_statistics(s, {std::make_tuple(backends[0], pool_id), std::make_tuple(backends[1], pool_id)}, {});

	// disable one by one backends

	disable_backend(s, setup, backends[0]);
	check_statistics(s, {std::make_tuple(backends[1], pool_id)}, {std::make_tuple(backends[0], pool_id)});

	disable_backend(s, setup, backends[1]);
	check_statistics(s, {}, {std::make_tuple(backends[0], pool_id), std::make_tuple(backends[1], pool_id)});

	// remove one by one backends

	remove_backend(s, setup, backends[0]);
	check_statistics(s, {}, {std::make_tuple(backends[1], pool_id)});

	remove_backend(s, setup, backends[1]);
	// after remove node should be returned to original state
	check_statistics(s, {}, {});

	// revert on-disk config to original one
	setup->nodes.front().config().write(setup->nodes.front().config_path());
}

bool register_tests(const nodes_data *setup) {
	auto n = setup->node->get_native();

	ELLIPTICS_TEST_CASE(test_empy_node, use_session(n));

	// Test node with 1 backend
	ELLIPTICS_TEST_CASE(test_one_backend_with_individual_pool, use_session(n), setup);
	ELLIPTICS_TEST_CASE(test_one_backend_with_shared_pool, use_session(n), setup);

	// Test node with 2 backends
	ELLIPTICS_TEST_CASE(test_two_backends_with_one_shared_pool, use_session(n), setup);
	// ELLIPTICS_TEST_CASE(test_two_backends_with_individual_pools, use_session(n), setup);
	// ELLIPTICS_TEST_CASE(test_two_backends_with_two_shared_pools, use_session(n), setup);
	// ELLIPTICS_TEST_CASE(test_two_backends_with_shared_and_individual_pools, use_session(n), setup);

	// TODO(shaitan): test start/stop node with enabled/disabled backends at start

	// TODO(shaitan): check via sending read/write/remove, backend_status etc. commands

	// TODO(shaitan): test affecting backend's delay on other backends which share the same pool

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
bool init_func() {
	return register_tests(setup.get());
}
}

int main(int argc, char *argv[]) {
	srand(time(nullptr));

	// we own our test setup
	setup = configure_test_setup_from_args(argc, argv);

	int result = unit_test_main(init_func, argc, argv);

	// disassemble setup explicitly, to be sure about where its lifetime ends
	setup.reset();

	return result;
}

