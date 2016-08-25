/*
 * 2013+ Copyright (c) Ruslan Nigmatullin <euroelessar@yandex.ru>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include <algorithm>
#include <thread>

#include <boost/program_options.hpp>
#define BOOST_TEST_NO_MAIN
#define BOOST_TEST_ALTERNATIVE_INIT_API
#include <boost/test/included/unit_test.hpp>

#include "elliptics/interface.h"
#include "exec_context_data_p.hpp"

#include <cocaine/framework/manager.hpp>
#include <cocaine/framework/service.hpp>

#include <cocaine/traits/tuple.hpp>
#include "cocaine/idl/localnode.hpp"
#include "cocaine/traits/localnode.hpp"

#include "srw_test_base.hpp"

namespace {

std::string to_hex_string(const unsigned char * data, const size_t size)
{
	static const char hexchars[] = "0123456789abcdef";
	std::string result;
	result.reserve(size * 2);
	for (size_t i = 0; i < size; ++i) {
		const unsigned char byte = data[i];
		result.push_back(hexchars[(byte >> 4) & 0x0f]);
		result.push_back(hexchars[byte & 0x0f]);
	}
	return result;
}

std::string gen_random(const int len) {
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	std::string result;
	result.reserve(len);
	for (int i = 0; i < len; ++i) {
		result += alphanum[rand() % (sizeof(alphanum) - 1)];
	}
	return result;
}

} // anonymous namespace

/* required for localnode_test
 */

inline bool operator==(const dnet_record_info &a, const dnet_record_info &b)
{
	return (0 == memcmp(&a, &b, sizeof(a)));
}

inline std::ostream& operator<<(std::ostream& ostr, const dnet_record_info &v)
{
	ostr << "{\n record_flags=" << v.record_flags
		<< ",\n " << "user_flags=" << v.user_flags
		<< ",\n " << "json_timestamp=" << std::string(dnet_print_time(&v.json_timestamp))
		<< ",\n " << "json_offset=" << v.json_offset
		<< ",\n " << "json_size=" << v.json_size
		<< ",\n " << "json_capacity=" << v.json_capacity
		<< ",\n " << "data_timestamp=" << std::string(dnet_print_time(&v.data_timestamp))
		<< ",\n " << "data_offset=" << v.data_offset
		<< ",\n " << "data_size=" << v.data_size
		<< "\n}"
		;
	return ostr;
}

inline bool operator==(const dnet_io_info &a, const dnet_io_info &b)
{
	return (0 == memcmp(&a, &b, sizeof(a)));
}

inline std::ostream& operator<<(std::ostream& ostr, const dnet_io_info &v)
{
	ostr << "{\n json_size=" << v.json_size
		<< ",\n " << "data_offset=" << v.data_offset
		<< ",\n " << "data_size=" << v.data_size
		<< "\n}"
		;
	return ostr;
}

inline std::ostream& operator<<(std::ostream& ostr, const std::tuple<dnet_record_info, std::string> &v)
{
	ostr << "{\n record_info=" << std::get<0>(v)
		<< ",\n " << "value=" << std::get<1>(v)
		<< "\n}"
		;
	return ostr;
}
inline std::ostream &operator<<(std::ostream &ostr,
                                const std::tuple<dnet_record_info, ioremap::elliptics::data_pointer> &v) {
	ostr << "{\n record_info=" << std::get<0>(v)
		<< ",\n " << "value=" << std::get<1>(v).to_string()
		<< "\n}"
		;
	return ostr;
}


namespace tests {

using namespace ioremap::elliptics;
using namespace boost::unit_test;

static nodes_data::ptr configure_test_setup(const std::vector<std::string> &remotes, const std::string &path)
{
	if (remotes.empty()) {
		start_nodes_config start_config(results_reporter::get_stream(),
			std::vector<server_config>({
				server_config::default_srw_value().apply_options(config_data()
					("group", 1)
				),
				// server_config::default_srw_value().apply_options(config_data()
				// 	("group", 1)
				// ),
			}),
			path
		);

		return start_nodes(start_config);

	} else {
		return start_nodes(results_reporter::get_stream(), remotes, path);
	}
}

static nodes_data::ptr configure_test_setup_from_args(int argc, char *argv[])
{
	namespace bpo = boost::program_options;

	bpo::variables_map vm;
	bpo::options_description generic("Test options");

	std::vector<std::string> remotes;
	std::string path;

	generic.add_options()
			("help", "This help message")
			("remote", bpo::value(&remotes), "Remote elliptics server address")
			("path", bpo::value(&path), "Path where to store everything")
			;

	bpo::store(bpo::parse_command_line(argc, argv, generic), vm);
	bpo::notify(vm);

	if (vm.count("help")) {
		std::cerr << generic;
		return NULL;
	}

	return configure_test_setup(remotes, path);
}

/*
 * Checks retrieving info about application (via elliptics channel).
 */
static void test_info(session &client, const std::string &app_name)
{
	key key(std::string(__func__) + "info");
	key.transform(client);
	dnet_id id = key.id();

	ELLIPTICS_REQUIRE(async, client.exec(&id, app_name + "@info", ""));

	BOOST_REQUIRE_EQUAL(async.get().size(), 1);
	auto result = async.get()[0].context().data().to_string();
	BOOST_REQUIRE_GT(result.size(), 0);
	BOOST_REQUIRE_EQUAL(result[0], '{');
	BOOST_REQUIRE_EQUAL(result[result.size() - 1], '}');
}

/*
 * Checks response on event dispatching errors.
 */
static void test_dispatch_errors(session &client, const std::string &app_name)
{
	// -2 on system `info` event to unknown app
	{
		key key(std::string(__func__) + "info");
		key.transform(client);
		dnet_id id = key.id();

		auto async = client.exec(&id, "unknown-app@info", "");
		async.wait();
		BOOST_REQUIRE_EQUAL(async.error().code(), -2);
	}

	// -2 on any event to unknown app
	{
		key key(std::string(__func__) + "any-event");
		key.transform(client);
		dnet_id id = key.id();

		auto async = client.exec(&id, "unknown-app@any-event", "");
		async.wait();
		BOOST_REQUIRE_EQUAL(async.error().code(), -2);
	}

	/* -2 on unknown event to known app
	 *FIXME: right now error code is 1 because srw passes code received from the worker
	 * and this code is too uncertain now (also across different frameworks) to rely on it
	 * and to make a permanent translation into -2.
	 * Fix when cocaine will stabilize it.
	 */
	{
		key key(std::string(__func__) + "unknown-event");
		key.transform(client);
		dnet_id id = key.id();

		auto async = client.exec(&id, app_name + "@unknown-event", "");
		async.wait();
		BOOST_REQUIRE_EQUAL(async.error().code(), 1);
	}
}

/*
 * Checks worker response via worker's own elliptics client.
 * (For some time it was the only working way to respond.)
 * Original client is able to receive reply.
 */
static void test_echo_via_elliptics(session &client, const std::string &app_name, const std::string &data)
{
	key key_id(gen_random(8));
	key_id.transform(client);
	dnet_id id = key_id.id();

	ELLIPTICS_REQUIRE(exec_result, client.exec(&id, app_name + "@echo-via-elliptics", data));

	sync_exec_result result = exec_result;
	BOOST_REQUIRE_EQUAL(result.size(), 1);
	BOOST_REQUIRE_EQUAL(result[0].context().data().to_string(), data);
}

/*
 * Checks worker response via cocaine response stream.
 * From original client's point of view there should be no difference.
 * Original client is able to receive reply.
 */
static void test_echo_via_cocaine(session &client, const std::string &app_name, const std::string &data)
{
	key key_id(gen_random(8));
	key_id.transform(client);
	dnet_id id = key_id.id();

	ELLIPTICS_REQUIRE(exec_result, client.exec(&id, app_name + "@echo-via-cocaine", data));

	sync_exec_result result = exec_result;
	BOOST_REQUIRE_EQUAL(result.size(), 1);
	BOOST_REQUIRE_EQUAL(result[0].context().data().to_string(), data);
}

/*
 * Checks `push` processing expectations.
 * Original client receives nothing even from handlers that send replies.
 */
static void test_push(session &client, const std::string &app_name, const std::string &data)
{
	auto origin = exec_context_data::create("dummy-event", "dummy-data");

	{
		key key(std::string(__func__) + "noreply");
		key.transform(client);
		dnet_id id = key.id();
		ELLIPTICS_REQUIRE(async, client.push(&id, origin, app_name + "@noreply", data));
		BOOST_REQUIRE_EQUAL(async.get().size(), 0);
	}
	{
		key key(std::string(__func__) + "echo-via-elliptics");
		key.transform(client);
		dnet_id id = key.id();
		ELLIPTICS_REQUIRE(async, client.push(&id, origin, app_name + "@echo-via-elliptics", data));
		BOOST_REQUIRE_EQUAL(async.get().size(), 0);
	}
	{
		key key(std::string(__func__) + "echo-via-cocaine");
		key.transform(client);
		dnet_id id = key.id();
		ELLIPTICS_REQUIRE(async, client.push(&id, origin, app_name + "@echo-via-cocaine", data));
		BOOST_REQUIRE_EQUAL(async.get().size(), 0);
	}
}

/*
 * Checks `exec`->`push`(->`push`...) chaining.
 * Original client is able to receive reply from the end of the chain
 * (from it's point of view there should be no difference with test_echo_*).
 */
static void test_chain_via_elliptics(session &client, const std::string &app_name, const std::string &start_event,
                                     const std::string &data) {
	key key_id(__func__ + start_event);
	key_id.transform(client);
	dnet_id id = key_id.id();

	ELLIPTICS_REQUIRE(async, client.exec(&id, app_name + "@" + start_event, data));
	BOOST_REQUIRE_EQUAL(async.get().size(), 1);
	BOOST_REQUIRE_EQUAL(async.get()[0].context().data().to_string(), data);
}

/*
 * This funky thread is needed to periodically 'ping' network connection to given node,
 * since otherwise 3 timed out transaction in a row will force elliptics client to kill
 * this connection and all subsequent transactions will be timed out prematurely.
 *
 * State is only marked as 'stall' (and eventually will be killed) when it faces timeout transactions.
 * Read transactions will be quickly completed (even with ENOENT error), which resets stall
 * counter of the selected network connection.
 */
class thread_watchdog {
	public:
		session client;

		thread_watchdog(const session &client) : client(client), need_exit(false) {
			tid = std::thread(std::bind(&thread_watchdog::ping, this));
		}

		~thread_watchdog() {
			need_exit = true;
			tid.join();
		}

	private:
		std::thread tid;
		bool need_exit;

		void ping() {
			while (!need_exit) {
				client.read_data(std::string("test-key"), 0, 0).wait();
				sleep(1);
			}
		}
};

/*
 * Checks timeout mechanics on `exec` commands.
 *
 * Runs @num exec transactions with random timeouts.
 *
 * Timeouts must be set to less than 30 seconds, since 30 seconds is a magic number:
 * first, because that's the number of seconds cocaine application sleeps in 'noreply' event,
 * second, because cocaine sends heartbeats every 30 seconds (or at least complains that it didn't
 * receive heartbeat after 30 seconds) and kills application.
 *
 * Trying to set 'heartbeat-timeout' in profile to 60 seconds didn't help.
 * See tests/srw_test.hpp file where we actually set 3 different timeouts to 60 seconds,
 * but yet application is killed in 30 seconds.
 *TODO: check if this is still true after moving to cocaine v12.
 *
 * Basic idea behind this test is following: we run multiple exec transactions with random timeouts,
 * and all transactions must be timed out at most in 2 seconds after timeout expired. These 2 seconds
 * happen because of checker thread which checks timer tree every second and check time (in seconds)
 * must be greater than so called 'death' time.
 *
 * For more details see dnet_trans_iterate_move_transaction() function.
 */
static void test_timeout(session &client, const std::string &app_name)
{
	key key_id = app_name;
	key_id.transform(client);
	dnet_id id = key_id.id();

	// just a number of test transactions
	int num = 50;

	std::vector<std::pair<int, async_exec_result>> results;
	results.reserve(num);

	client.set_exceptions_policy(session::no_exceptions);

	thread_watchdog ping(client);

	for (int i = 0; i < num; ++i) {
		int timeout = rand() % 20 + 1;
		client.set_timeout(timeout);

		results.emplace_back(
		    std::make_pair(timeout, client.exec(&id, app_name + "@noreply-30seconds-wait", "some data")));
	}


	for (auto it = results.begin(); it != results.end(); ++it) {
		auto & res = it->second;

		res.wait();

		auto elapsed = res.elapsed_time();
		auto diff = elapsed.tsec - it->first;

		// 2 is a magic number of seconds, I tried to highlight it in the test description
		unsigned long max_diff = 2;

		if (diff >= max_diff) {
			printf("elapsed: %lld.%lld, timeout: %d, diff: %ld, must be less than %ld, error: %s [%d]\n",
					(unsigned long long)elapsed.tsec, (unsigned long long)elapsed.tnsec, it->first,
					diff, max_diff,
					res.error().message().c_str(), res.error().code());

			BOOST_REQUIRE_LE(elapsed.tsec - it->first, max_diff);
		}
	}
}

/*
 * Checks serializability of data structures used in `localnode` service interface.
 */
template<class T>
T pack_unpack(const T &v)
{
	msgpack::sbuffer buf;
	msgpack::pack(buf, v);

	msgpack::unpacked msg;
	msgpack::unpack(&msg, buf.data(), buf.size());

	return msg.get().as<T>();
}

static void test_localnode_data_serialization()
{
	{
		dnet_raw_id a = { "0123455678" };
		dnet_raw_id b = pack_unpack(a);
		BOOST_REQUIRE_EQUAL(std::string((const char *)a.id), std::string((const char *)b.id));
	}
	{
		dnet_time a = { 5, 8 };
		dnet_time b = pack_unpack(a);
		BOOST_REQUIRE_EQUAL(a.tsec, b.tsec);
		BOOST_REQUIRE_EQUAL(a.tnsec, b.tnsec);
	}
	{
		dnet_record_info a = { 1, 2, { 3, 4 }, 5, 6, 7, { 8, 9 }, 10, 11 };
		dnet_record_info b = pack_unpack(a);
		BOOST_REQUIRE_EQUAL(a, b);
	}
	{
		dnet_io_info a = { 1, 2, 3 };
		dnet_io_info b = pack_unpack(a);
		BOOST_REQUIRE_EQUAL(a, b);
	}
}

/*
 * Checks if `localnode` service methods are really working.
 */
static void test_localnode(session &client, const std::vector<int> &groups, int locator_port)
{
	using cocaine::framework::service_manager_t;

	service_manager_t::endpoint_type endpoint(boost::asio::ip::address_v4::loopback(), locator_port);
	service_manager_t manager({endpoint}, 1);

	cocaine::trace_t::current() = cocaine::trace_t(
		// trace
		client.get_trace_id(), client.get_trace_id(), cocaine::trace_t::zero_value,
		// rpc_name
		"srw_test"
	);

	auto localnode = manager.create<io::localnode_tag>("localnode");

	key key(gen_random(8));
	key.transform(client);

	auto value = gen_random(15);

	std::tuple<dnet_record_info, std::string> write_result;
	std::tuple<dnet_record_info, std::string> lookup_result;
	{
		auto &result = write_result;
		auto future = localnode.invoke<io::localnode::write>(key.raw_id(), groups, value);
		BOOST_REQUIRE_EQUAL(future.valid(), true);
		BOOST_REQUIRE_NO_THROW(result = std::move(future.get()));
		dnet_record_info record_info;
		std::string path;
		std::tie(record_info, path) = result;
		BOOST_CHECK_GT(record_info.data_size, 0);
		BOOST_CHECK_GT(path.size(), 0);
	}
	{
		auto &result = lookup_result;
		auto future = localnode.invoke<io::localnode::lookup>(key.raw_id(), groups);
		BOOST_REQUIRE_EQUAL(future.valid(), true);
		BOOST_REQUIRE_NO_THROW(result = std::move(future.get()));
		dnet_record_info record_info;
		std::string path;
		std::tie(record_info, path) = result;
		BOOST_CHECK_GT(record_info.data_size, 0);
		BOOST_CHECK_GT(path.size(), 0);
	}

	BOOST_CHECK_EQUAL(write_result, lookup_result);

	std::tuple<dnet_record_info, ioremap::elliptics::data_pointer> read_result;
	{
		auto &result = read_result;
		auto future = localnode.invoke<io::localnode::read>(key.raw_id(), groups, 0, 0);
		BOOST_REQUIRE_EQUAL(future.valid(), true);
		BOOST_REQUIRE_NO_THROW(result = std::move(future.get()));
	}

	/* read_result and write_result can't be compared byte-to-byte because
	 * read_result.data_offset is always 0 while write_result.data_offset
	 * carries proper data offset in a blob.
	 */
#define CMP(x) BOOST_REQUIRE_EQUAL(std::get<0>(write_result).x, std::get<0>(lookup_result).x)
	CMP(record_flags);
	CMP(user_flags);
	CMP(json_timestamp);
	CMP(json_offset);
	CMP(json_size);
	CMP(json_capacity);
	CMP(data_timestamp);
	// CMP(data_offset);
	CMP(data_size);
#undef CMP

	BOOST_CHECK_EQUAL(std::get<1>(read_result).to_string(), value);

	// check if methods could take flags
	{
		auto future = localnode.invoke<io::localnode::write>(key.raw_id(), groups, value,
			DNET_FLAGS_NOLOCK,
			DNET_IO_FLAGS_CACHE_ONLY
		);
		BOOST_REQUIRE_EQUAL(future.valid(), true);
		BOOST_REQUIRE_NO_THROW(future.get());
	}
	{
		auto future = localnode.invoke<io::localnode::lookup>(key.raw_id(), groups,
			DNET_FLAGS_NOLOCK
		);
		BOOST_REQUIRE_EQUAL(future.valid(), true);
		BOOST_REQUIRE_NO_THROW(future.get());
	}
	{
		auto future = localnode.invoke<io::localnode::read>(key.raw_id(), groups, 0, 0,
			DNET_FLAGS_NOLOCK,
			DNET_IO_FLAGS_CACHE | DNET_IO_FLAGS_NOCSUM
		);
		BOOST_REQUIRE_EQUAL(future.valid(), true);
		BOOST_REQUIRE_NO_THROW(future.get());
	}
}


/*
 * Place to list available tests.
 */
bool register_tests(const nodes_data *setup)
{
	/* IMPORTANT: Any testcase that uses session object should be registered
	 * with ELLIPTICS_TEST_CASE macro using session object exactly as a second argument --
	 * -- there is special variant of tests::make() in test_object.hpp,
	 * which is specifically tailored for test cases with session.
	 */

	const std::string app = application_name();
	auto n = setup->node->get_native();

	/* prerequisite: launch and init test application
	 * TODO: turn them collectively into some fixture
	 */
	ELLIPTICS_TEST_CASE(upload_application, setup->nodes[0].locator_port(), app, setup->directory.path());
	for (const auto &i : setup->nodes) {
		ELLIPTICS_TEST_CASE(start_application, i.locator_port(), app);
	}

	ELLIPTICS_TEST_CASE(init_application_impl, use_session(n, { 1 }), app, setup);

	ELLIPTICS_TEST_CASE(test_info, use_session(n, { 1 }), app);

	ELLIPTICS_TEST_CASE(test_dispatch_errors, use_session(n, { 1 }), app);

	// various ways to send a reply to an `exec` command
	ELLIPTICS_TEST_CASE(test_echo_via_elliptics, use_session(n, { 1 }), app, "some-data");
	ELLIPTICS_TEST_CASE(test_echo_via_elliptics, use_session(n, { 1 }), app, "some-data and long-data.. like this");
	ELLIPTICS_TEST_CASE(test_echo_via_cocaine, use_session(n, { 1 }), app, "some-data");
	ELLIPTICS_TEST_CASE(test_echo_via_cocaine, use_session(n, { 1 }), app, "some-data and long-data.. like this");

	// single `push` command does not expect reply at all
	ELLIPTICS_TEST_CASE(test_push, use_session(n, { 1 }), app, "some-data");

	/*FIXME: change tests accordingly: empty reply is a special case now
	 * (apps can't return empty data and get away with it)
	 * ELLIPTICS_TEST_CASE(test_echo_via_elliptics, use_session(n, { 1 }), app, "");
	 * ELLIPTICS_TEST_CASE(test_echo_via_cocaine, use_session(n, { 1 }), app, "");
	 * ELLIPTICS_TEST_CASE(test_push, use_session(n, { 1 }), app, "");
	 */

	// `exec`/`push` chains
	ELLIPTICS_TEST_CASE(test_chain_via_elliptics, use_session(n, {1}), app, "2-step-chain-via-elliptics",
	                    "some-data");
	ELLIPTICS_TEST_CASE(test_chain_via_elliptics, use_session(n, {1}), app, "3-step-chain-via-elliptics",
	                    "some-data");
	ELLIPTICS_TEST_CASE(test_chain_via_elliptics, use_session(n, {1}), app, "4-step-chain-via-elliptics",
	                    "some-data");

	// timeout mechanics on `exec` commands (long test -- at least 30 seconds long)
	ELLIPTICS_TEST_CASE(test_timeout, use_session(n, { 1 }), app);

	/* continuous load handles properly
	 *TODO: micro stress test similar to timeout test:
	 * - send vast stream of commands, big enough to affect concurrency rate
	 *   and number of spawned workers;
	 * - wait for completion;
	 * - check app info if load stat returned to zero
	 */

	// localnode service
	// * data structures
	ELLIPTICS_TEST_CASE_NOARGS(test_localnode_data_serialization);
	// * methods (first using matching group_id, then empty group list)
	ELLIPTICS_TEST_CASE(test_localnode, use_session(n, { 1 }), std::vector<int>{1}, setup->nodes[0].locator_port());
	ELLIPTICS_TEST_CASE(test_localnode, use_session(n, { 1 }), std::vector<int>{}, setup->nodes[0].locator_port());

	return true;
}

} // namespace tests


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
