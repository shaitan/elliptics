/*
 * 2015+ Copyright (c) Andrey Budnik <budnik27@gmail.com>
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

#include "test_base.hpp"
#include "test_session.hpp"
#include "library/elliptics.h"

#define BOOST_TEST_NO_MAIN
#define BOOST_TEST_ALTERNATIVE_INIT_API
#include <boost/test/included/unit_test.hpp>

#include <boost/program_options.hpp>

using namespace ioremap::elliptics;
using namespace boost::unit_test;

namespace tests {

static size_t backends_count = 1;
static int stall_count = 2;
static int wait_timeout = 1;
static uint8_t reconnect_batch_size = 2;

static server_config default_value(size_t server_index, bool interconnected)
{
	// Minimize number of threads
	server_config server = server_config::default_value();
	server.options
		("io_thread_num", 1)
		("nonblocking_io_thread_num", 1)
		("net_thread_num", 1)
		("caches_number", 1)
		("reconnect_batch_size", reconnect_batch_size)
	;

	server.backends[0]("enable", true)("group", static_cast<int>(server_index + 1));

	server.backends.resize(backends_count, server.backends.front());

	if (!interconnected) {
		// Make server to interconnect with itself => no remotes
		server.custom_remote_indexes = std::unordered_set<size_t>{ server_index };
	}

	return server;
}

/* Check timeout must be at least wait_timeout * stall_count seconds to
 * guarantee that reconnection process will not affect test_failed_connection_restore().
 * Otherwise reconnection thread may send transactions when command sending is already
 * disabled, while test logic is not even started, so stall counter can reach its limit
 * and BACKEND_STATUS will be send. These circumstances lead to network state destruction,
 * thereby requests from test_failed_connection_restore() will return ENXIO error,
 * instead of expected ETIMEDOUT error.
 */
static nodes_data::ptr setup_test_nodes(const std::string &path, size_t servers_count, bool interconnected,
                                        int check_timeout)
{
	std::vector<server_config> servers;
	for (size_t i = 0; i != servers_count; ++i) {
		server_config server = default_value(i, interconnected);
		servers.push_back(server);
	}

	start_nodes_config start_config(results_reporter::get_stream(), std::move(servers), path);
	start_config.fork = true;
	start_config.client_wait_timeout = wait_timeout;
	start_config.client_check_timeout = check_timeout;
	start_config.client_stall_count = stall_count;
	start_config.client_reconnect_batch_size = reconnect_batch_size;

	return start_nodes(start_config);
}

/* After tcp connection failure between client node and server node, all sended requests
 * from client to server node increase client's stall_count counter after request
 * timeout. When stall_count reaches it's configurable limit, then client node sends
 * 'ping' non-blocking request to server, and after timeout client removes timeouted
 * network state, so server node becomes logically unavailable.
 * Client node checks failed network states every check_timeout seconds and tries to
 * restore failed tcp conenction. If tcp connection successfully restored, then network
 * state becomes available, thereby client can send requests to server nodes.
 *
 * Following test checks this mechanics by disabling physical requests sending to remote node and
 * subsequent sending requests multiple times to reach given stall_count limit. After that,
 * physical request send is enabled, sleep some time (check_timeout seconds) and check, if
 * connection was restored by sending request and checking its response.
 */
static void test_failed_connection_restore(const std::string &temp_path)
{
	int check_timeout = wait_timeout * stall_count;

	auto nodes = setup_test_nodes(temp_path, 1, true, check_timeout);
	auto n = nodes->node->get_native();

	newapi::session sess(n);
	sess.set_groups({ 1 });
	sess.set_exceptions_policy(session::no_exceptions);
	test_session test_sess(sess);

	const server_node &node = nodes->nodes[0];
	const key id = std::string("dont_care");

	BOOST_REQUIRE_EQUAL(sess.state_num(), 1);

	ELLIPTICS_REQUIRE_ERROR(async_lookup_result, sess.lookup(id), -ENOENT);

	test_sess.toggle_all_command_send(false);

	/* using stall_count + 1 here to guarantee that state will actually
	 * be reset before this loop ends
	 */
	for (int i = 0; i < stall_count + 1; ++i)
	{
		auto async = sess.lookup(id);
		async.wait();

		/* state reset could happen a bit earlier (as a result of route list update processing in dnet_check)
		 * if so we should just stop the loop
		 */
		if (async.error().code() == -ENXIO) {
			break;
		}

		BOOST_REQUIRE(async.error().code() == -ETIMEDOUT);
	}

	BOOST_REQUIRE_EQUAL(sess.state_num(), 0);

	test_sess.toggle_all_command_send(true);

	// wait until background thread will restore connection with server node
	::sleep(check_timeout + 1);

	ELLIPTICS_REQUIRE_ERROR(async_lookup_result2, sess.lookup(id), -ENOENT);
	ELLIPTICS_REQUIRE(async_status_result2, sess.request_backends_status(node.remote()));
}

/* Node can hold massive queue of addresses to reconnect. When accessibility of all addresses is one-time restored (e.g.
 * datacenter is open), node mustn't try to reconnect all of them one time - otherwise node may receive too much route
 * lists and overfill its io_pool for a lot of time. Config parameter reconnect_batch_size tells node how many addresses
 * it can reconnect one time to. Current test checks that this parameter makes effect.
 */
static void test_failed_connections_restore_by_batches(const std::string &temp_path) {
	size_t servers_count = 4;
	int check_timeout = 5;

	// Unfortunately in test we can only check session's connections count (via state_num() method), and cannot
	// check a number of route_list requests sent. But if all servers are interconnected, we independently on
	// reconnect_batch_size will restore all connections at first reconnect iteration, because we'll reconnect
	// recursively to addresses from received route list. The way to prevent this - create servers which aren't
	// interconnected.
	auto nodes = setup_test_nodes(temp_path, servers_count, false /*not interconnected*/, check_timeout);
	auto n = nodes->node->get_native();

	newapi::session sess(n);
	sess.set_groups({ 1, 2, 3, 4 });
	sess.set_exceptions_policy(session::no_exceptions);
	test_session test_sess(sess);

	const server_node &node = nodes->nodes[0];
	const key id = std::string("dont_care");

	BOOST_REQUIRE_EQUAL(sess.state_num(), servers_count);

	ELLIPTICS_REQUIRE_ERROR(async_lookup_result, sess.lookup(id), -ENOENT);

	// Here we block sending of any command from client node. As result of this, replies don't come, and all the
	// transactions fails with timeout error. After stall_count of timeouted requests client node will try to ping
	// servers. But ping also is blocked to send. Without reply on ping, server became disconnected.
	test_sess.toggle_all_command_send(false);

	// Increase count of timeouted-requests, to cause stall_count overrun.
	for (int i = 0; i < stall_count; ++i) {
		auto async = sess.lookup(id);
		async.wait();
		auto err = async.error().code();

		// -ENXIO => no groups in route list
		// -ETIMEDOUT => lookup request is timed-out
		BOOST_REQUIRE(err == -ENXIO || err == -ETIMEDOUT);
	}

	// Wait for ping timeout. After this timeout ping fails, and connections are guaranteedly broken.
	::sleep(1);

	// Check that there aren't any connections
	BOOST_REQUIRE_EQUAL(sess.state_num(), 0);

	// Unblock sending of commands. So reconnect iterations became successful, because they're starting to get
	// responses on route_list.
	test_sess.toggle_all_command_send(true);

	// Here we check connections recovery progress. It mustn't be that all connections are one-time recovered.
	// Reconnect timeout check_timeout = 5, and we must grow by reconnect_batch_size = 2 connections each time.
	size_t prev_state_num = 0;

	while (true) {
		size_t state_num = sess.state_num();

		if (state_num != prev_state_num) {
			// Must grow by reconnect_batch_size = 2 connections each time
			BOOST_REQUIRE_EQUAL(state_num - prev_state_num, reconnect_batch_size);
			prev_state_num = state_num;
		}

		if (state_num == servers_count) {
			break;
		}

		::sleep(1);
	}

	// After connections are established, requests must cause responces with data info.
	ELLIPTICS_REQUIRE_ERROR(async_lookup_result2, sess.lookup(id), -ENOENT);
	ELLIPTICS_REQUIRE(async_status_result2, sess.request_backends_status(node.remote()));
}


bool register_tests(const std::string &temp_path)
{
	ELLIPTICS_TEST_CASE(test_failed_connection_restore, temp_path);
	ELLIPTICS_TEST_CASE(test_failed_connections_restore_by_batches, temp_path);

	return true;
}

std::string configure_test_setup_from_args(int argc, char *argv[])
{
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
		return NULL;
	}

	return path;
}

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

std::string temp_path;

bool init_func()
{
	return register_tests(temp_path);
}

}

int main(int argc, char *argv[])
{
	srand(time(nullptr));

	temp_path = configure_test_setup_from_args(argc, argv);

	return unit_test_main(init_func, argc, argv);
}
