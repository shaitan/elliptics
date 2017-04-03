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
/* Check timeout must be at least wait_timeout * stall_count seconds to
 * guarantee that reconnection process will not affect test_failed_connection_restore().
 * Otherwise reconnection thread may send transactions when command sending is already
 * disabled, while test logic is not even started, so stall counter can reach its limit
 * and BACKEND_STATUS will be send. These circumstances lead to network state destruction,
 * thereby requests from test_failed_connection_restore() will return ENXIO error,
 * instead of expected ETIMEDOUT error.
 */
static int check_timeout = wait_timeout * stall_count;

static server_config default_value()
{
	// Minimize number of threads
	server_config server = server_config::default_value();
	server.options
		("io_thread_num", 1)
		("nonblocking_io_thread_num", 1)
		("net_thread_num", 1)
		("caches_number", 1)
	;

	server.backends[0]("enable", true)("group", 1);

	server.backends.resize(backends_count, server.backends.front());

	return server;
}

static nodes_data::ptr configure_test_setup(const std::string &path)
{
	std::vector<server_config> servers;
	server_config server = default_value();
	servers.push_back(server);

	start_nodes_config start_config(results_reporter::get_stream(), std::move(servers), path);
	start_config.fork = true;
	start_config.client_wait_timeout = wait_timeout;
	start_config.client_check_timeout = check_timeout;
	start_config.client_stall_count = stall_count;

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
static void test_failed_connection_restore(session &sess, const nodes_data *setup)
{
	test_session test_sess(sess);

	const server_node &node = setup->nodes[0];
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


bool register_tests(const nodes_data *setup)
{
	auto n = setup->node->get_native();

	ELLIPTICS_TEST_CASE(test_failed_connection_restore, use_session(n, { 1 }, 0, 0), setup);

	return true;
}

nodes_data::ptr configure_test_setup_from_args(int argc, char *argv[])
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

	return configure_test_setup(path);
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
