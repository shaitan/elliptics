/*
 * 2015+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
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
#include "library/elliptics.h"
#include "library/logger.hpp"
#include <algorithm>

#include <blackhole/attribute.hpp>

#define BOOST_TEST_NO_MAIN
#define BOOST_TEST_ALTERNATIVE_INIT_API
#include <boost/test/included/unit_test.hpp>

#include <boost/program_options.hpp>

using namespace ioremap::elliptics;
using namespace boost::unit_test;

static std::initializer_list<int> ssend_src_groups {1};
static std::vector<int> ssend_dst_groups = {2, 3};
static size_t ssend_backends = 8;

const long ssend_timeout = 120;

static std::string print_groups(const std::vector<int> &groups) {
	std::ostringstream ss;
	for (size_t pos = 0; pos < groups.size(); ++pos) {
		ss << groups[pos];
		if (pos != groups.size() - 1)
			ss << ":";
	}

	return ss.str();
}

static tests::server_config ssend_server_config(int group)
{
	// Minimize number of threads
	tests::server_config server = tests::server_config::default_value();
	server.options
		("io_thread_num", 4)
		("nonblocking_io_thread_num", 4)
		("net_thread_num", 1)
		("caches_number", 1)
	;

	server.backends[0]("enable", true)("group", group);
	server.backends.resize(ssend_backends, server.backends.front());

	return server;
}

static tests::nodes_data::ptr configure_test_setup(const std::string &path)
{
	std::vector<tests::server_config> servers;
	for (const auto &g : ssend_src_groups) {
		tests::server_config server = ssend_server_config(g);
		servers.push_back(server);
	}
	for (const auto &g : ssend_dst_groups) {
		tests::server_config server = ssend_server_config(g);
		servers.push_back(server);
	}

	tests::start_nodes_config cfg(results_reporter::get_stream(), std::move(servers), path);
	cfg.fork = true;

	return tests::start_nodes(cfg);
}

static void ssend_test_insert_many_keys_old_ts(session &s, int num, const std::string &id_prefix,
                                               const std::string &data_prefix) {
	std::vector<async_write_result> results;
	s.set_timeout(ssend_timeout);
	s.set_trace_id(rand());
	for (int i = 0; i < num; ++i) {
		auto id = id_prefix + lexical_cast(i);
		auto data = data_prefix + lexical_cast(i);

		key k(id);
		s.transform(k);

		dnet_io_attr io;
		memset(&io, 0, sizeof(dnet_io_attr));

		memcpy(io.id, k.raw_id().id, DNET_ID_SIZE);

		dnet_current_time(&io.timestamp);
		io.timestamp.tsec -= 1000;

		results.push_back(s.write_data(io, data));
	}

	for (auto &r : results) {
		ELLIPTICS_REQUIRE(res, std::move(r));
	}
}

static void ssend_test_insert_many_keys(session &s, int num, const std::string &id_prefix,
                                        const std::string &data_prefix) {
	std::vector<async_write_result> results;
	s.set_timeout(ssend_timeout);
	s.set_trace_id(rand());
	for (int i = 0; i < num; ++i) {
		auto id = id_prefix + lexical_cast(i);
		auto data = data_prefix + lexical_cast(i);

		results.push_back(s.write_data(id, data, 0));
	}

	for (auto &r : results) {
		ELLIPTICS_REQUIRE(res, std::move(r));
	}
}

static void ssend_test_read_many_keys(session &s, int num, const std::string &id_prefix,
                                      const std::string &data_prefix) {
	std::vector<async_read_result> results;
	s.set_timeout(ssend_timeout);
	s.set_trace_id(rand());
	for (int i = 0; i < num; ++i) {
		auto id = id_prefix + lexical_cast(i);

		results.push_back(s.read_data(id, 0, 0));
	}

	for (int i = 0; i < num; ++i) {
		auto data = data_prefix + lexical_cast(i);

		ELLIPTICS_COMPARE_REQUIRE(res, std::move(results[i]), data);
	}
}

static void ssend_test_read_many_keys_error(session &s, int num, const std::string &id_prefix, int error)
{
        std::vector<async_read_result> results;
	s.set_exceptions_policy(session::no_exceptions);
	s.set_timeout(120);
	s.set_trace_id(rand());
	for (int i = 0; i < num; ++i) {
		auto id = id_prefix + lexical_cast(i);

		results.push_back(s.read_data(id, 0, 0));
	}

	for (auto &r : results) {
		ELLIPTICS_REQUIRE_ERROR(res, std::move(r), error);
	}
}

static std::vector<dnet_raw_id> ssend_ids(session &s)
{
	std::vector<dnet_raw_id> ret;
	std::set<uint32_t> backends;

	std::vector<int> groups = s.get_groups();
	std::vector<dnet_route_entry> routes = s.get_routes();

	for (auto it = routes.begin(); it != routes.end(); ++it) {
		const dnet_route_entry &entry = *it;
		if (std::find(groups.begin(), groups.end(), entry.group_id) != groups.end()) {
			auto back = backends.find(entry.backend_id);
			if (back == backends.end()) {
				backends.insert(entry.backend_id);
				ret.push_back(entry.id);
			}
		}
	}

	return ret;
}

static void ssend_test_copy(session &s, const std::vector<int> &dst_groups, int num, uint64_t iflags, int status)
{
	s.set_timeout(ssend_timeout);
	auto run_over_single_backend = [](session &s, const key &id, const std::vector<int> &dst_groups,
	                                  uint64_t iflags, int status) {
		std::vector<dnet_iterator_range> ranges;
		dnet_iterator_range whole;
		memset(whole.key_begin.id, 0, sizeof(dnet_raw_id));
		memset(whole.key_end.id, 0xff, sizeof(dnet_raw_id));
		ranges.push_back(whole);

		dnet_time time_begin, time_end;
		dnet_empty_time(&time_begin);
		dnet_current_time(&time_end);

		uint64_t ifl = DNET_IFLAGS_KEY_RANGE | DNET_IFLAGS_NO_META | iflags;

		s.set_trace_id(rand());
		auto iter = s.start_copy_iterator(id, ranges, ifl, time_begin, time_end, dst_groups);

		int copied = 0;

		char buffer[2*DNET_ID_SIZE + 1] = {0};

		auto log = s.get_logger();

		for (auto it = iter.begin(), end = iter.end(); it != end; ++it) {
#if 1
			/* we have to explicitly convert all members from dnet_iterator_response
			 * since it is packed and there will be alignment issues and
			 * following error:
			 * error: cannot bind packed field ... to int&
			 */
			DNET_LOG_DEBUG(log, "ssend_test: key: {}, backend: {}, user_flags: {:x}, ts: {} ({}), status: "
			                    "{} (should be: {}), size: {}, iterated_keys: {}/{}",
			               dnet_dump_id_len_raw(it->reply()->key.id, DNET_ID_SIZE, buffer),
			               it->command()->backend_id, it->reply()->user_flags,
			               dnet_print_time(&it->reply()->timestamp), it->reply()->timestamp.tsec,
			               it->reply()->timestamp.tnsec, it->reply()->status, status, it->reply()->size,
			               it->reply()->iterated_keys, it->reply()->total_keys);
#endif

			BOOST_REQUIRE_EQUAL(it->command()->status, 0);
			BOOST_REQUIRE_EQUAL(it->reply()->status, status);

			if (iflags & DNET_IFLAGS_DATA) {
				BOOST_REQUIRE_EQUAL(it->command()->size,
				                    sizeof(struct dnet_iterator_response) + it->reply()->size);
			} else {
				BOOST_REQUIRE_EQUAL(it->command()->size, sizeof(struct dnet_iterator_response));
			}

			copied++;
		}

		DNET_LOG_NOTICE(log, "ssend_test: {}: dst_groups: {}, copied: {}", id.to_string(),
		                print_groups(dst_groups), copied);

		return copied;
	};

	int copied = 0;
	std::vector<dnet_raw_id> ids = ssend_ids(s);
	for (const auto &id: ids) {
		copied += run_over_single_backend(s, id, dst_groups, iflags, status);
	}

	BOOST_REQUIRE_EQUAL(copied, num);
}

static void ssend_test_server_send(session &s, int num, const std::string &id_prefix, const std::string &data_prefix,
                                   const std::vector<int> &dst_groups, uint64_t iflags, int status,
                                   uint32_t exception_policy, const long timeout) {
	auto log = s.get_logger();

	s.set_exceptions_policy(exception_policy);
	s.set_timeout(timeout);
	s.set_trace_id(rand());
	std::vector<async_write_result> write_results;
	std::vector<std::string> keys;
	for (int i = 0; i < num; ++i) {
		auto id = id_prefix + lexical_cast(i);
		auto data = data_prefix + lexical_cast(i);

		write_results.push_back(s.write_data(id, data, 0));
		keys.push_back(id);
	}

	for (auto &r : write_results) {
		ELLIPTICS_REQUIRE(res, std::move(r));
	}

	DNET_LOG_NOTICE(log, "{}: keys: {}, dst_groups: {}, starting copy", __func__, num, print_groups(dst_groups));
	//char buffer[2*DNET_ID_SIZE + 1] = {0};

	int copied = 0;
	auto iter = s.server_send(keys, iflags, dst_groups);
	for (auto it = iter.begin(), iter_end = iter.end(); it != iter_end; ++it) {
#if 0
		/* we have to explicitly convert all members from dnet_iterator_response
		 * since it is packed and there will be alignment issues and
		 * following error:
		 * error: cannot bind packed field ... to int&
		 */
		DNET_LOG_DEBUG(log,
				"ssend_test: "
				"key: {}, backend: {}, user_flags: {:x}, ts: {}.{}, status: {}, size: {}, "
				"iterated_keys: {}/{}",
			dnet_dump_id_len_raw(it->reply()->key.id, DNET_ID_SIZE, buffer),
			(int)it->command()->backend_id,
			(unsigned long long)it->reply()->user_flags,
			(unsigned long long)it->reply()->timestamp.tsec, (unsigned long long)it->reply()->timestamp.tnsec,
			(int)it->reply()->status, (unsigned long long)it->reply()->size,
			(unsigned long long)it->reply()->iterated_keys, (unsigned long long)it->reply()->total_keys);
#endif
		BOOST_REQUIRE_EQUAL(it->command()->status, 0);
		BOOST_REQUIRE_EQUAL(it->reply()->status, status);

		copied++;
	}

	DNET_LOG_NOTICE(log, "{}: keys: {}, dst_groups: {}, copied total: {}", __func__, num, print_groups(dst_groups),
	                copied);

	/* timeout check is different, session timeout (i.e. transaction timeout) is the same as timeout for every write
	 * command send by the iterator or server_send method, which means that if write expires (slow backend), session
	 * will expire too, so we have to check async_result.error() instead of how many keys have been completed with
	 * timeout error
	 */
	if (status != -ETIMEDOUT) {
		BOOST_REQUIRE_EQUAL(copied, num);
	} else {
		BOOST_REQUIRE_EQUAL(iter.error().code(), status);
	}
}

static bool register_tests(const tests::nodes_data *setup)
{
	using namespace tests;

	auto n = setup->node->get_native();

	std::string id_prefix = "server send id";
	std::string data_prefix = "this is a test data";
	int num = 3000;

	uint64_t iflags = DNET_IFLAGS_MOVE | DNET_IFLAGS_DATA;

	/* the first stage - write many keys, move them, check that there are no keys
	 * in the source groups and that every destination group contains all keys written
	 *
	 * also test it with DATA flag - client should get not only iterator response
	 * per key, but also its data
	 */
	ELLIPTICS_TEST_CASE(ssend_test_insert_many_keys, use_session(n, ssend_src_groups), num, id_prefix, data_prefix);

	ELLIPTICS_TEST_CASE(ssend_test_copy, use_session(n, ssend_src_groups), ssend_dst_groups, num, iflags, 0);
	/* use no-exception session, since every read must return error here,
	 * with default session this ends up with exception at get/wait/result access time
	 */
	ELLIPTICS_TEST_CASE(ssend_test_read_many_keys_error, use_session(n, ssend_src_groups), num, id_prefix, -ENOENT);

	// check every dst group, it must contain all keys originally written into src groups
	for (auto g = ssend_dst_groups.begin(), gend = ssend_dst_groups.end(); g != gend; ++g) {
		ELLIPTICS_TEST_CASE(ssend_test_read_many_keys,
				use_session(n, {*g}, 0, 0), num, id_prefix, data_prefix);
	}

	/* the second stage - play with OVERWRITE bit
	 *
	 *
	 * there are no keys in @ssend_src_groups at this point
	 * write new data with the same keys as we have moved,
	 * but with older timestamp than that already written,
	 * so that move with timestamp cas would fail
	 */
	data_prefix = "new data prefix";
	ELLIPTICS_TEST_CASE(ssend_test_insert_many_keys_old_ts, use_session(n, ssend_src_groups), num, id_prefix,
	                    data_prefix);

	/* it should actually fail to move any key, since data is different and we
	 * do not set OVERWRITE bit, thus reading from source groups should succeed
	 * -EBADFD should be returned for cas/timestamp-cas errors
	 */
	ELLIPTICS_TEST_CASE(ssend_test_copy, use_session(n, ssend_src_groups), ssend_dst_groups, num, iflags, -EBADFD);
	ELLIPTICS_TEST_CASE(ssend_test_read_many_keys, use_session(n, ssend_src_groups), num, id_prefix, data_prefix);

	/* with OVERWRITE bit move should succeed - there should be no keys in @ssend_src_groups
	 * and all keys in @ssend_dst_groups should have been updated
	 */
	iflags = DNET_IFLAGS_OVERWRITE | DNET_IFLAGS_MOVE;
	ELLIPTICS_TEST_CASE(ssend_test_copy, use_session(n, ssend_src_groups), ssend_dst_groups, num, iflags, 0);
	ELLIPTICS_TEST_CASE(ssend_test_read_many_keys_error, use_session(n, ssend_src_groups), num, id_prefix, -ENOENT);

	for (auto g = ssend_dst_groups.begin(), gend = ssend_dst_groups.end(); g != gend; ++g) {
		ELLIPTICS_TEST_CASE(ssend_test_read_many_keys,
				use_session(n, {*g}, 0, 0), num, id_prefix, data_prefix);
	}


	// the third stage - write many keys, move them using @server_send() method, not iterator,
	// check that there are no keys in the source groups and that every destination group contains all keys written
	id_prefix = "server_send method test";
	data_prefix = "server_send method test data";
	iflags = DNET_IFLAGS_MOVE;
	ELLIPTICS_TEST_CASE(ssend_test_server_send, use_session(n, ssend_src_groups), num, id_prefix, data_prefix,
	                    ssend_dst_groups, iflags, 0, session::default_exceptions, ssend_timeout);
	ELLIPTICS_TEST_CASE(ssend_test_read_many_keys_error, use_session(n, ssend_src_groups), num, id_prefix, -ENOENT);
	for (auto g = ssend_dst_groups.begin(), gend = ssend_dst_groups.end(); g != gend; ++g) {
		ELLIPTICS_TEST_CASE(ssend_test_read_many_keys,
				use_session(n, {*g}, 0, 0), num, id_prefix, data_prefix);
	}

	// the fourth stage - check that plain copy iterator doesn't remove data
	iflags = 0;
	id_prefix = "plain iterator test";
	data_prefix = "plain iterator data";
	ELLIPTICS_TEST_CASE(ssend_test_insert_many_keys, use_session(n, ssend_src_groups), num, id_prefix, data_prefix);

	ELLIPTICS_TEST_CASE(ssend_test_copy, use_session(n, ssend_src_groups), ssend_dst_groups, num, iflags, 0);
	ELLIPTICS_TEST_CASE(ssend_test_read_many_keys, use_session(n, ssend_src_groups), num, id_prefix, data_prefix);
	for (auto g = ssend_dst_groups.begin(), gend = ssend_dst_groups.end(); g != gend; ++g) {
		ELLIPTICS_TEST_CASE(ssend_test_read_many_keys,
				use_session(n, {*g}, 0, 0), num, id_prefix, data_prefix);
	}

	// the fifth stage - check that copy-iterator doesn't move keys to itself:
	// write many keys, move them using @start_copy_iterator() method with destination groups
	// equal to the source groups and check that no keys were moved
	iflags = DNET_IFLAGS_MOVE;
	id_prefix = "server_send self write test";
	data_prefix = "server_send self write data";
	ELLIPTICS_TEST_CASE(ssend_test_insert_many_keys, use_session(n, ssend_src_groups), num, id_prefix, data_prefix);
	ELLIPTICS_TEST_CASE(ssend_test_copy, use_session(n, ssend_src_groups), ssend_src_groups, 0, iflags, 0);


	/* Check that server_send returns error (-ENXIO) occurred while writing a record.
	 */

	id_prefix = "-ENXIO handling test";
	data_prefix = "-ENXIO handling data";
	iflags = 0;
	ELLIPTICS_TEST_CASE(ssend_test_server_send, use_session(n, ssend_src_groups), 1, id_prefix, data_prefix,
	                    std::vector<int>{1000}, iflags, -ENXIO, session::no_exceptions, ssend_timeout);

#if (!DISABLE_LONG_TEST)
	/* Check that server_send returns error (-ETIMEDOUT) occurred during writing a record.
	 * This test is disabled because it takes too much time.
	 * TODO: Expedite the completion of the test by setting smaller timeout which require
	 *     the ability to set timeout to write commands which will be sent by dnet_ioserv
	 *     while executing server-send.
	 */
	id_prefix = "-ETIMEDOUT handling test";
	data_prefix = "-ETIMEDOUT handling data";
	iflags = 0;

	std::vector<int> delayed_groups{ssend_dst_groups[0]};
	std::unordered_set<int> delayed_groups_set(delayed_groups.begin(), delayed_groups.end());
	ELLIPTICS_TEST_CASE(set_delay_for_groups, use_session(n, ssend_src_groups), delayed_groups_set, 61000);

	ELLIPTICS_TEST_CASE(ssend_test_server_send, use_session(n, ssend_src_groups), 1, id_prefix, data_prefix,
	                    delayed_groups, iflags, -ETIMEDOUT, session::no_exceptions, 30);
#endif

	return true;
}

static tests::nodes_data::ptr configure_test_setup_from_args(int argc, char *argv[])
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
