/*
 * 2015+ Copyright (c) Ivan Chelyubeev <ivan.chelubeev@gmail.com>
 * 2014 Copyright (c) Asier Gutierrez <asierguti@gmail.com>
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

#include <sstream>

#include "elliptics/interface.h"
#include "elliptics.h"

#include <blackhole/v1/logger.hpp>
#include <blackhole/v1/attribute.hpp>
#include <cocaine/context.hpp>
#include <cocaine/rpc/actor.hpp> // for factory
#include <cocaine/logging.hpp>

#include "cocaine/api/elliptics_node.hpp"
#include "cocaine/idl/localnode.hpp"
#include "cocaine/traits/localnode.hpp"
#include "localnode.hpp"


namespace {

std::string to_string(const std::vector<int> &v) {
	std::ostringstream ss;
	for (size_t i = 0; i < v.size(); ++i) {
		if (i > 0) {
			ss << ", ";
		}
		ss << v[i];
	}
	return ss.str();
}

}

namespace {

const uint64_t CFLAGS_WHITELIST = DNET_FLAGS_NOLOCK | DNET_FLAGS_NO_QUEUE_TIMEOUT | DNET_FLAGS_TRACE_BIT;
const uint64_t IOFLAGS_WHITELIST = DNET_IO_FLAGS_NOCSUM | DNET_IO_FLAGS_CACHE | DNET_IO_FLAGS_CACHE_ONLY;

}

namespace ioremap { namespace elliptics {

namespace ph = std::placeholders;

std::vector<int> find_local_groups(dnet_node *node)
{
	std::vector<int> result;

	for (rb_node *i = rb_first(&node->group_root); i != nullptr; i = rb_next(i)) {
		const dnet_group *group = rb_entry(i, dnet_group, group_entry);
		// take local groups only
		if (group->ids[0].idc->st == node->st) {
			result.push_back(group->group_id);
		}
	}

	return result;
}

struct debug_log_scope
{
	cocaine::logging::logger_t &logger;
	const char *name;

	debug_log_scope(cocaine::logging::logger_t &logger, const char *name) : logger(logger) , name(name)
	{
		COCAINE_LOG_DEBUG(logger, "{}: ENTER", name);
	}
	~debug_log_scope() {
		COCAINE_LOG_DEBUG(logger, "{}: EXIT", name);
	}
};

localnode::localnode(cocaine::context_t &context, asio::io_service &reactor, const std::string &name,
                     const cocaine::dynamic_t &args)
: cocaine::api::service_t(context, reactor, name, args)
, cocaine::dispatch<io::localnode_tag>(name)
, m_node(context.repository().get<cocaine::api::elliptics_node_t>("elliptics_node"))
, m_session_proto(m_node)
, m_log(context.log(name))
{
	debug_log_scope scope(*m_log, __func__);

	on<io::localnode::read>(std::bind(&localnode::read, this, ph::_1, ph::_2, ph::_3, ph::_4, ph::_5, ph::_6));
	on<io::localnode::write>(std::bind(&localnode::write, this, ph::_1, ph::_2, ph::_3, ph::_4, ph::_5));
	on<io::localnode::lookup>(std::bind(&localnode::lookup, this, ph::_1, ph::_2, ph::_3));

	// In the simplest case when node serves exactly one group, we want to free
	// client from the bother of providing group number: client will be allowed
	// to use an empty group list.
	{
		// We are forced to find all local groups anyway because there is no other
		// way to get the total number of the groups this node serves.
		const auto local_groups = find_local_groups(m_node);
		COCAINE_LOG_INFO(m_log, "{}: found local groups: [{}]", __func__, to_string(local_groups).c_str());
		if (local_groups.size() == 1) {
			m_session_proto.set_groups(local_groups);
		}
	}

	COCAINE_LOG_INFO(m_log, "{}: service initialized", __func__);
}

inline void override_groups(session &s, const std::vector<int> &groups)
{
	// Empty group list is only meaningful if node serve a single group.
	// In that case, empty groups are just a way to say: "please execute
	// my command against whatever group you are serving".
	if (!groups.empty())  {
		s.set_groups(groups);
	}
}

deferred<localnode::read_result> localnode::read(const dnet_raw_id &key, const std::vector<int> &groups, uint64_t offset, uint64_t size, uint64_t cflags, uint32_t ioflags)
{
	debug_log_scope scope(*m_log, __func__);

	uint64_t trace_id = cocaine::trace_t::current().get_trace_id();

	auto s = m_session_proto.clone();
	s.set_trace_id(trace_id);
	s.set_exceptions_policy(session::no_exceptions);
	override_groups(s, groups);

	s.set_cflags(cflags & CFLAGS_WHITELIST);
	s.set_ioflags(ioflags & IOFLAGS_WHITELIST);

	deferred<read_result> promise;

	s.read_data(elliptics::key(key), offset, size).connect(
		cocaine::trace_t::bind(&localnode::on_read_completed, this, promise, ph::_1, ph::_2)
	);

	return promise;
}

deferred<localnode::write_result> localnode::write(const dnet_raw_id &key, const std::vector<int> &groups, const std::string &bytes, uint64_t cflags, uint32_t ioflags)
{
	debug_log_scope scope(*m_log, __func__);

	uint64_t trace_id = cocaine::trace_t::current().get_trace_id();

	auto s = m_session_proto.clone();
	s.set_trace_id(trace_id);
	s.set_exceptions_policy(session::no_exceptions);
	override_groups(s, groups);

	s.set_cflags(cflags & CFLAGS_WHITELIST);
	s.set_ioflags(ioflags & IOFLAGS_WHITELIST);

	deferred<write_result> promise;

	//FIXME: add support for json, json_capacity and data_capacity?
	s.write(elliptics::key(key), "", 0, bytes, 0).connect(
		cocaine::trace_t::bind(&localnode::on_write_completed, this, promise, ph::_1, ph::_2)
	);

	return promise;
}

deferred<localnode::lookup_result> localnode::lookup(const dnet_raw_id &key, const std::vector<int> &groups, uint64_t cflags)
{
	debug_log_scope scope(*m_log, __func__);

	uint64_t trace_id = cocaine::trace_t::current().get_trace_id();

	auto s = m_session_proto.clone();
	s.set_trace_id(trace_id);
	s.set_exceptions_policy(session::no_exceptions);
	override_groups(s, groups);

	s.set_cflags(cflags & CFLAGS_WHITELIST);

	deferred<lookup_result> promise;

	s.lookup(elliptics::key(key)).connect(
		cocaine::trace_t::bind(&localnode::on_write_completed, this, promise, ph::_1, ph::_2)
	);

	return promise;
}

void localnode::on_read_completed(deferred<localnode::read_result> promise,
		const std::vector<newapi::read_result_entry> &results,
		const error_info &error)
{
	debug_log_scope scope(*m_log, __func__);

	if (error) {
		COCAINE_LOG_ERROR(m_log, "{}: return error {}, {}", __func__, error.code(), error.message());
		try {
			promise.abort(std::error_code(-error.code(), std::generic_category()), error.message());
		} catch(const std::exception &e) {
			COCAINE_LOG_ERROR(m_log, "{}: abort failed {}", __func__, e.what());
		}

	} else {
		const auto &r = results[0];
		COCAINE_LOG_DEBUG(m_log, "{}: return success", __func__);
		try {
			promise.write(std::make_tuple(r.record_info(), r.data()));
		} catch(const std::exception &e) {
			COCAINE_LOG_ERROR(m_log, "{}: write failed {}", __func__, e.what());
		}
	}
}

void localnode::on_write_completed(deferred<write_result> promise,
		const std::vector<newapi::write_result_entry> &results,
		const error_info &error)
{
	debug_log_scope scope(*m_log, __func__);

	if (error) {
		COCAINE_LOG_ERROR(m_log, "{}: return error {}, {}", __func__, error.code(), error.message());
		try {
			promise.abort(std::error_code(-error.code(), std::generic_category()), error.message());
		} catch(const std::exception &e) {
			COCAINE_LOG_ERROR(m_log, "{}: abort failed {}", __func__, e.what());
		}

	} else {
		const auto &r = results[0];
		COCAINE_LOG_DEBUG(m_log, "{}: return success", __func__);
		try {
			promise.write(std::make_tuple(r.record_info(), r.path()));
		} catch(const std::exception &e) {
			COCAINE_LOG_ERROR(m_log, "{}: write failed {}", __func__, e.what());
		}
	}
}

}} // namespace ioremap::elliptics
