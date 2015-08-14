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

#include <cocaine/context.hpp>
#include <cocaine/logging.hpp>

#include <elliptics/interface.h>

#include "elliptics.h"

#include "cocaine/idl/localnode.hpp"
#include "cocaine/traits/localnode.hpp"
#include "localnode.hpp"


namespace {

std::string to_string(const std::vector<int> &v)
{
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


namespace ioremap { namespace elliptics {

using namespace std::placeholders;

// Is there a better way to find groups that are served by this node?
std::vector<int> find_local_groups(session &sess)
{
	const auto &routes = sess.get_routes();
	const dnet_node *node = sess.get_native_node();
	std::set<int> unique_groups;
	for (const auto &route : routes) {
		for (int i = 0; i < node->addr_num; ++i) {
			if (dnet_addr_equal(&route.addr, &node->addrs[i])) {
				unique_groups.insert(route.group_id);
			}
		}
	}
	return std::move(std::vector<int>(unique_groups.begin(), unique_groups.end()));
}

localnode::localnode(cocaine::context_t& context, cocaine::io::reactor_t& reactor, const std::string& name, const Json::Value& args, dnet_node* node)
	: service_t(context, reactor, name, args)
	, log_(context, name)
	, session_proto_(node)
{
	COCAINE_LOG_DEBUG((&log_), "%s: enter", __func__);

	on<localnode_interface::read>(localnode_interface::read::alias(),
		std::bind(&localnode::read, this, _1, _2, _3, _4)
	);
	on<localnode_interface::write>(localnode_interface::write::alias(),
		std::bind(&localnode::write, this, _1, _2, _3, _4)
	);
	on<localnode_interface::lookup>(localnode_interface::lookup::alias(),
		std::bind(&localnode::lookup, this, _1, _2)
	);

	// find groups that are served by our node, and set them as session default
	session_proto_.set_groups(find_local_groups(session_proto_));
	COCAINE_LOG_INFO((&log_), "%s: found local groups: [%s]", __func__, to_string(session_proto_.get_groups()).c_str());

	COCAINE_LOG_DEBUG((&log_), "%s: exit", __func__);
}

error_info override_groups(session &s, const std::vector<int> &groups)
{
	// special case: empty group list is only meaningful if node serve
	// exactly single group, then is just a way to say:
	// 'execute command against whatever group you serving'

	if (groups.size() > 0)  {
		s.set_groups(groups);

	} else {
		if (s.get_groups().size() > 1) {
			return error_info(-6, "couldn't use group substitution on node which serve more then one group");
		}
	}
	return error_info();
}

deferred<data_pointer> localnode::read(const dnet_raw_id &key, const std::vector<int> &groups, uint64_t offset, uint64_t size)
{
	COCAINE_LOG_DEBUG((&log_), "%s: enter", __func__);

	deferred<data_pointer> promise;

	auto s = session_proto_.clone();
	s.set_exceptions_policy(session::no_exceptions);

	if (auto error = override_groups(s, groups)) {
		promise.abort(error.code(), error.message());
		return promise;
	}

	COCAINE_LOG_INFO((&log_), "%s: proposed groups: [%s]", __func__, to_string(groups).c_str());
	COCAINE_LOG_INFO((&log_), "%s: using groups: [%s]", __func__, to_string(s.get_groups()).c_str());

	s.read_data(elliptics::key(key), offset, size).connect(
		std::bind(&localnode::on_read_completed, this, promise, _1, _2)
	);

	COCAINE_LOG_DEBUG((&log_), "%s: exit", __func__);

	return promise;
}

deferred<dnet_async_service_result> localnode::write(const dnet_raw_id &key, const std::vector<int> &groups, const std::string &bytes, uint64_t offset)
{
	COCAINE_LOG_DEBUG((&log_), "%s: enter", __func__);

	deferred<dnet_async_service_result> promise;

	auto s = session_proto_.clone();
	s.set_exceptions_policy(ioremap::elliptics::session::no_exceptions);

	if (auto error = override_groups(s, groups)) {
		promise.abort(error.code(), error.message());
		return promise;
	}

	s.write_data(elliptics::key(key), bytes, offset).connect(
		std::bind(&localnode::on_write_completed, this, promise, _1, _2)
	);

	COCAINE_LOG_DEBUG((&log_), "%s: exit", __func__);

	return promise;
}

deferred<dnet_async_service_result> localnode::lookup(const dnet_raw_id &key, const std::vector<int> &groups)
{
	deferred<dnet_async_service_result> promise;

	auto s = session_proto_.clone();
	s.set_exceptions_policy(ioremap::elliptics::session::no_exceptions);

	if (auto error = override_groups(s, groups)) {
		COCAINE_LOG_ERROR((&log_), "%s: return error %d, %s", __func__, error.code(), error.message());
		promise.abort(error.code(), error.message());
		return promise;
	}

	s.lookup(elliptics::key(key)).connect(
		std::bind(&localnode::on_write_completed, this, promise, _1, _2)
	);

	return promise;
}

void localnode::on_read_completed(deferred<data_pointer> promise,
		const std::vector<ioremap::elliptics::read_result_entry> &result,
		const ioremap::elliptics::error_info &error)
{
	COCAINE_LOG_DEBUG((&log_), "%s: enter", __func__);

	if (error) {
		COCAINE_LOG_ERROR((&log_), "%s: return error %d, %s", __func__, error.code(), error.message());
		promise.abort(error.code(), error.message());
	} else {
		promise.write(result[0].file());
	}

	COCAINE_LOG_DEBUG((&log_), "%s: exit", __func__);
}

void localnode::on_write_completed(deferred<dnet_async_service_result> promise,
		const std::vector<ioremap::elliptics::lookup_result_entry> &results,
		const ioremap::elliptics::error_info &error)
{
	COCAINE_LOG_DEBUG((&log_), "%s: enter", __func__);

	if (error) {
		COCAINE_LOG_ERROR((&log_), "%s: return error %d, %s", __func__, error.code(), error.message());
		promise.abort(error.code(), error.message());
	} else {
		dnet_async_service_result r;
		const auto &single_result = results[0];
		r.addr = *single_result.storage_address();
		r.file_info = *single_result.file_info();
		r.file_path = single_result.file_path();
		COCAINE_LOG_INFO((&log_), "%s: return success", __func__);
		promise.write(r);
	}

	COCAINE_LOG_DEBUG((&log_), "%s: exit", __func__);
}


}} // namespace ioremap::elliptics
