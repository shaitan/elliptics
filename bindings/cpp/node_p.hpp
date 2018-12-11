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

#ifndef IOREMAP_ELLIPTICS_NODE_P_HPP
#define IOREMAP_ELLIPTICS_NODE_P_HPP

#include <elliptics/cppdef.h>

#include "library/logger.hpp"

namespace ioremap { namespace elliptics {

class node_data {
public:
	node_data(std::unique_ptr<dnet_logger> logger, std::unique_ptr<dnet_logger> access_logger_)
	: node_ptr(NULL)
	, logger(new trace_wrapper_t(std::move(logger)))
	, access_logger(nullptr)
	, destroy_node(true) {
		if (access_logger_)
			access_logger.reset(new trace_wrapper_t(std::move(access_logger_)));
	}

	~node_data() {
		if (destroy_node && node_ptr)
			dnet_node_destroy(node_ptr);
	}

	struct dnet_node *node_ptr;
	std::unique_ptr<trace_wrapper_t> logger;
	std::unique_ptr<trace_wrapper_t> access_logger;
	bool destroy_node;
};

class session_data {
public:
	session_data(const node &n);

	session_data(dnet_node *node);

	session_data(session_data &other);

	~session_data();

	struct dnet_session *session_ptr;
	result_filter filter;
	result_checker checker;
	result_error_handler error_handler;
	uint32_t policy;
};

}} // namespace ioremap::elliptics

// mix_states calls transform, so there is no need to call it twice
#define DNET_SESSION_GET_GROUPS(RESULT_TYPE) \
	std::vector<int> groups; \
	if (error_info error = mix_states(id, groups)) { \
		RESULT_TYPE result(*this); \
		async_result_handler<RESULT_TYPE::entry_type> handler(result); \
		handler.complete(error); \
		return result; \
	} else do {} while (false)


#endif // IOREMAP_ELLIPTICS_NODE_P_HPP
