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

#ifndef LOCALNODE_SERVICE_PROXY_HPP
#define LOCALNODE_SERVICE_PROXY_HPP

#include <cocaine/framework/service.hpp>

#include "cocaine/idl/localnode.hpp"
#include "cocaine/traits/localnode.hpp"

namespace ioremap { namespace elliptics {

using cocaine::framework::service_traits;

//
// Service proxy object.
// Provides native interface to the remote service on the client side.
//
struct localnode_proxy : public cocaine::framework::service_t
{
	static const unsigned int version = cocaine::io::protocol<localnode_tag>::version::value;

	localnode_proxy(std::shared_ptr<cocaine::framework::service_connection_t> connection)
		: service_t(connection)
	{
		// pass
	}

	service_traits<localnode_interface::read>::future_type
	read(const dnet_raw_id &id, const std::vector<int> &groups, uint64_t offset, uint64_t size) {
		return call<localnode_interface::read>(id, groups, offset, size);
	}

	service_traits<localnode_interface::write>::future_type
	write(const dnet_raw_id &id, const std::vector<int> &groups, const std::string &bytes, uint64_t offset)	{
		return call<localnode_interface::write>(id, groups, bytes, offset);
	}

	service_traits<localnode_interface::lookup>::future_type
	lookup(const dnet_raw_id &id, const std::vector<int> &groups) {
		return call<localnode_interface::lookup>(id, groups);
	}
};

}} // namespace ioremap::elliptics

#endif // LOCALNODE_SERVICE_PROXY_HPP
