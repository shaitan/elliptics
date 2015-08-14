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

#ifndef LOCALNODE_SERVICE_INTERFACE_HPP
#define LOCALNODE_SERVICE_INTERFACE_HPP

#include <cocaine/rpc/protocol.hpp>
#include <elliptics/packet.h>

namespace ioremap { namespace elliptics {

struct dnet_async_service_result {
	dnet_addr addr;
	dnet_file_info file_info;
	std::string file_path;
};

struct localnode_tag;

struct localnode_interface {

	struct read {
		typedef localnode_tag tag;

		static const char* alias() { return "read"; }

		typedef boost::mpl::list<
			dnet_raw_id,
			std::vector<int>,
			uint64_t,
			uint64_t
		> tuple_type;

		typedef std::string result_type;
	};

	struct write {
		typedef localnode_tag tag;

		static const char* alias() { return "write"; }

		typedef boost::mpl::list<
			dnet_raw_id,
			std::vector<int>,
			std::string,
			uint64_t
		> tuple_type;

		typedef dnet_async_service_result result_type;
	};

	struct lookup {
		typedef localnode_tag tag;

		static const char* alias() { return "lookup"; }

		typedef boost::mpl::list<
			dnet_raw_id,
			std::vector<int>
		> tuple_type;

		typedef dnet_async_service_result result_type;
	};
};

}} // namespace ioremap::elliptics


namespace cocaine { namespace io {

using ioremap::elliptics::localnode_tag;
using ioremap::elliptics::localnode_interface;

template<>
struct protocol<localnode_tag> {
	typedef boost::mpl::int_<1>::type version;

	typedef mpl::list<
		localnode_interface::read,
		localnode_interface::write,
		localnode_interface::lookup
	> type;
};

}} // namespace cocaine::io


#endif // LOCALNODE_SERVICE_INTERFACE_HPP
