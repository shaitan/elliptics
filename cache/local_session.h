/*
 * Copyright 2013+ Ruslan Nigmatullin <euroelessar@yandex.ru>
 *
 * This file is part of Elliptics.
 *
 * Elliptics is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Elliptics is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Elliptics.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LOCAL_SESSION_H
#define LOCAL_SESSION_H

#include "elliptics/utils.hpp"
#include "library/n2_protocol.hpp"

#include <chrono>

struct dnet_backend;

namespace ioremap { namespace elliptics {
class dnet_remove_request;
}} /* namespace ioremap::elliptics */

class local_session {
	local_session(const local_session&) = delete;
	local_session &operator =(const local_session &) = delete;
public:
	local_session(dnet_backend &backend, dnet_node *node);
	~local_session();

	void set_ioflags(uint32_t flags);
	void set_cflags(uint64_t flags);

	int read(const dnet_id &id,
	         uint64_t *user_flags,
	         ioremap::elliptics::data_pointer *json,
	         dnet_time *json_ts,
	         ioremap::elliptics::data_pointer *data,
	         dnet_time *data_ts);

	int write(const dnet_id &id, const char *data, size_t size, uint64_t user_flags, const dnet_time &timestamp);
	int write(const dnet_id &id,
	          uint64_t user_flags,
	          const std::string &json,
	          const dnet_time &json_ts,
	          const std::string &data,
	          const dnet_time &data_ts);

	std::unique_ptr<ioremap::elliptics::n2::lookup_response> lookup(const dnet_cmd &cmd, int *errp);

	int remove(const struct dnet_id &id, dnet_access_context *context = nullptr);
	int remove_new(const struct dnet_id &id,
	               const ioremap::elliptics::dnet_remove_request &request,
	               dnet_access_context *context = nullptr);

private:
	void clear_queue(int *errp = nullptr);

	dnet_backend &m_backend;
	dnet_net_state *m_state;
	uint32_t m_ioflags;
	uint64_t m_cflags;
};

#endif // LOCAL_SESSION_H
