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

#include "local_session.h"

#include <blackhole/attribute.hpp>

#include "library/backend.h"
#include "library/logger.hpp"
#include "library/protocol.hpp"

using namespace ioremap::elliptics;

#undef list_entry
#define list_entry(ptr, type, member) ({			\
	const list_head *__mptr = (ptr);	\
	(dnet_io_req *)( (char *)__mptr - dnet_offsetof(dnet_io_req, member) );})

#undef list_for_each_entry_safe
#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_entry((head)->next, decltype(*pos), member),	\
		n = list_entry(pos->member.next, decltype(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = list_entry(n->member.next, decltype(*n), member))

local_session::local_session(dnet_backend &backend, dnet_node *node)
: m_backend(backend)
, m_ioflags(DNET_IO_FLAGS_CACHE)
, m_cflags(DNET_FLAGS_NOLOCK) {
	m_state = reinterpret_cast<dnet_net_state *>(malloc(sizeof(dnet_net_state)));
	if (!m_state)
		throw std::bad_alloc();

	memset(m_state, 0, sizeof(dnet_net_state));

	m_state->__need_exit = -1;
	m_state->write_s = -1;
	m_state->read_s = -1;
	m_state->accept_s = -1;

	dnet_state_micro_init(m_state, node, node->addrs, 0);
	dnet_state_get(m_state);
}

local_session::~local_session()
{
	dnet_state_put(m_state);
	dnet_state_put(m_state);
}

void local_session::set_ioflags(uint32_t flags)
{
	m_ioflags = flags;
}

void local_session::set_cflags(uint64_t flags)
{
	m_cflags = flags;
}

int local_session::read(const dnet_id &id,
                        uint64_t *user_flags,
                        ioremap::elliptics::data_pointer *json,
                        dnet_time *json_ts,
                        ioremap::elliptics::data_pointer *data,
                        dnet_time *data_ts) {
	const uint64_t read_flags = (json ? DNET_READ_FLAGS_JSON : 0) | (data ? DNET_READ_FLAGS_DATA : 0);
	auto packet = serialize(dnet_read_request{/*ioflags*/ m_ioflags,
	                                          /*read_flags*/ read_flags,
	                                          /*data_offset*/ 0,
	                                          /*data_size*/ 0,
	                                          /*deadline*/ dnet_time{0, 0}});

	dnet_cmd cmd;
	memset(&cmd, 0, sizeof(cmd));

	cmd.id = id;
	cmd.cmd = DNET_CMD_READ_NEW;
	cmd.flags |= m_cflags;
	cmd.size = packet.size();
	cmd.backend_id = m_backend.backend_id();

	const int err = dnet_process_cmd_raw(m_state, &cmd, packet.data(), 0, 0, /*context*/ nullptr);
	if (err) {
		clear_queue();
		return err;
	}

	struct dnet_io_req *r, *tmp;

	list_for_each_entry_safe(r, tmp, &m_state->send_list, req_entry) {
		DNET_LOG_DEBUG(m_state->n, "hsize: {}, dsize: {}", r->hsize, r->dsize);

		dnet_cmd *req_cmd = reinterpret_cast<dnet_cmd *>(r->header ? r->header : r->data);

		DNET_LOG_DEBUG(m_state->n, "entry in list, status: {}", req_cmd->status);

		if (req_cmd->status) {
			const auto status = req_cmd->status;
			clear_queue();
			return status;
		} else if (req_cmd->size) {
			size_t roffset = 0;
			auto rdata = data_pointer::from_raw(req_cmd + 1, r->hsize ? r->hsize : r->dsize);
			dnet_read_response response;
			deserialize(rdata, response, roffset);

			if (user_flags)
				*user_flags = response.user_flags;
			if (json_ts)
				*json_ts = response.json_timestamp;
			if (data_ts)
				*data_ts = response.data_timestamp;

			DNET_LOG_DEBUG(m_state->n, "entry in list, size: {}", req_cmd->size);

			if (json)
				*json = data_pointer::copy(rdata.slice(roffset, response.read_json_size));

			if (data) {
				data_pointer result;

				if (r->data) {
					result = data_pointer::copy(r->data, r->dsize);
				} else if (response.read_data_size) {
					result = data_pointer::allocate(response.read_data_size);
					const ssize_t err = dnet_read_ll(r->fd, result.data<char>(), result.size(),
					                                 r->local_offset);
					if (err) {
						clear_queue();
						return err;
					}
				} else {
					result = data_pointer();
				}

				clear_queue();
				*data = std::move(result);
			}

			return 0;
		}
	}

	clear_queue();
	return -ENOENT;
}

int local_session::write(const dnet_id &id, const char *data, size_t size, uint64_t user_flags, const dnet_time &timestamp)
{
	dnet_io_attr io;
	memset(&io, 0, sizeof(io));
	dnet_empty_time(&io.timestamp);

	memcpy(io.id, id.id, DNET_ID_SIZE);
	memcpy(io.parent, id.id, DNET_ID_SIZE);
	io.flags |= DNET_IO_FLAGS_COMMIT | DNET_IO_FLAGS_NOCSUM | m_ioflags;
	io.size = size;
	io.num = size;
	io.user_flags = user_flags;
	io.timestamp = timestamp;

	if (dnet_time_is_empty(&io.timestamp))
		dnet_current_time(&io.timestamp);

	data_buffer buffer(sizeof(dnet_io_attr) + size);
	buffer.write(io);
	buffer.write(data, size);

	DNET_LOG_DEBUG(m_state->n, "going to write size: {}", size);

	data_pointer datap = std::move(buffer);

	dnet_cmd cmd;
	memset(&cmd, 0, sizeof(cmd));

	cmd.id = id;
	cmd.cmd = DNET_CMD_WRITE;
	cmd.flags |= m_cflags;
	cmd.size = datap.size();
	cmd.backend_id = m_backend.backend_id();

	int err = dnet_process_cmd_raw(m_state, &cmd, datap.data(), 0, 0, /*context*/ nullptr);

	clear_queue(&err);

	return err;
}

int local_session::write(const dnet_id &id,
                         uint64_t user_flags,
                         const std::string &json,
                         const dnet_time &json_ts,
                         const std::string &data,
                         const dnet_time &data_ts) {
	auto packet = serialize(dnet_write_request{
		/*ioflags*/ m_ioflags | DNET_IO_FLAGS_PREPARE | DNET_IO_FLAGS_COMMIT | DNET_IO_FLAGS_PLAIN_WRITE,
		/*user_flags*/ user_flags,
		/*timestamp*/ data_ts,
		/*json_size*/ json.size(),
		/*json_capacity*/ json.capacity(),
		/*json_timestamp*/ json_ts,
		/*data_offset*/ 0,
		/*data_size*/ data.size(),
		/*data_capacity*/ data.size(),
		/*data_commit_size*/ data.size(),
		/*cache_lifetime*/ 0,
		/*deadline*/ {0,0}
	});


	data_buffer buffer(packet.size() + json.size() + data.size());
	buffer.write(packet.data(), packet.size());
	buffer.write(json.data(), json.size());
	buffer.write(data.data(), data.size());

	DNET_LOG_DEBUG(m_state->n, "going to write size: {}", buffer.size());

	data_pointer datap = std::move(buffer);

	dnet_cmd cmd;
	memset(&cmd, 0, sizeof(cmd));

	cmd.id = id;
	cmd.cmd = DNET_CMD_WRITE_NEW;
	cmd.flags = m_cflags;
	cmd.size = datap.size();
	cmd.backend_id = m_backend.backend_id();

	int err = dnet_process_cmd_raw(m_state, &cmd, datap.data(), 0, 0, /*context*/ nullptr);
	clear_queue(&err);
	return err;
}

std::unique_ptr<ioremap::elliptics::n2::lookup_response> local_session::lookup(const dnet_cmd &tmp_cmd, int *errp)
{
	std::unique_ptr<n2::lookup_request> request(new(std::nothrow) n2::lookup_request(tmp_cmd));
	if (!request) {
		*errp = -ENOMEM;
		return nullptr;
	}
	request->cmd.flags |= m_cflags;
	request->cmd.size = 0;
	request->cmd.backend_id = m_backend.backend_id();

	std::unique_ptr<n2::lookup_response> response;
	n2_repliers repliers{
		[&](std::unique_ptr<n2_message> message) {
			response.reset(static_cast<n2::lookup_response *>(message.release()));
			return 0;
		}, // on_reply
		[](int err) {
			return err;
		} // on_reply_error
	};

	n2_request_info req_info{request->cmd,
		                 std::move(request),
		                 std::move(repliers)};

	*errp = n2_process_cmd_raw(m_state, &req_info, 0, 0, /*context*/ nullptr);
	if (*errp) {
		return nullptr;
	}
	if (!response) {
		*errp = -ENOENT;
	}
	return response;
}

int local_session::remove(const struct dnet_id &id, dnet_access_context *context) {
	struct dnet_io_attr io;
	memset(&io, 0, sizeof(io));
	memcpy(io.parent, id.id, DNET_ID_SIZE);
	memcpy(io.id, id.id, DNET_ID_SIZE);
	io.flags = DNET_IO_FLAGS_SKIP_SENDING;
	dnet_convert_io_attr(&io);

	struct dnet_cmd cmd;
	memset(&cmd, 0, sizeof(cmd));
	cmd.id = id;
	cmd.size = sizeof(io);
	cmd.flags = DNET_FLAGS_NOLOCK;
	cmd.cmd = DNET_CMD_DEL;
	cmd.backend_id = m_backend.backend_id();

	struct dnet_cmd_stats cmd_stats;
	memset(&cmd_stats, 0, sizeof(cmd_stats));

	const auto &callbacks = m_backend.callbacks();
	const int err = callbacks.command_handler(m_state,
	                                          callbacks.command_private,
	                                          &cmd,
	                                          &io,
	                                          &cmd_stats,
	                                          context);
	DNET_LOG_NOTICE(m_state->n, "{}: local remove: err: {}", dnet_dump_id(&cmd.id), err);

	clear_queue(nullptr);
	return err;
}

int local_session::remove_new(const struct dnet_id &id,
                              const ioremap::elliptics::dnet_remove_request &request,
                              dnet_access_context *context) {
	const auto packet = ioremap::elliptics::serialize(request);

	struct dnet_cmd cmd;
	memset(&cmd, 0, sizeof(struct dnet_cmd));
	cmd.id = id;
	cmd.size = packet.size();
	cmd.flags = DNET_FLAGS_NOLOCK;
	cmd.cmd = DNET_CMD_DEL_NEW;
	cmd.backend_id = m_backend.backend_id();

	struct dnet_cmd_stats cmd_stats;
	memset(&cmd_stats, 0, sizeof(struct dnet_cmd_stats));

	const auto &callbacks = m_backend.callbacks();
	int err = callbacks.command_handler(m_state,
	                                    callbacks.command_private,
	                                    &cmd,
	                                    packet.data(),
	                                    &cmd_stats,
	                                    context);
	DNET_LOG_NOTICE(m_state->n, "{}: local remove_new: err: {}", dnet_dump_id(&cmd.id), err);

	return err;
}

void local_session::clear_queue(int *errp)
{
	struct dnet_io_req *r, *tmp;

	list_for_each_entry_safe(r, tmp, &m_state->send_list, req_entry) {
		dnet_cmd *cmd = reinterpret_cast<dnet_cmd *>(r->header ? r->header : r->data);

		if (errp && cmd->status)
			*errp = cmd->status;

		list_del(&r->req_entry);
		dnet_io_req_free(r);
	}
}
