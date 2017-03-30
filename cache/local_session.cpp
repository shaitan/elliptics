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

data_pointer local_session::read(const dnet_id &id, int *errp)
{
	return read(id, NULL, NULL, errp);
}

data_pointer local_session::read(const dnet_id &id, uint64_t *user_flags, dnet_time *timestamp, int *errp)
{
	dnet_io_attr io;
	memset(&io, 0, sizeof(io));
	dnet_empty_time(&io.timestamp);

	memcpy(io.id, id.id, DNET_ID_SIZE);
	memcpy(io.parent, id.id, DNET_ID_SIZE);

	io.flags = DNET_IO_FLAGS_NOCSUM | m_ioflags;

	dnet_cmd cmd;
	memset(&cmd, 0, sizeof(cmd));

	cmd.id = id;
	cmd.cmd = DNET_CMD_READ;
	cmd.flags |= m_cflags;
	cmd.size = sizeof(io);
	cmd.backend_id = m_backend.backend_id();

	int err = dnet_process_cmd_raw(m_state, &cmd, &io, 0, 0);
	if (err) {
		clear_queue();
		*errp = err;
		return data_pointer();
	}

	struct dnet_io_req *r, *tmp;

	list_for_each_entry_safe(r, tmp, &m_state->send_list, req_entry) {
		DNET_LOG_DEBUG(m_state->n, "hsize: {}, dsize: {}", r->hsize, r->dsize);

		dnet_cmd *req_cmd = reinterpret_cast<dnet_cmd *>(r->header ? r->header : r->data);

		DNET_LOG_DEBUG(m_state->n, "entry in list, status: {}", req_cmd->status);

		if (req_cmd->status) {
			*errp = req_cmd->status;
			clear_queue();
			return data_pointer();
		} else if (req_cmd->size) {
			dnet_io_attr *req_io = reinterpret_cast<dnet_io_attr *>(req_cmd + 1);

			if (user_flags)
				*user_flags = req_io->user_flags;
			if (timestamp)
				*timestamp = req_io->timestamp;

			DNET_LOG_DEBUG(m_state->n, "entry in list, size: {}", req_io->size);

			data_pointer result;

			if (r->data) {
				result = data_pointer::copy(r->data, r->dsize);
			} else {
				result = data_pointer::allocate(req_io->size);
				ssize_t read_res = pread(r->fd, result.data(), result.size(), r->local_offset);
				if (read_res == -1) {
					*errp = errno;
					clear_queue();
					return data_pointer();
				}
			}


			clear_queue();
			return result;
		}
	}

	*errp = -ENOENT;
	clear_queue();
	return data_pointer();
}

int local_session::write(const dnet_id &id, const data_pointer &data)
{
	return write(id, data.data<char>(), data.size());
}

int local_session::write(const dnet_id &id, const char *data, size_t size)
{
	dnet_time null_time;
	dnet_empty_time(&null_time);
	return write(id, data, size, 0, null_time);
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

	int err = dnet_process_cmd_raw(m_state, &cmd, datap.data(), 0, 0);

	clear_queue(&err);

	return err;
}

data_pointer local_session::lookup(const dnet_cmd &tmp_cmd, int *errp)
{
	dnet_cmd cmd = tmp_cmd;
	cmd.flags |= m_cflags;
	cmd.size = 0;
	cmd.backend_id = m_backend.backend_id();

	*errp = dnet_process_cmd_raw(m_state, &cmd, NULL, 0, 0);

	if (*errp)
		return data_pointer();

	struct dnet_io_req *r, *tmp;

	list_for_each_entry_safe(r, tmp, &m_state->send_list, req_entry) {
		dnet_cmd *req_cmd = reinterpret_cast<dnet_cmd *>(r->header ? r->header : r->data);

		if (req_cmd->status) {
			*errp = req_cmd->status;
			clear_queue();
			return data_pointer();
		} else if (req_cmd->size) {
			data_pointer result = data_pointer::copy(req_cmd + 1, req_cmd->size);
			clear_queue();
			return result;
		}
	}

	*errp = -ENOENT;
	clear_queue();
	return data_pointer();
}

int local_session::remove(const struct dnet_id &id) {
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
	const int err = callbacks.command_handler(m_state, callbacks.command_private, &cmd, &io, &cmd_stats);
	DNET_LOG_NOTICE(m_state->n, "{}: local remove: err: {}", dnet_dump_id(&cmd.id), err);

	clear_queue(nullptr);
	return err;
}

int local_session::remove_new(const struct dnet_id &id, const ioremap::elliptics::dnet_remove_request &request) {
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
	int err = callbacks.command_handler(m_state, callbacks.command_private, &cmd, packet.data(), &cmd_stats);
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
