/*
 * Copyright 2015+ Kirill Smorodinnikov <shaitkir@gmail.com>
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

#include "session_structured_data.hpp"

#include "callback_p.h"
#include "node_p.hpp"

namespace ioremap { namespace elliptics {

class lookup_handler : public multigroup_handler<lookup_handler, write_struct_result_entry> {
public:
	lookup_handler(const session &sess, const async_write_struct_result &result,
	               std::vector<int> &&groups, const dnet_trans_control &control)
	: multigroup_handler<lookup_handler, write_struct_result_entry>(sess, result, std::move(groups))
	, m_control(control)
	{}

	async_generic_result send_to_next_group() {
		m_control.id.group_id = current_group();

		return send_to_single_state(m_sess, m_control);
	}

private:
	dnet_trans_control m_control;
};

async_write_struct_result session::lookup_struct(const key &id) {
	DNET_SESSION_GET_GROUPS(async_write_struct_result);

	transport_control control(id.id(), DNET_CMD_LOOKUP_STRUCT, DNET_FLAGS_NEED_ACK);

	async_write_struct_result result(*this);
	auto handler = std::make_shared<lookup_handler>(*this, result, std::move(groups), control.get_native());
	handler->set_total(1);
	handler->start();

	return result;
}

static inline int validate_struct_index(const data_pointer &index,
                                        const std::vector<data_pointer> &datas) {
	// TODO: validate index
	// throw_error(err, id.id(), "Invalid index");
	return 0;
}

static inline const data_pointer make_write_struct_request(const data_pointer &index,
                                                           const std::vector<data_pointer> &datas) {
	// size of whole request including its header and data
	const size_t request_size = [&index, &datas] {
		// size of request header
		size_t size = sizeof(struct dnet_write_struct_request);

		// size of index entry header + size of index data
		size += sizeof(struct dnet_write_struct_request_entry) + index.size();

		// size of all entries headers
		size += sizeof(struct dnet_write_struct_request_entry) * datas.size();

		for (const auto &data : datas) {
			// size of each entry data
			size += data.size();
		}
		return size;
	}();

	data_buffer buffer(request_size);

	const struct dnet_write_struct_request request = [&datas] {
		struct dnet_write_struct_request val;
		memset(&val, 0, sizeof(val));

		val.entries_count = datas.size() + 1;
		return val;
	}();

	buffer.write(request);

	struct dnet_write_struct_request_entry entry;
	memset(&entry, 0, sizeof(entry));

	entry.size = index.size();
	buffer.write(entry);
	buffer.write(index.data(), index.size());

	for (const auto &data : datas) {
		entry.size = data.size();
		buffer.write(entry);
		buffer.write(data.data(), data.size());
	}
	return std::move(buffer);
}

async_write_struct_result session::write_struct(const key &id,
                                                const data_pointer &index,
                                                const std::vector<data_pointer> &datas) {
	validate_struct_index(index, datas);

	transform(id);

	struct dnet_io_control ctl;
	memset(&ctl, 0, sizeof(ctl));

	ctl.cmd = DNET_CMD_WRITE_STRUCT;
	ctl.cflags = DNET_FLAGS_NEED_ACK;
	ctl.fd = -1;
	ctl.io.flags = get_ioflags();
	ctl.io.user_flags = get_user_flags();
	ctl.io.offset = 0;

	memcpy(&ctl.id, &id.id(), sizeof(struct dnet_id));
	memcpy(ctl.io.id, ctl.id.id, DNET_ID_SIZE);

	get_timestamp(&ctl.io.timestamp);
	if (dnet_time_is_empty(&ctl.io.timestamp))
		dnet_current_time(&ctl.io.timestamp);

	const auto request_data = make_write_struct_request(index, datas);

	ctl.data = request_data.data();
	ctl.io.size = request_data.size();

	auto sess = clean_clone();
	return async_result_cast<write_struct_result_entry>(*this, send_to_groups(sess, ctl));
}

class read_struct_handler: public multigroup_handler<read_struct_handler, callback_result_entry> {
public:
	read_struct_handler(const session &sess, const async_generic_result &result,
	             std::vector<int> &&groups, const dnet_io_control &control)
	: parent_type(sess, result, std::move(groups))
	, m_control(control)
	{}

	async_generic_result send_to_next_group() {
		m_control.id.group_id = current_group();

		return send_to_single_state(m_sess, m_control);
	}

private:
	dnet_io_control m_control;
};

static void on_read_struct_callback(async_result_handler<read_struct_result_entry> handler,
                                    const sync_generic_result &results, const error_info &error) {
	if (!error) {
		read_struct_result_entry entry;

		auto it = results.cbegin();
		auto end = results.cend();

		entry.index = it->data().skip<struct dnet_read_struct_response>();

		for (++it; it != end; ++it) {
			entry.datas.emplace_back(it->data().skip<struct dnet_io_attr>());
		}

		handler.process(entry);
	}

	handler.complete(error);
}

async_read_struct_result session::read_struct(const key &id,
                                              const data_pointer &index) {
	async_read_struct_result result(*this);
	async_result_handler<read_struct_result_entry> handler(result);

	DNET_SESSION_GET_GROUPS(async_read_struct_result);

	transform(id);
	dnet_id raw = id.id();

	dnet_io_control ctl;
	memset(&ctl, 0, sizeof(ctl));

	ctl.cmd = DNET_CMD_READ_STRUCT;
	ctl.cflags = DNET_FLAGS_NEED_ACK;
	ctl.fd = -1;
	ctl.io.flags = get_ioflags();
	ctl.io.user_flags = get_user_flags();
	ctl.io.offset = 0;

	memcpy(&ctl.id, &raw, sizeof(dnet_id));
	memcpy(ctl.io.id, ctl.id.id, DNET_ID_SIZE);

	data_buffer buffer(sizeof(struct dnet_read_struct_request) + index.size());

	struct dnet_read_struct_request request;
	memset(&request, 0, sizeof(request));
	request.size = index.size();

	buffer.write(request);
	buffer.write(index.data(), index.size());

	data_pointer data_p(std::move(buffer));

	ctl.data = data_p.data();
	ctl.io.size = data_p.size();

	async_generic_result raw_result(*this);
	auto raw_handler = std::make_shared<read_struct_handler>(*this, raw_result, std::move(groups), ctl);
	raw_handler->start();

	using namespace std::placeholders;

	raw_result.connect(std::bind(on_read_struct_callback, handler, _1, _2));
	return result;
}

}} /* namespace ioremap::elliptics */
