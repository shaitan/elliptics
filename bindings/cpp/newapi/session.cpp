#include "elliptics/newapi/session.hpp"

#include "elliptics/async_result_cast.hpp"
#include "bindings/cpp/callback_p.h"
#include "bindings/cpp/node_p.hpp"

#include "library/protocol.hpp"

namespace ioremap { namespace elliptics { namespace newapi {

session::session(const node &n) : elliptics::session(n) {
}

session::session(dnet_node *n) : elliptics::session(n) {
}

session::session(const std::shared_ptr<elliptics::session_data> &d) : elliptics::session(d) {
}

session::session(const session &other) : elliptics::session(other) {
}

session::session(const elliptics::session &other) : elliptics::session(other) {
}

session::~session() {
}

session session::clone() const {
	return session(elliptics::session::clone());
}

session session::clean_clone() const {
	return session(elliptics::session::clean_clone());
}

class lookup_handler: public multigroup_handler<lookup_handler, lookup_result_entry> {
public:
	lookup_handler(const session &s, const async_lookup_result &result,
	               std::vector<int> &&groups, const dnet_trans_control &control)
		: parent_type(s, result, std::move(groups))
		, m_control(control) {
	}

	async_generic_result send_to_next_group() {
		m_control.id.group_id = current_group();
		return send_to_single_state(m_sess, m_control);
	}

private:
	dnet_trans_control m_control;
};

async_lookup_result session::lookup(const key &id) {
	DNET_SESSION_GET_GROUPS(async_lookup_result);
	transform(id);


	transport_control control;
	control.set_key(id.id());
	control.set_command(DNET_CMD_LOOKUP_NEW);
	control.set_cflags(get_cflags() | DNET_FLAGS_NEED_ACK);

	async_lookup_result result(*this);
	auto handler = std::make_shared<lookup_handler>(*this, result, std::move(groups), control.get_native());
	handler->set_total(1);
	handler->start();

	return result;
}

class read_handler : public multigroup_handler<read_handler, read_result_entry> {
public:
	read_handler(const session &s, const async_read_result &result,
	             std::vector<int> &&groups, const dnet_trans_control &control)
		: parent_type(s, result, std::move(groups))
		, m_control(control) {
	}

	async_generic_result send_to_next_group() {
		m_control.id.group_id = current_group();
		return send_to_single_state(m_sess, m_control);
	}

private:
	dnet_trans_control m_control;
};

async_read_result session::read_json(const key &id) {
	DNET_SESSION_GET_GROUPS(async_read_result);
	transform(id);

	auto packet = [&] () {
		dnet_read_request request;
		memset(&request, 0, sizeof(request));

		request.ioflags = get_ioflags();
		request.read_flags = DNET_READ_FLAGS_JSON;
		return serialize(request);
	} ();

	transport_control control;

	control.set_key(id.id());
	control.set_command(DNET_CMD_READ_NEW);
	control.set_cflags(get_cflags() | DNET_FLAGS_NEED_ACK);
	control.set_data(packet.data(), packet.size());

	async_read_result result(*this);
	auto handler = std::make_shared<read_handler>(*this, result, std::move(groups), control.get_native());
	handler->set_total(1);
	handler->start();

	return result;
}

async_read_result session::read_data(const key &id, uint64_t offset, uint64_t size) {
	DNET_SESSION_GET_GROUPS(async_read_result);
	transform(id);

	auto packet = [&] () {
		dnet_read_request request;
		memset(&request, 0, sizeof(request));

		request.ioflags = get_ioflags();
		request.read_flags = DNET_READ_FLAGS_DATA;
		request.data_offset = offset;
		request.data_size = size;
		return serialize(request);
	} ();

	transport_control control;

	control.set_key(id.id());
	control.set_command(DNET_CMD_READ_NEW);
	control.set_cflags(get_cflags() | DNET_FLAGS_NEED_ACK);
	control.set_data(packet.data(), packet.size());

	async_read_result result(*this);
	auto handler = std::make_shared<read_handler>(*this, result, std::move(groups), control.get_native());
	handler->set_total(1);
	handler->start();

	return result;
}

async_read_result session::read(const key &id, uint64_t offset, uint64_t size) {
	DNET_SESSION_GET_GROUPS(async_read_result);
	transform(id);

	auto packet = [&] () {
		dnet_read_request request;
		memset(&request, 0, sizeof(request));

		request.ioflags = get_ioflags();
		request.read_flags = DNET_READ_FLAGS_JSON | DNET_READ_FLAGS_DATA;
		request.data_offset = offset;
		request.data_size = size;
		return serialize(request);
	} ();

	transport_control control;

	control.set_key(id.id());
	control.set_command(DNET_CMD_READ_NEW);
	control.set_cflags(get_cflags() | DNET_FLAGS_NEED_ACK);
	control.set_data(packet.data(), packet.size());

	async_read_result result(*this);
	auto handler = std::make_shared<read_handler>(*this, result, std::move(groups), control.get_native());
	handler->set_total(1);
	handler->start();

	return result;
}

async_write_result session::write(const key &id,
                                  const argument_data &json, uint64_t json_capacity,
                                  const argument_data &data, uint64_t data_capacity) {
	transform(id);

	try {
		validate_json(std::string((const char*)json.data(), json.size()));
	} catch (const std::exception &e) {
		async_write_result result(*this);
		async_result_handler<write_result_entry> handler(result);
		handler.complete(create_error(-EINVAL, "invalid json: %s", e.what()));
		return result;
	}

	auto packet = [&] () {
		auto header = [&] () {
			dnet_write_request request;
			memset(&request, 0, sizeof(request));

			request.ioflags = get_ioflags() | DNET_IO_FLAGS_PREPARE | DNET_IO_FLAGS_COMMIT | DNET_IO_FLAGS_PLAIN_WRITE;
			request.user_flags = get_user_flags();

			get_timestamp(&request.timestamp);
			if (dnet_time_is_empty(&request.timestamp)) {
				dnet_current_time(&request.timestamp);
			}

			request.json_size = json.size();
			request.json_capacity = json_capacity;

			request.data_offset = 0;
			request.data_commit_size = request.data_size = data.size();
			request.data_capacity = data_capacity;

			return serialize(request);
		} ();

		auto ret = data_pointer::allocate(header.size() + json.size() + data.size());
		memcpy(ret.data(), header.data(), header.size());
		memcpy(ret.skip(header.size()).data(), json.data(), json.size());
		memcpy(ret.skip(header.size() + json.size()).data(), data.data(), data.size());
		return ret;
	} ();

	transport_control control;
	control.set_key(id.id());
	control.set_command(DNET_CMD_WRITE_NEW);
	control.set_cflags(get_cflags() | DNET_FLAGS_NEED_ACK);
	control.set_data(packet.data(), packet.size());

	auto session = clean_clone();
	return async_result_cast<write_result_entry>(*this, send_to_groups(session, control));
}

async_lookup_result session::write_prepare(const key &id,
                                           const argument_data &json, uint64_t json_capacity,
                                           const argument_data &data, uint64_t data_offset, uint64_t data_capacity) {
	transform(id);

	try {
		validate_json(std::string((const char*)json.data(), json.size()));
	} catch (const std::exception &e) {
		async_write_result result(*this);
		async_result_handler<write_result_entry> handler(result);
		handler.complete(create_error(-EINVAL, "invalid json: %s", e.what()));
		return result;
	}

	if (json_capacity == 0)
		json_capacity = json.size();

	if (data_capacity == 0)
		data_capacity = data_offset + data.size();

	auto packet = [&] () {
		auto header = [&] () {
			dnet_write_request request;
			memset(&request, 0, sizeof(request));

			request.ioflags = get_ioflags() | DNET_IO_FLAGS_PREPARE | DNET_IO_FLAGS_PLAIN_WRITE;
			request.user_flags = get_user_flags();

			get_timestamp(&request.timestamp);
			if (dnet_time_is_empty(&request.timestamp)) {
				dnet_current_time(&request.timestamp);
			}

			request.json_size = json.size();
			request.json_capacity = json_capacity;

			request.data_offset = data_offset;
			request.data_size = data.size();
			request.data_capacity = data_capacity;

			return serialize(request);
		} ();

		auto ret = data_pointer::allocate(header.size() + json.size() + data.size());
		memcpy(ret.data(), header.data(), header.size());
		memcpy(ret.skip(header.size()).data(), json.data(), json.size());
		memcpy(ret.skip(header.size() + json.size()).data(), data.data(), data.size());
		return ret;
	} ();

	transport_control control;
	control.set_key(id.id());
	control.set_command(DNET_CMD_WRITE_NEW);
	control.set_cflags(get_cflags() | DNET_FLAGS_NEED_ACK);
	control.set_data(packet.data(), packet.size());

	auto session = clean_clone();
	return async_result_cast<write_result_entry>(*this, send_to_groups(session, control));
}

async_lookup_result session::write_plain(const key &id,
                                         const argument_data &json,
                                         const argument_data &data, uint64_t data_offset) {
	transform(id);

	try {
		validate_json(std::string((const char*)json.data(), json.size()));
	} catch (const std::exception &e) {
		async_write_result result(*this);
		async_result_handler<write_result_entry> handler(result);
		handler.complete(create_error(-EINVAL, "invalid json: %s", e.what()));
		return result;
	}

	auto packet = [&] () {
		auto header = [&] () {
			dnet_write_request request;
			memset(&request, 0, sizeof(request));

			request.ioflags = get_ioflags() | DNET_IO_FLAGS_PLAIN_WRITE;
			request.user_flags = get_user_flags();

			get_timestamp(&request.timestamp);
			if (dnet_time_is_empty(&request.timestamp)) {
				dnet_current_time(&request.timestamp);
			}

			request.json_size = json.size();

			request.data_offset = data_offset;
			request.data_size = data.size();

			return serialize(request);
		} ();

		auto ret = data_pointer::allocate(header.size() + json.size() + data.size());
		memcpy(ret.data(), header.data(), header.size());
		memcpy(ret.skip(header.size()).data(), json.data(), json.size());
		memcpy(ret.skip(header.size() + json.size()).data(), data.data(), data.size());
		return ret;
	} ();

	transport_control control;
	control.set_key(id.id());
	control.set_command(DNET_CMD_WRITE_NEW);
	control.set_cflags(get_cflags() | DNET_FLAGS_NEED_ACK);
	control.set_data(packet.data(), packet.size());

	auto session = clean_clone();
	return async_result_cast<write_result_entry>(*this, send_to_groups(session, control));
}

async_lookup_result session::write_commit(const key &id,
                                          const argument_data &json,
                                          const argument_data &data, uint64_t data_offset, uint64_t data_commit_size) {
	transform(id);

	try {
		validate_json(std::string((const char*)json.data(), json.size()));
	} catch (const std::exception &e) {
		async_write_result result(*this);
		async_result_handler<write_result_entry> handler(result);
		handler.complete(create_error(-EINVAL, "invalid json: %s", e.what()));
		return result;
	}

	if (data_commit_size == 0)
		data_commit_size = data_offset + data.size();

	auto packet = [&] () {
		auto header = [&] () {
			dnet_write_request request;
			memset(&request, 0, sizeof(request));

			request.ioflags = get_ioflags() | DNET_IO_FLAGS_COMMIT | DNET_IO_FLAGS_PLAIN_WRITE;
			request.user_flags = get_user_flags();

			get_timestamp(&request.timestamp);
			if (dnet_time_is_empty(&request.timestamp)) {
				dnet_current_time(&request.timestamp);
			}

			request.json_size = json.size();

			request.data_offset = data_offset;
			request.data_size = data.size();
			request.data_commit_size = data_commit_size;

			return serialize(request);
		} ();

		auto ret = data_pointer::allocate(header.size() + json.size() + data.size());
		memcpy(ret.data(), header.data(), header.size());
		memcpy(ret.skip(header.size()).data(), json.data(), json.size());
		memcpy(ret.skip(header.size() + json.size()).data(), data.data(), data.size());
		return ret;
	} ();

	transport_control control;
	control.set_key(id.id());
	control.set_command(DNET_CMD_WRITE_NEW);
	control.set_cflags(get_cflags() | DNET_FLAGS_NEED_ACK);
	control.set_data(packet.data(), packet.size());

	auto session = clean_clone();
	return async_result_cast<write_result_entry>(*this, send_to_groups(session, control));
}

}}} // ioremap::elliptics::newapi
