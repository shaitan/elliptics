#include "elliptics/newapi/session.hpp"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include <blackhole/attribute.hpp>

#include "elliptics/async_result_cast.hpp"
#include "bindings/cpp/callback_p.h"
#include "bindings/cpp/node_p.hpp"

#include "library/protocol.hpp"

#include "bindings/cpp/functional_p.h"

namespace ioremap { namespace elliptics { namespace newapi {

class timer {
public:
	timer() {
		gettimeofday(&point, nullptr);
	}

	unsigned long long elapsed() {
		struct timeval curr;
		gettimeofday(&curr, nullptr);
		return (curr.tv_sec - point.tv_sec) * 1000000 + curr.tv_usec - point.tv_usec;
	}
private:
	struct timeval point;
};

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

session &session::operator =(const session &other) {
	elliptics::session::operator =(other);
	return *this;
}

dnet_time session::get_timestamp() const
{
	struct dnet_time ts;
	dnet_session_get_timestamp(m_data->session_ptr, &ts);
	return ts;
}

void session::reset_timestamp()
{
	struct dnet_time empty;
	dnet_empty_time(&empty);
	dnet_session_set_timestamp(m_data->session_ptr, &empty);
}

void session::set_json_timestamp(const dnet_time &ts)
{
	dnet_session_set_json_timestamp(m_data->session_ptr, &ts);
}

dnet_time session::get_json_timestamp() const
{
	struct dnet_time ts;
	dnet_session_get_json_timestamp(m_data->session_ptr, &ts);
	return ts;
}

void session::reset_json_timestamp()
{
	struct dnet_time empty;
	dnet_empty_time(&empty);
	dnet_session_set_json_timestamp(m_data->session_ptr, &empty);
}

void session::set_cache_lifetime(uint64_t lifetime)
{
	dnet_session_set_cache_lifetime(m_data->session_ptr, lifetime);
}

uint64_t session::get_cache_lifetime() const
{
	return dnet_session_get_cache_lifetime(m_data->session_ptr);
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
	trace_scope scope{get_trace_id(), get_trace_bit()};
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

async_remove_result session::remove(const key &id) {
	trace_scope scope{get_trace_id(), get_trace_bit()};
	transform(id);

	dnet_remove_request request;
	request.ioflags = get_ioflags();
	request.timestamp = get_timestamp();

	auto packet = serialize(request);

	transport_control control;
	control.set_key(id.id());
	control.set_command(DNET_CMD_DEL_NEW);
	control.set_cflags(get_cflags() | DNET_FLAGS_NEED_ACK);
	control.set_data(packet.data(), packet.size());

	return send_to_groups(*this, control);
}

/* TODO: refactor read_handler/write_handler because they have a lot in common */
class read_handler : public std::enable_shared_from_this<read_handler> {
private:
	class inner_handler : public multigroup_handler<inner_handler, read_result_entry> {
	public:
		inner_handler(const session &s, const async_read_result &result,
		              std::vector<int> &&groups, const dnet_trans_control &control,
		              const dnet_read_request &request)
		: parent_type(s, result, std::move(groups))
		, m_control(control) {
			m_packet = serialize(request);
			m_control.data = m_packet.data();
			m_control.size = m_packet.size();
		}

		async_generic_result send_to_next_group() {
			m_control.id.group_id = current_group();
			return send_to_single_state(m_sess, m_control);
		}

	private:
		dnet_trans_control m_control;
		data_pointer m_packet;
	};

	struct response {
		uint32_t group;
		int status;
		uint64_t json_size;
		uint64_t data_size;
		uint64_t trans;
	};

public:
	explicit read_handler(const session &orig_sess, const async_read_result &result,
	                      const key &id)
	: m_timer()
	, m_key(id)
	, m_session(orig_sess.clean_clone())
	, m_handler(result)
	, m_log(orig_sess.get_logger())
	{
		m_session.set_checker(orig_sess.get_checker());
		m_responses.reserve(m_session.get_groups().size());
	}

	void start(std::vector<int> &&groups, const transport_control &control, const dnet_read_request &request) {
		m_handler.set_total(1);
		async_read_result result(m_session);
		auto handler = std::make_shared<inner_handler>(m_session, result, std::move(groups),
		                                               control.get_native(), request);
		handler->set_total(1);
		handler->start();
		result.connect(
			std::bind(&read_handler::process, shared_from_this(), std::placeholders::_1),
			std::bind(&read_handler::complete, shared_from_this(), std::placeholders::_1)
		);
	}

private:
	void process(const ioremap::elliptics::callback_result_entry &entry) {
		const auto &resp = callback_cast<read_result_entry>(entry);
		m_responses.emplace_back(response{
			resp.command()->id.group_id,
			resp.status(),
			resp.status() ? 0 : resp.io_info().json_size,
			resp.status() ? 0 : resp.io_info().data_size,
			resp.command()->trans,
		});

		m_handler.process(resp);
	}

	void complete(const error_info &error) {
		m_handler.complete(error);

		std::string groups, status, jsons, datas, trans;
		std::tie(groups, status, jsons, datas, trans) = dump_responses();
		DNET_LOG_INFO(m_log, "{}: {}: finished: groups: {}, trans: {}, status: {}, json-size: {}, data-size: "
		                     "{}, total_time: {}",
		              dnet_dump_id_str(m_key.id().id), dnet_cmd_string(DNET_CMD_READ_NEW), groups, trans,
		              status, jsons, datas, m_timer.elapsed());
	}

	std::tuple<std::string, std::string, std::string, std::string, std::string> dump_responses() const {
		auto dump = [this] (const char b, const char e, const std::function<std::string(const response &)> &f) {
			std::ostringstream str;
			str << b;
			for (auto it = m_responses.cbegin(); it != m_responses.cend(); ++it) {
				if (it != m_responses.cbegin())
					str << ", ";
				str << f(*it);
			}
			str << e;
			return str.str();
		};

		auto dump_array = [&dump] (const std::function<std::string(const response &)> &f) {
			return dump('[', ']', f);
		};

		auto dump_pairs = [&dump] (const std::function<std::string(const response &)> &f) {
			return dump('{', '}', [&f] (const response &r) {
				return std::to_string(r.group) + ": " + f(r);
			});
		};

		auto groups = dump_array([] (const response &r) {
			return std::to_string(r.group);
		});

		auto status = dump_pairs([] (const response &r) { return std::to_string(r.status); });
		auto json = dump_pairs([] (const response &r) { return std::to_string(r.json_size); });
		auto data = dump_pairs([] (const response &r) { return std::to_string(r.data_size); });
		auto trans = dump_pairs([] (const response &r) { return std::to_string(r.trans); });

		return std::make_tuple(groups, status, json, data, trans);
	}

	timer m_timer;
	key m_key;
	session m_session;
	async_result_handler<read_result_entry> m_handler;
	std::vector<response> m_responses;
	std::unique_ptr<dnet_logger> m_log;
};

async_read_result send_read(const session &orig_sess, const key &id, const dnet_read_request &request,
                            std::vector<int> &&groups) {
	transport_control control;
	control.set_key(id.id());
	control.set_command(DNET_CMD_READ_NEW);
	control.set_cflags(orig_sess.get_cflags() | DNET_FLAGS_NEED_ACK);

	auto log = orig_sess.get_logger();
	DNET_LOG_INFO(log, "{}: {}: started: flags: {}, read-flags: {}, offset: {}, size: {}", dnet_dump_id(&id.id()),
	              dnet_cmd_string(control.get_native().cmd), dnet_flags_dump_ioflags(request.ioflags),
	              dnet_dump_read_flags(request.read_flags), request.data_offset, request.data_size);

	async_read_result result(orig_sess);
	auto handler = std::make_shared<read_handler>(orig_sess, result, id);
	handler->start(std::move(groups), control.get_native(), request);
	return result;
}

async_read_result session::read_json(const key &id) {
	trace_scope scope{get_trace_id(), get_trace_bit()};
	DNET_SESSION_GET_GROUPS(async_read_result);
	transform(id);

	dnet_read_request request;
	memset(&request, 0, sizeof(request));

	request.ioflags = get_ioflags();
	request.read_flags = DNET_READ_FLAGS_JSON;

	dnet_current_time(&request.deadline);
	request.deadline.tsec += get_timeout();

	return send_read(*this, id, request, std::move(groups));
}

async_read_result session::read_data(const key &id, uint64_t offset, uint64_t size) {
	trace_scope scope{get_trace_id(), get_trace_bit()};
	DNET_SESSION_GET_GROUPS(async_read_result);
	transform(id);

	dnet_read_request request;
	memset(&request, 0, sizeof(request));

	request.ioflags = get_ioflags();
	request.read_flags = DNET_READ_FLAGS_DATA;
	request.data_offset = offset;
	request.data_size = size;

	dnet_current_time(&request.deadline);
	request.deadline.tsec += get_timeout();

	return send_read(*this, id, request, std::move(groups));
}

async_read_result session::read(const key &id, uint64_t offset, uint64_t size) {
	trace_scope scope{get_trace_id(), get_trace_bit()};
	DNET_SESSION_GET_GROUPS(async_read_result);
	transform(id);

	dnet_read_request request;
	memset(&request, 0, sizeof(request));

	request.ioflags = get_ioflags();
	request.read_flags = DNET_READ_FLAGS_JSON | DNET_READ_FLAGS_DATA;
	request.data_offset = offset;
	request.data_size = size;

	dnet_current_time(&request.deadline);
	request.deadline.tsec += get_timeout();

	return send_read(*this, id, request, std::move(groups));
}

/* TODO: refactor read_handler/write_handler because they have a lot in common */
class write_handler : public std::enable_shared_from_this<write_handler> {
private:
	struct response {
		uint32_t group;
		int status;
		uint64_t json_size;
		uint64_t data_size;
		uint64_t trans;
	};
public:
	explicit write_handler(const async_write_result &result, const session &orig_sess,
	                       const key &id)
	: m_timer()
	, m_key(id)
	, m_session(orig_sess.clean_clone())
	, m_handler(result)
	, m_log(orig_sess.get_logger())
	{
		m_session.set_checker(orig_sess.get_checker());
		m_responses.reserve(m_session.get_groups().size());
	}

	void start(const transport_control &control, const dnet_write_request &request) {
		DNET_LOG_INFO(m_log, "{}: {}: started: flags: {}, ts: '{}', json: {{size: {}, capacity: {}}}, data: "
		                     "{{offset: {}, size: {}, capacity: {}, commit-size: {}}}",
		              dnet_dump_id(&m_key.id()), dnet_cmd_string(control.get_native().cmd),
		              dnet_flags_dump_ioflags(request.ioflags), dnet_print_time(&request.timestamp),
		              request.json_size, request.json_capacity, request.data_offset, request.data_size,
		              request.data_capacity, request.data_commit_size);
		auto rr = send_to_groups(m_session, control);
		m_handler.set_total(rr.total());

		rr.connect(
			std::bind(&write_handler::process, shared_from_this(), std::placeholders::_1),
			std::bind(&write_handler::complete, shared_from_this(), std::placeholders::_1)
		);
	}

private:
	void process(const ioremap::elliptics::callback_result_entry &entry) {
		const auto &resp = callback_cast<write_result_entry>(entry);
		m_responses.emplace_back(response{
			resp.command()->id.group_id,
			resp.status(),
			resp.status() ? 0 : resp.record_info().json_size,
			resp.status() ? 0 : resp.record_info().data_size,
			resp.command()->trans,
		});

		m_handler.process(resp);
	}

	void complete(const error_info &error) {
		m_handler.complete(error);

		std::string groups, status, jsons, datas, trans;
		std::tie(groups, status, jsons, datas, trans) = dump_responses();
		DNET_LOG_INFO(m_log, "{}: {}: finished: groups: {}, trans: {}, status: {}, json-size: {}, data-size: "
		                     "{}, total_time: {}",
		              dnet_dump_id_str(m_key.id().id), dnet_cmd_string(DNET_CMD_WRITE_NEW), groups, trans,
		              status, jsons, datas, m_timer.elapsed());
	}

	std::tuple<std::string, std::string, std::string, std::string, std::string> dump_responses() const {
		auto dump = [this] (const char b, const char e, const std::function<std::string(const response &)> &f) {
			std::ostringstream str;
			str << b;
			for (auto it = m_responses.cbegin(); it != m_responses.cend(); ++it) {
				if (it != m_responses.cbegin())
					str << ", ";
				str << f(*it);
			}
			str << e;
			return str.str();
		};

		auto dump_array = [&dump] (const std::function<std::string(const response &)> &f) {
			return dump('[', ']', f);
		};

		auto dump_pairs = [&dump] (const std::function<std::string(const response &)> &f) {
			return dump('{', '}', [&f] (const response &r) {
				return std::to_string(r.group) + ": " + f(r);
			});
		};

		auto groups = dump_array([] (const response &r) {
			return std::to_string(r.group);
		});

		auto status = dump_pairs([] (const response &r) { return std::to_string(r.status); });
		auto json = dump_pairs([] (const response &r) { return std::to_string(r.json_size); });
		auto data = dump_pairs([] (const response &r) { return std::to_string(r.data_size); });
		auto trans = dump_pairs([] (const response &r) { return std::to_string(r.trans); });

		return std::make_tuple(groups, status, json, data, trans);
	}

	timer m_timer;
	key m_key;
	session m_session;
	async_result_handler<write_result_entry> m_handler;
	std::vector<response> m_responses;
	std::unique_ptr<dnet_logger> m_log;
};

async_write_result send_write(const session &orig_sess, const key &id, const dnet_write_request &request,
                              const argument_data &json, const argument_data &data) {

	auto packet = [&] () {
		auto header = serialize(request);

		auto ret = data_pointer::allocate(header.size() + json.size() + data.size());
		memcpy(ret.data(), header.data(), header.size());
		memcpy(ret.skip(header.size()).data(), json.data(), json.size());
		memcpy(ret.skip(header.size() + json.size()).data(), data.data(), data.size());
		return ret;
	} ();

	transport_control control;
	control.set_key(id.id());
	control.set_command(DNET_CMD_WRITE_NEW);
	control.set_cflags(orig_sess.get_cflags() | DNET_FLAGS_NEED_ACK);
	control.set_data(packet.data(), packet.size());

	async_write_result result(orig_sess);
	auto handler = std::make_shared<write_handler>(result, orig_sess, id);
	handler->start(control, request);
	return result;
}

static dnet_write_request create_write_request(const session &sess)
{
	dnet_write_request request;
	memset(&request, 0, sizeof(request));

	request.ioflags = sess.get_ioflags();
	request.user_flags = sess.get_user_flags();
	request.cache_lifetime = sess.get_cache_lifetime();

	request.timestamp = sess.get_timestamp();
	if (dnet_time_is_empty(&request.timestamp)) {
		dnet_current_time(&request.timestamp);
	}

	request.json_timestamp = sess.get_json_timestamp();
	if (dnet_time_is_empty(&request.json_timestamp)) {
		request.json_timestamp = request.timestamp;
	}

	dnet_current_time(&request.deadline);
	request.deadline.tsec += sess.get_timeout();

	return request;
}

async_write_result session::write(const key &id,
                                  const argument_data &json, uint64_t json_capacity,
                                  const argument_data &data, uint64_t data_capacity) {
	trace_scope scope{get_trace_id(), get_trace_bit()};
	transform(id);

	auto on_fail = [this](const error_info & error) {
		async_write_result result(*this);
		async_result_handler<write_result_entry> handler(result);
		handler.complete(error);
		return result;
	};

	try {
		validate_json(std::string((const char*)json.data(), json.size()));
	} catch (const std::exception &e) {
		return on_fail(create_error(-EINVAL, "invalid json: %s", e.what()));
	}

	if (json_capacity == 0) {
		json_capacity = json.size();
	}

	if (data_capacity == 0) {
		data_capacity = data.size();
	}

	if (json_capacity < json.size()) {
		return on_fail(create_error(-EINVAL,
		                            "json_capacity (%llu) is less than json.size() (%llu)",
		                            (unsigned long long)json_capacity,
		                            (unsigned long long)json.size()));
	}

	if (data_capacity < data.size()) {
		return on_fail(create_error(-EINVAL,
		                            "data_capacity (%llu) is less than data.size() (%llu)",
		                            (unsigned long long)data_capacity,
		                            (unsigned long long)data.size()));
	}

	dnet_write_request request = create_write_request(*this);

	request.ioflags |= DNET_IO_FLAGS_PREPARE |
	                   DNET_IO_FLAGS_COMMIT |
	                   DNET_IO_FLAGS_PLAIN_WRITE;
	request.ioflags &= ~DNET_IO_FLAGS_UPDATE_JSON;

	request.json_size = json.size();
	request.json_capacity = json_capacity;

	request.data_offset = 0;
	request.data_commit_size = request.data_size = data.size();
	request.data_capacity = data_capacity;

	return send_write(*this, id, request, json, data);
}

async_lookup_result session::write_prepare(const key &id,
                                           const argument_data &json, uint64_t json_capacity,
                                           const argument_data &data, uint64_t data_offset, uint64_t data_capacity) {
	trace_scope scope{get_trace_id(), get_trace_bit()};
	transform(id);

	auto on_fail = [this](const error_info & error) {
		async_write_result result(*this);
		async_result_handler<write_result_entry> handler(result);
		handler.complete(error);
		return result;
	};

	try {
		validate_json(std::string((const char*)json.data(), json.size()));
	} catch (const std::exception &e) {
		return on_fail(create_error(-EINVAL, "invalid json: %s", e.what()));
	}

	if (json_capacity == 0) {
		json_capacity = json.size();
	}

	if (data_capacity == 0) {
		data_capacity = data_offset + data.size();
	}

	if (json_capacity < json.size()) {
		return on_fail(create_error(-EINVAL,
		                            "json_capacity (%llu) is less than json.size() (%llu)",
		                            (unsigned long long)json_capacity,
		                            (unsigned long long)json.size()));
	}

	if (data_capacity < data_offset + data.size()) {
		return on_fail(create_error(-EINVAL,
		                            "data_capacity (%llu) is less than data_offset (%llu) + data.size() (%llu)",
		                            (unsigned long long)data_capacity,
		                            (unsigned long long)data_offset,
		                            (unsigned long long)data.size()));
	}

	dnet_write_request request = create_write_request(*this);

	request.ioflags |= DNET_IO_FLAGS_PREPARE | DNET_IO_FLAGS_PLAIN_WRITE;
	request.ioflags &= ~(DNET_IO_FLAGS_COMMIT | DNET_IO_FLAGS_UPDATE_JSON);

	request.json_size = json.size();
	request.json_capacity = json_capacity;

	request.data_offset = data_offset;
	request.data_size = data.size();
	request.data_capacity = data_capacity;

	return send_write(*this, id, request, json, data);
}

async_lookup_result session::write_plain(const key &id,
                                         const argument_data &json,
                                         const argument_data &data, uint64_t data_offset) {
	trace_scope scope{get_trace_id(), get_trace_bit()};
	transform(id);

	try {
		validate_json(std::string((const char*)json.data(), json.size()));
	} catch (const std::exception &e) {
		async_write_result result(*this);
		async_result_handler<write_result_entry> handler(result);
		handler.complete(create_error(-EINVAL, "invalid json: %s", e.what()));
		return result;
	}

	dnet_write_request request = create_write_request(*this);

	request.ioflags |= DNET_IO_FLAGS_PLAIN_WRITE;
	request.ioflags &= ~(DNET_IO_FLAGS_PREPARE | DNET_IO_FLAGS_COMMIT | DNET_IO_FLAGS_UPDATE_JSON);

	request.json_size = json.size();

	request.data_offset = data_offset;
	request.data_size = data.size();

	return send_write(*this, id, request, json, data);
}

async_lookup_result session::write_commit(const key &id,
                                          const argument_data &json,
                                          const argument_data &data, uint64_t data_offset, uint64_t data_commit_size) {
	trace_scope scope{get_trace_id(), get_trace_bit()};
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

	dnet_write_request request = create_write_request(*this);

	request.ioflags |= DNET_IO_FLAGS_COMMIT | DNET_IO_FLAGS_PLAIN_WRITE;
	request.ioflags &= ~(DNET_IO_FLAGS_PREPARE | DNET_IO_FLAGS_UPDATE_JSON);

	request.json_size = json.size();

	request.data_offset = data_offset;
	request.data_size = data.size();
	request.data_commit_size = data_commit_size;

	return send_write(*this, id, request, json, data);
}

async_lookup_result session::update_json(const key &id, const argument_data &json) {
	trace_scope scope{get_trace_id(), get_trace_bit()};
	transform(id);

	try {
		validate_json(std::string((const char*)json.data(), json.size()));
	} catch (const std::exception &e) {
		async_write_result result(*this);
		async_result_handler<write_result_entry> handler(result);
		handler.complete(create_error(-EINVAL, "invalid json: %s", e.what()));
		return result;
	}

	dnet_write_request request = create_write_request(*this);

	request.ioflags |= DNET_IO_FLAGS_UPDATE_JSON;
	request.ioflags &= ~(DNET_IO_FLAGS_COMMIT | DNET_IO_FLAGS_PREPARE | DNET_IO_FLAGS_PLAIN_WRITE);

	request.json_size = json.size();

	return send_write(*this, id, request, json, "");
}

async_iterator_result session::start_iterator(const address &addr, uint32_t backend_id,
                                              uint64_t flags,
                                              const std::vector<dnet_iterator_range> &key_ranges,
                                              const std::tuple<dnet_time, dnet_time> &time_range) {
	trace_scope scope{get_trace_id(), get_trace_bit()};
	if (key_ranges.empty()) {
		flags &= ~DNET_IFLAGS_KEY_RANGE;
	} else {
		flags |= DNET_IFLAGS_KEY_RANGE;
	}

	auto request = serialize(dnet_iterator_request{
		DNET_ITYPE_NETWORK,
		flags,
		key_ranges,
		time_range,
	});

	transport_control control;
	control.set_command(DNET_CMD_ITERATOR_NEW);
	control.set_cflags(get_cflags() | DNET_FLAGS_NEED_ACK | DNET_FLAGS_NOLOCK);
	control.set_data(request.data(), request.size());

	auto session = clean_clone();
	session.set_direct_id(addr, backend_id);
	return async_result_cast<iterator_result_entry>(*this, send_to_single_state(session, control));
}

async_iterator_result session::server_send(const std::vector<dnet_raw_id> &keys, uint64_t flags, uint64_t chunk_size,
                                           const int src_group, const std::vector<int> &dst_groups) {
	std::vector<key> converted_keys;
	converted_keys.reserve(keys.size());

	for (const auto &key: keys) {
		converted_keys.emplace_back(key);
	}

	return server_send(converted_keys, flags, chunk_size, src_group, dst_groups);
}

async_iterator_result session::server_send(const std::vector<std::string> &keys, uint64_t flags, uint64_t chunk_size,
                                           const int src_group, const std::vector<int> &dst_groups) {
	std::vector<key> converted_keys;
	converted_keys.reserve(keys.size());

	for (const auto &key: keys) {
		converted_keys.emplace_back(key);
	}

	return server_send(converted_keys, flags, chunk_size, src_group, dst_groups);
}

async_iterator_result session::server_send(const std::vector<key> &keys, uint64_t flags, uint64_t chunk_size,
                                           const int src_group, const std::vector<int> &dst_groups) {
	trace_scope scope{get_trace_id(), get_trace_bit()};
	if (dst_groups.empty()) {
		async_iterator_result result{*this};
		async_result_handler<iterator_result_entry> handler{result};
		handler.complete(create_error(-ENXIO, "server_send: remote groups list is empty"));
		return result;
	}

	if (keys.empty()) {
		async_iterator_result result{*this};
		async_result_handler<iterator_result_entry> handler{result};
		handler.complete(create_error(-ENXIO, "server_send: keys list is empty"));
		return result;
	}

	struct remote {
		dnet_addr address;
		int backend_id;

		bool operator<(const remote &other) const {
			const int cmp = dnet_addr_cmp(&address, &other.address);
			return cmp == 0 ? (backend_id < other.backend_id) : (cmp < 0);
		}
	};

	std::map<remote, std::vector<dnet_raw_id>> remotes_ids;

	dnet_addr address;
	int backend_id;
	for (auto &key: keys) {
		transform(key);
		const int err = dnet_lookup_addr(get_native(), nullptr, 0, &key.id(), src_group, &address, &backend_id);
		if (err != 0) {
			async_iterator_result result{*this};
			async_result_handler<iterator_result_entry> handler{result};
			handler.complete(create_error(-ENXIO,
			                              "server_send: could not locate address & backend for requested key: %d:%s",
			                              src_group, dnet_dump_id(&key.id())));
			return result;
		}

		remotes_ids[remote{address, backend_id}].emplace_back(key.raw_id());
	}

	std::vector<async_iterator_result> results;
	results.reserve(remotes_ids.size());

	{
		remote remote;
		std::vector<dnet_raw_id> ids;
		for (auto &pair: remotes_ids) {
			std::tie(remote, ids) = pair;

			auto request = serialize(dnet_server_send_request{
				ids,
				dst_groups,
				flags,
				chunk_size
			});

			transport_control control;
			control.set_command(DNET_CMD_SEND_NEW);
			control.set_cflags(DNET_FLAGS_NEED_ACK | DNET_FLAGS_NOLOCK);
			control.set_data(request.data(), request.size());

			session session = clean_clone();
			session.set_direct_id(remote.address, remote.backend_id);
			results.emplace_back(
				async_result_cast<iterator_result_entry>(*this, send_to_single_state(session, control))
			);
		}
	}

	return aggregated(*this, results.begin(), results.end());
}

}}} // ioremap::elliptics::newapi
