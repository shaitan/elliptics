#include "elliptics/newapi/session.hpp"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include <blackhole/attribute.hpp>

#include "elliptics/async_result_cast.hpp"
#include "bindings/cpp/callback_p.h"
#include "bindings/cpp/node_p.hpp"
#include "bindings/cpp/session_internals.hpp"
#include "bindings/cpp/timer.hpp"

#include "library/access_context.h"
#include "library/elliptics.h"
#include "library/protocol.hpp"
#include "library/common.hpp"

#include "bindings/cpp/functional_p.h"

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

class lookup_handler : public std::enable_shared_from_this<lookup_handler> {
private:
	class inner_handler : public multigroup_handler<lookup_handler, lookup_result_entry> {
	public:
		inner_handler(const session &s,
		              const async_lookup_result &result,
		              std::vector<int> &&groups,
		              const dnet_trans_control &control)
		: parent_type(s, result, std::move(groups))
		, m_control(control) {
		}

	protected:
		async_generic_result send_to_next_group() override {
			m_control.id.group_id = current_group();
			return send_to_single_state(m_sess, m_control);
		}

	private:
		dnet_trans_control m_control;
	};

public:
	explicit lookup_handler(const session &session, const async_lookup_result &result, const key &key)
	: m_key(key)
	, m_session(session.clean_clone())
	, m_handler(result)
	, m_log(session.get_logger()) {
		m_session.set_checker(session.get_checker());
		m_handler.set_total(1);
	}

	void start(std::vector<int> &&groups, const transport_control &control) {
		DNET_LOG_INFO(m_log, "{}: {}: started: groups: {}, cflags: {}", dnet_dump_id_str(m_key.raw_id().id),
		              dnet_cmd_string(control.get_native().cmd), groups,
		              dnet_flags_dump_cflags(control.get_native().cflags));

		m_context.reset(new dnet_access_context(m_session.get_native_node()));
		if (m_context) {
			m_context->add({{"cmd", std::string(dnet_cmd_string(control.get_native().cmd))},
			                {"id", std::string(dnet_dump_id_str(m_key.id().id))},
			                {"access", "client"},
			                {"cflags",  std::string(dnet_flags_dump_cflags(control.get_native().cflags))},
			                {"trace_id", to_hex_string(m_session.get_trace_id())},
			               });
		}

		m_transes.reserve(groups.size());

		async_lookup_result result{m_session};
		auto handler = std::make_shared<inner_handler>(m_session, result, std::move(groups),
		                                               control.get_native());
		handler->set_total(m_handler.get_total());
		handler->start();
		result.connect(
			std::bind(&lookup_handler::process, shared_from_this(), std::placeholders::_1),
			std::bind(&lookup_handler::complete, shared_from_this(), std::placeholders::_1)
		);
	}

private:
	void process(const lookup_result_entry &entry) {
		m_handler.process(entry);

		const auto *cmd = entry.command();
		m_transes.emplace_back(cmd->trans);
	}

	void complete(const error_info &error) {
		m_handler.complete(error);

		if (m_context) {
			m_context->add({"transes", [&] {
				std::ostringstream result;
				result << m_transes;
				return std::move(result.str());
			}()});
			m_context.reset(); // destroy context to print access log
		}
	}

	const key m_key;
	session m_session;
	async_result_handler<lookup_result_entry> m_handler;
	std::unique_ptr<dnet_logger> m_log;

	std::vector<uint64_t> m_transes;
	std::unique_ptr<dnet_access_context> m_context;
};

async_lookup_result session::lookup(const key &id) {
	trace_scope scope{*this};
	DNET_SESSION_GET_GROUPS(async_lookup_result);
	transform(id);

	transport_control control;
	control.set_key(id.id());
	control.set_command(DNET_CMD_LOOKUP_NEW);
	control.set_cflags(get_cflags() | DNET_FLAGS_NEED_ACK);

	async_lookup_result result(*this);
	auto handler = std::make_shared<lookup_handler>(*this, result, id);
	handler->start(std::move(groups), control.get_native());
	return result;
}

class remove_handler : public std::enable_shared_from_this<remove_handler> {
public:
	explicit remove_handler(const async_remove_result &result,
	                        const session &session,
	                        const key &key)
	: m_key(key)
	, m_session(session.clean_clone())
	, m_handler(result)
	, m_log(session.get_logger()) {
		m_session.set_checker(session.get_checker());

		const size_t count = m_session.get_groups().size();
		m_transes.reserve(count);
	}

	void start(const transport_control &control, const dnet_remove_request &request) {
		DNET_LOG_INFO(m_log, "{}: {}: started: groups: {}, ioflags: {}, ts: '{}",
		              dnet_dump_id_str(m_key.id().id), dnet_cmd_string(control.get_native().cmd),
		              m_session.get_groups(), dnet_flags_dump_ioflags(request.ioflags),
		              dnet_print_time(&request.timestamp));

		m_context.reset(new dnet_access_context(m_session.get_native_node()));
		if (m_context) {
			m_context->add({{"cmd", std::string(dnet_cmd_string(control.get_native().cmd))},
			                {"id", std::string(dnet_dump_id_str(m_key.id().id))},
			                {"access", "client"},
			                {"ioflags", std::string(dnet_flags_dump_ioflags(request.ioflags))},
			                {"cflags", std::string(dnet_flags_dump_cflags(control.get_native().cflags))},
			                {"ts", std::string(dnet_print_time(&request.timestamp))},
			                {"trace_id", to_hex_string(m_session.get_trace_id())},
			               });
		}

		auto rr = send_to_groups(m_session, control);
		m_handler.set_total(rr.total());

		rr.connect(
			std::bind(&remove_handler::process, shared_from_this(), std::placeholders::_1),
			std::bind(&remove_handler::complete, shared_from_this(), std::placeholders::_1)
		);
	}

private:
	void process(const remove_result_entry &entry) {
		m_handler.process(entry);

		const auto *cmd = entry.command();
		m_transes.emplace_back(cmd->trans);
	}

	void complete(const error_info &error) {
		m_handler.complete(error);

		if (m_context) {
			m_context->add({"transes", [&] {
				std::ostringstream result;
				result << m_transes;
				return std::move(result.str());
			}()});
			m_context.reset(); // destroy context to print access log
		}
	}

private:

	const key m_key;
	session m_session;
	async_result_handler<remove_result_entry> m_handler;
	std::unique_ptr<dnet_logger> m_log;

	std::vector<uint64_t> m_transes;
	std::unique_ptr<dnet_access_context> m_context;
};

async_remove_result session::remove(const key &id) {
	trace_scope scope{*this};
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

	async_remove_result result{*this};
	auto handler = std::make_shared<remove_handler>(result, *this, id);
	handler->start(control, request);
	return result;
}

/* TODO: refactor read_handler/write_handler because they have a lot in common */
class read_handler : public std::enable_shared_from_this<read_handler> {
private:
	class inner_handler : public multigroup_handler<inner_handler, read_result_entry> {
	public:
		inner_handler(const session &session,
		              const async_read_result &result,
		              std::vector<int> &&groups,
		              const dnet_trans_control &control,
		              const dnet_read_request &request)
		: parent_type(session, result, std::move(groups))
		, m_control(control) {
			m_packet = serialize(request);
			m_control.data = m_packet.data();
			m_control.size = m_packet.size();
		}

	protected:
		async_generic_result send_to_next_group() override {
			m_control.id.group_id = current_group();
			return send_to_single_state(m_sess, m_control);
		}

	private:
		dnet_trans_control m_control;
		data_pointer m_packet;
	};

public:
	explicit read_handler(const session &session,
	                      const async_read_result &result,
	                      const key &key)
	: m_key(key)
	, m_session(session.clean_clone())
	, m_handler(result)
	, m_log(session.get_logger()) {
		m_session.set_checker(session.get_checker());
		m_handler.set_total(1);
	}

	void start(std::vector<int> &&groups, const transport_control &control, const dnet_read_request &request) {
		DNET_LOG_INFO(m_log, "{}: {}: started: groups: {}, ioflags: {}, read-flags: {}, offset: {}, size: {}",
		              dnet_dump_id_str(m_key.raw_id().id), dnet_cmd_string(control.get_native().cmd), groups,
		              dnet_flags_dump_ioflags(request.ioflags), dnet_dump_read_flags(request.read_flags),
		              request.data_offset, request.data_size);

		m_context.reset(new dnet_access_context(m_session.get_native_node()));
		if (m_context) {
			m_context->add({{"cmd", std::string(dnet_cmd_string(control.get_native().cmd))},
			                {"id", std::string(dnet_dump_id_str(m_key.id().id))},
			                {"access", "client"},
			                {"ioflags", std::string(dnet_flags_dump_ioflags(request.ioflags))},
			                {"cflags", std::string(dnet_flags_dump_cflags(control.get_native().cflags))},
			                {"read_flags", std::string(dnet_dump_read_flags(request.read_flags))},
			                {"request_offset", request.data_offset},
			                {"request_size", request.data_size},
			                {"deadline", std::string(dnet_print_time(&request.deadline))},
			                {"trace_id", to_hex_string(m_session.get_trace_id())},
			               });
		}

		m_responses.groups.reserve(groups.size());
		m_responses.transes.reserve(groups.size());
		m_responses.statuses.reserve(groups.size());
		m_responses.data_sizes.reserve(groups.size());
		m_responses.json_sizes.reserve(groups.size());
		m_transes.reserve(groups.size());

		async_read_result result(m_session);
		auto handler = std::make_shared<inner_handler>(m_session, result, std::move(groups),
		                                               control.get_native(), request);
		handler->set_total(m_handler.get_total());
		handler->start();
		result.connect(
			std::bind(&read_handler::process, shared_from_this(), std::placeholders::_1),
			std::bind(&read_handler::complete, shared_from_this(), std::placeholders::_1)
		);
	}

private:
	void process(const read_result_entry &entry) {
		m_handler.process(entry);

		const auto *cmd = entry.command();
		m_transes.emplace_back(cmd->trans);

		if (!entry.error()) {
			m_read_json_size += entry.io_info().json_size;
			m_read_data_size += entry.io_info().data_size;
		}

		const auto &response = callback_cast<read_result_entry>(entry);
		const auto group = cmd->id.group_id;
		m_responses.groups.emplace_back(group);
		m_responses.transes.emplace_back(group, cmd->trans);
		m_responses.statuses.emplace_back(group, cmd->status);
		m_responses.data_sizes.emplace_back(group, cmd->status ? 0 : response.io_info().data_size);
		m_responses.json_sizes.emplace_back(group, cmd->status ? 0 : response.io_info().json_size);
	}

	void complete(const error_info &error) {
		m_handler.complete(error);

		DNET_LOG_INFO(m_log, "{}: {}: finished: groups: {}, trans: {}, status: {}, json-size: {}, data-size: "
		                     "{}, total_time: {}",
		              dnet_dump_id_str(m_key.id().id), dnet_cmd_string(DNET_CMD_READ_NEW), m_responses.groups,
		              m_responses.transes, m_responses.statuses, m_responses.json_sizes, m_responses.data_sizes,
		              m_timer.get_us());

		if (m_context) {
			m_context->add({{"transes", [&] {
				        	std::ostringstream result;
				        	result << m_transes;
				        	return std::move(result.str());
			                }()},
			                {"read_json_size", m_read_json_size},
			                {"read_data_size", m_read_data_size},
			               });
			m_context.reset(); // destroy context to print access log
		}
	}

	util::steady_timer m_timer{};
	const key m_key;
	session m_session;
	async_result_handler<read_result_entry> m_handler;
	std::unique_ptr<dnet_logger> m_log;

	std::vector<uint64_t> m_transes;
	uint64_t m_read_json_size{0};
	uint64_t m_read_data_size{0};

	struct {
		std::vector<uint32_t> groups;
		std::vector<std::pair<uint32_t, int>> statuses;
		std::vector<std::pair<uint32_t, uint64_t>> transes;
		std::vector<std::pair<uint32_t, uint64_t>> data_sizes;
		std::vector<std::pair<uint32_t, uint64_t>> json_sizes;
	} m_responses;

	std::unique_ptr<dnet_access_context> m_context;
};

async_read_result send_read(const session &orig_sess, const key &id, const dnet_read_request &request,
                            std::vector<int> &&groups) {
	transport_control control;
	control.set_key(id.id());
	control.set_command(DNET_CMD_READ_NEW);
	control.set_cflags(orig_sess.get_cflags() | DNET_FLAGS_NEED_ACK);

	async_read_result result(orig_sess);
	auto handler = std::make_shared<read_handler>(orig_sess, result, id);
	handler->start(std::move(groups), control.get_native(), request);
	return result;
}

async_read_result session::read_json(const key &id) {
	trace_scope scope{*this};
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
	trace_scope scope{*this};
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
	trace_scope scope{*this};
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
public:
	explicit write_handler(const async_write_result &result,
	                       const session &session,
	                       const key &key)
	: m_key(key)
	, m_session(session.clean_clone())
	, m_handler(result)
	, m_log(session.get_logger()) {
		m_session.set_checker(session.get_checker());
	}

	void start(const transport_control &control, const dnet_write_request &request) {
		DNET_LOG_INFO(m_log, "{}: {}: started: groups: {}, ioflags: {}, "
		                     "json: {{size: {}, capacity: {}, ts: '{}'}}, "
		                     "data: {{offset: {}, size: {}, capacity: {}, commit-size: {}, ts: '{}'}}",
		              dnet_dump_id_str(m_key.id().id), dnet_cmd_string(control.get_native().cmd),
		              m_session.get_groups(), dnet_flags_dump_ioflags(request.ioflags),
		              request.json_size, request.json_capacity, dnet_print_time(&request.json_timestamp),
		              request.data_offset, request.data_size, request.data_capacity, request.data_commit_size,
		              dnet_print_time(&request.timestamp));

		m_context.reset(new dnet_access_context(m_session.get_native_node()));
		if (m_context) {
			m_context->add({{"cmd", std::string(dnet_cmd_string(control.get_native().cmd))},
			                {"id", std::string(dnet_dump_id_str(m_key.id().id))},
			                {"access", "client"},
			                {"ioflags", std::string(dnet_flags_dump_ioflags(request.ioflags))},
			                {"cflags", std::string(dnet_flags_dump_cflags(control.get_native().cflags))},
			                {"user_flags", request.user_flags},
			                {"json_ts", std::string(dnet_print_time(&request.json_timestamp))},
			                {"json_size", request.json_size},
			                {"json_capacity", request.json_capacity},
			                {"data_ts", std::string(dnet_print_time(&request.timestamp))},
			                {"data_offset", request.data_offset},
			                {"data_size", request.data_size},
			                {"data_capacity", request.data_capacity},
			                {"data_commit_size", request.data_commit_size},
			                {"cache_lifetime", request.cache_lifetime},
			                {"deadline", std::string(dnet_print_time(&request.deadline))},
			                {"trace_id", to_hex_string(m_session.get_trace_id())},
			               });
		}

		const auto groups_number = m_session.get_groups().size();
		m_responses.groups.reserve(groups_number);
		m_responses.statuses.reserve(groups_number);
		m_responses.transes.reserve(groups_number);
		m_responses.json_sizes.reserve(groups_number);
		m_responses.data_sizes.reserve(groups_number);
		m_transes.reserve(groups_number);

		auto rr = async_result_cast<write_result_entry>(m_session, send_to_groups(m_session, control));
		m_handler.set_total(rr.total());

		rr.connect(
			std::bind(&write_handler::process, shared_from_this(), std::placeholders::_1),
			std::bind(&write_handler::complete, shared_from_this(), std::placeholders::_1)
		);
	}

private:
	void process(const write_result_entry &entry) {
		m_handler.process(entry);

		const auto *cmd = entry.command();
		m_transes.emplace_back(cmd->trans);

		const auto &response = callback_cast<write_result_entry>(entry);
		const auto group = cmd->id.group_id;
		m_responses.groups.emplace_back(group);
		m_responses.transes.emplace_back(group, cmd->trans);
		m_responses.statuses.emplace_back(group, cmd->status);
		m_responses.json_sizes.emplace_back(group, cmd->status ? 0 : response.record_info().json_size);
		m_responses.data_sizes.emplace_back(group, cmd->status ? 0 : response.record_info().data_size);
	}

	void complete(const error_info &error) {
		m_handler.complete(error);

		DNET_LOG_INFO(m_log, "{}: {}: finished: groups: {}, trans: {}, status: {}, json-size: {}, data-size: "
		                     "{}, total_time: {}",
		              dnet_dump_id_str(m_key.id().id), dnet_cmd_string(DNET_CMD_WRITE_NEW), m_responses.groups,
		              m_responses.transes, m_responses.statuses, m_responses.json_sizes, m_responses.data_sizes,
		              m_timer.get_us());

		if (m_context) {
			m_context->add({"trans", [&] {
				        	std::ostringstream result;
				        	result << m_transes;
				        	return std::move(result.str());
			               }()});
			m_context.reset(); // destroy context to print access log
		}
	}

	util::steady_timer m_timer{};
	const key m_key;
	session m_session;
	async_result_handler<write_result_entry> m_handler;
	std::unique_ptr<dnet_logger> m_log;

	std::vector<uint64_t> m_transes;

	struct {
		std::vector<uint32_t> groups;
		std::vector<std::pair<uint32_t, int>> statuses;
		std::vector<std::pair<uint32_t, uint64_t>> transes;
		std::vector<std::pair<uint32_t, uint64_t>> json_sizes;
		std::vector<std::pair<uint32_t, uint64_t>> data_sizes;
	} m_responses;
	std::unique_ptr<dnet_access_context> m_context;
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
	trace_scope scope{*this};
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
	trace_scope scope{*this};
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
	trace_scope scope{*this};
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
	trace_scope scope{*this};
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
	trace_scope scope{*this};
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

class iterator_handler : public std::enable_shared_from_this<iterator_handler> {
public:
	explicit iterator_handler(const async_iterator_result &result,
	                          const session &session,
	                          const address &address,
	                          const uint32_t backend_id)
	: m_session(session.clean_clone())
	, m_handler(result)
	, m_log(session.get_logger())
	, m_address(address)
	, m_backend_id(backend_id) {
		m_session.set_direct_id(m_address, m_backend_id);
	}

	void start(const transport_control &control, const dnet_iterator_request &request) {
		DNET_LOG_INFO(m_log, "{}: started: st: {}/{}, id: {}, action: {}, type: {}, iflags: {}, "
		                     "key_ranges: {}, ts_range: '{}' - '{}', groups: {}",
		              dnet_cmd_string(control.get_native().cmd), m_address.to_string_with_family(),
		              m_backend_id, request.iterator_id, request.action, request.type, request.flags,
		              request.key_ranges.size(), dnet_print_time(&std::get<0>(request.time_range)),
		              dnet_print_time(&std::get<1>(request.time_range)), request.groups);

		m_context.reset(new dnet_access_context(m_session.get_native_node()));
		if (m_context) {
			m_context->add({{"cmd", std::string(dnet_cmd_string(control.get_native().cmd))},
			                {"access", "client"},
			                {"st", m_address.to_string_with_family()},
			                {"backend_id", m_backend_id},
			                {"iterator_id", request.iterator_id},
			                {"action", request.action},
			                {"type", request.type},
			                {"flags", request.flags},
			                {"key_ranges", request.key_ranges.size()},
			                {"time_range", [&] {
				        	std::ostringstream result;
				        	result << dnet_print_time(&std::get<0>(request.time_range)) << " - "
				        	       << dnet_print_time(&std::get<1>(request.time_range));
				        	return std::move(result.str());
			                }()},
			                {"groups", [&] {
				        	std::ostringstream result;
				        	result << request.groups;
				        	return std::move(result.str());
			                }()},
			                {"trace_id", to_hex_string(m_session.get_trace_id())},
			               });
		}

		auto rr = async_result_cast<iterator_result_entry>(m_session, send_to_single_state(m_session, control));
		rr.connect(
			std::bind(&iterator_handler::process, shared_from_this(), std::placeholders::_1),
			std::bind(&iterator_handler::complete, shared_from_this(), std::placeholders::_1)
		);
	}

private:
	void process(const iterator_result_entry &entry) {
		m_handler.process(entry);

		const auto *cmd = entry.command();
		m_trans = cmd->trans;
		auto it = m_statuses.emplace(cmd->status, 1);
		if (!it.second)
			++it.first->second;
	}

	void complete(const error_info &error) {
		m_handler.complete(error);

		if (m_context) {
			m_context->add({{"trans", m_trans},
			                {"statuses", [&] {
				        	std::ostringstream result;
				        	result << m_statuses;
				        	return std::move(result.str());
			                }()},
			               });
			m_context.reset(); // destroy context to print access log
		}
	}

private:
	session m_session;
	async_result_handler<iterator_result_entry> m_handler;
	std::unique_ptr<dnet_logger> m_log;
	const address m_address;
	const uint32_t m_backend_id;

	uint64_t m_trans{0};

	std::unordered_map<int, size_t> m_statuses;
	std::unique_ptr<dnet_access_context> m_context;
};

async_iterator_result session::start_iterator(const address &addr, uint32_t backend_id,
                                              uint64_t flags,
                                              const std::vector<dnet_iterator_range> &key_ranges,
                                              const std::tuple<dnet_time, dnet_time> &time_range) {
	trace_scope scope{*this};
	if (key_ranges.empty()) {
		flags &= ~DNET_IFLAGS_KEY_RANGE;
	} else {
		flags |= DNET_IFLAGS_KEY_RANGE;
	}

	dnet_iterator_request request{
		DNET_ITYPE_NETWORK,
		flags,
		key_ranges,
		time_range,
	};

	auto packet = serialize(request);

	transport_control control;
	control.set_command(DNET_CMD_ITERATOR_NEW);
	control.set_cflags(get_cflags() | DNET_FLAGS_NEED_ACK | DNET_FLAGS_NOLOCK);
	control.set_data(packet.data(), packet.size());

	async_iterator_result result(*this);
	auto handler = std::make_shared<iterator_handler>(result, *this, addr, backend_id);
	handler->start(control, request);
	return result;
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

class server_send_handler : public std::enable_shared_from_this<server_send_handler> {
public:
	explicit server_send_handler(const async_iterator_result &result,
	                             session &session)
	: m_session(session.clone())
	, m_handler(result)
	, m_log(session.get_logger()) {
	}

	void start(const std::vector<key> &keys,
	           uint64_t flags,
	           uint64_t chunk_size,
	           const int src_group,
	           const std::vector<int> &dst_groups) {
		DNET_LOG_INFO(m_log, "{}: started: flags: {}, src_group: {}, dst_groups: {}, "
		                     "chunk_size: {}, keys: {}",
		              dnet_cmd_string(DNET_CMD_SEND_NEW), flags, src_group, dst_groups, chunk_size,
		              keys.size());

		m_context.reset(new dnet_access_context(m_session.get_native_node()));
		if (m_context) {
			m_context->add({{"cmd", std::string(dnet_cmd_string(DNET_CMD_SEND_NEW))},
			                {"access", "client"},
			                {"keys", keys.size()},
			                {"groups", [&] {
				        	std::ostringstream result;
				        	result << dst_groups;
				        	return std::move(result.str());
			                }()},
			                {"flags", flags},
			                {"chunk_size", chunk_size},
			                {"trace_id", to_hex_string(m_session.get_trace_id())},
			               });
		}

		if (dst_groups.empty()) {
			m_handler.complete(create_error(-ENXIO, "server_send: remote groups list is empty"));
			return;
		}

		if (keys.empty()) {
			m_handler.complete(create_error(-ENXIO, "server_send: keys list is empty"));
			return;
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
		for (const auto &key: keys) {
			m_session.transform(key);
			const int err = dnet_lookup_addr(m_session.get_native(), nullptr, 0, &key.id(), src_group,
			                                 &address, &backend_id);
			if (err) {
				m_handler.complete(create_error(-ENXIO,
				                               "server_send: could not locate address & backend for "
				                               "requested key: %d:%s",
				                               src_group, dnet_dump_id(&key.id())));
				return;
			}

			remotes_ids[remote{address, backend_id}].emplace_back(key.raw_id());
		}

		std::vector<async_iterator_result> results;
		results.reserve(remotes_ids.size());
		for (auto &pair: remotes_ids) {
			const auto &remote = pair.first;
			const auto &ids = pair.second;

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

			session session = m_session.clean_clone();
			session.set_direct_id(remote.address, remote.backend_id);
			results.emplace_back(
				async_result_cast<iterator_result_entry>(m_session,
				                                         send_to_single_state(session, control))
			);
		}

		auto rr = aggregated(m_session, results);
		m_handler.set_total(rr.total());

		rr.connect(
			std::bind(&server_send_handler::process, shared_from_this(), std::placeholders::_1),
			std::bind(&server_send_handler::complete, shared_from_this(), std::placeholders::_1)
		);
	}

private:
	void process(const iterator_result_entry &entry) {
		m_handler.process(entry);

		const auto *cmd = entry.command();
		m_transes.emplace(cmd->trans);
		auto it = m_statuses.emplace(entry.status(), 1);
		if (!it.second)
			++it.first->second;
	}

	void complete(const error_info &error) {
		m_handler.complete(error);

		if (m_context) {
			m_context->add({{"transes",  [&] {
				        	std::ostringstream result;
				        	result << m_transes;
				        	return std::move(result.str());
			                }()},
			                {"statuses", [&] {
				        	std::ostringstream result;
				        	result << m_statuses;
				        	return std::move(result.str());
			                }()},
			               });
			m_context.reset(); // destroy context to print access log
		}
	}

private:
	session m_session;
	async_result_handler<iterator_result_entry> m_handler;
	std::unique_ptr<dnet_logger> m_log;

	std::unordered_set<uint64_t> m_transes;
	std::unordered_map<int, size_t> m_statuses;
	std::unique_ptr<dnet_access_context> m_context;
};

async_iterator_result session::server_send(const std::vector<key> &keys,
                                           uint64_t flags,
                                           uint64_t chunk_size,
                                           const int src_group,
                                           const std::vector<int> &dst_groups) {
	trace_scope scope{*this};

	async_iterator_result result(*this);
	auto handler = std::make_shared<server_send_handler>(result, *this);
	handler->start(keys, flags, chunk_size, src_group, dst_groups);
	return result;
}

class single_bulk_read_handler : public std::enable_shared_from_this<single_bulk_read_handler> {
public:
	explicit single_bulk_read_handler(const async_read_result &result,
	                                  const session &session,
	                                  const dnet_addr &addr)
	: m_session(session)
	, m_handler(result)
	, m_addr(addr)
	, m_log(session.get_logger()) {
	}

	void start(const transport_control &control, const dnet_bulk_read_request &request) {
		DNET_LOG_NOTICE(m_log, "{}: started: address: {}, flags: {}, read_flags: {}, num_keys: {}",
		                dnet_cmd_string(control.get_native().cmd), dnet_addr_string(&m_addr),
		                dnet_flags_dump_ioflags(request.ioflags), dnet_dump_read_flags(request.read_flags),
		                request.keys.size());

		auto rr = async_result_cast<read_result_entry>(m_session, send_to_single_state(m_session, control));
		m_handler.set_total(rr.total());

		m_keys.assign(request.keys.begin(), request.keys.end());
		std::sort(m_keys.begin(), m_keys.end());
		m_key_responses.resize(m_keys.size(), false);

		rr.connect(
			std::bind(&single_bulk_read_handler::process, shared_from_this(), std::placeholders::_1),
			std::bind(&single_bulk_read_handler::complete, shared_from_this(), std::placeholders::_1)
		);
	}

private:
	void process(const read_result_entry &entry) {
		auto cmd = entry.command();

		if (!entry.is_valid()) {
			DNET_LOG_ERROR(m_log, "{}: {}: process: invalid response, status: {}",
				       dnet_dump_id(&cmd->id), dnet_cmd_string(cmd->cmd), cmd->status);
			return;
		}

		bool found = false;
		for (auto it = std::lower_bound(m_keys.begin(), m_keys.end(), cmd->id); it != m_keys.end(); ++it) {
			if (dnet_id_cmp(&cmd->id, &*it) != 0)
				break;

			const auto index = std::distance(m_keys.begin(), it);

			if (m_key_responses[index])
				continue;

			m_handler.process(entry);

			m_key_responses[index] = true;
			found = true;
			break;
		}

		if (!found) {
			DNET_LOG_ERROR(m_log, "{}: {}: process: unknown key, status: {}",
				       dnet_dump_id(&cmd->id), dnet_cmd_string(cmd->cmd), cmd->status);
		}

		m_last_error = cmd->status;
	}

	void complete(const error_info &error) {
		dnet_cmd cmd;
		memset(&cmd, 0, sizeof(cmd));
		cmd.status = error ? error.code() : m_last_error;
		cmd.cmd = DNET_CMD_BULK_READ_NEW;
		cmd.trace_id = m_session.get_trace_id();
		cmd.flags = DNET_FLAGS_REPLY | DNET_FLAGS_MORE |
			(m_session.get_trace_bit() ? DNET_FLAGS_TRACE_BIT : 0);

		for (size_t i = 0; i < m_keys.size(); ++i) {
			if (m_key_responses[i])
				continue;

			cmd.id = m_keys[i];
			auto result_data = std::make_shared<ioremap::elliptics::callback_result_data>(&m_addr, &cmd);
			result_data->error = error ? error :
				create_error(m_last_error, "send_bulk_read: read failed for key: %s",
					     dnet_dump_id(&m_keys[i]));
			ioremap::elliptics::callback_result_entry entry(result_data);
			m_handler.process(callback_cast<read_result_entry>(entry));
		}

		m_handler.complete(error);

		DNET_LOG_NOTICE(m_log, "{}: finished: address: {}",
		                dnet_cmd_string(DNET_CMD_BULK_READ_NEW), dnet_addr_string(&m_addr));
	}

private:
	std::vector<dnet_id> m_keys;
	std::vector<bool> m_key_responses;
	session m_session;
	async_result_handler<read_result_entry> m_handler;
	int m_last_error{0};
	const dnet_addr m_addr;
	std::unique_ptr<dnet_logger> m_log;
};

class bulk_read_handler : public std::enable_shared_from_this<bulk_read_handler> {
public:
	explicit bulk_read_handler(const async_read_result &result,
	                           session &session,
	                           const std::vector<dnet_id> &keys)
	: m_session(session.clone())
	, m_handler(result)
	, m_log(session.get_logger())
	, m_keys(keys) {
	}

	void start(uint64_t read_flags) {
		DNET_LOG_INFO(m_log, "{}: started: keys: {}, read_flags: {}, ioflags: {}",
		              dnet_cmd_string(DNET_CMD_BULK_READ_NEW), m_keys.size(),
		              dnet_dump_read_flags(read_flags), dnet_flags_dump_ioflags(m_session.get_ioflags()));

		m_context.reset(new dnet_access_context(m_session.get_native_node()));
		if (m_context) {
			m_context->add({{"cmd", std::string(dnet_cmd_string(DNET_CMD_BULK_READ_NEW))},
			                {"access", "client"},
			                {"ioflags", std::string(dnet_flags_dump_ioflags(m_session.get_ioflags()))},
			                {"cflags", std::string(dnet_flags_dump_cflags(m_session.get_cflags()))},
			                {"read_flags", std::string(dnet_dump_read_flags(read_flags))},
			                {"keys", m_keys.size()},
			                {"trace_id", to_hex_string(m_session.get_trace_id())},
			               });
		}

		if (m_keys.empty()) {
			m_handler.complete(create_error(-ENXIO, "send_bulk_read: keys list is empty"));
			return;
		}

		auto dnet_addr_comparator = [] (const dnet_addr &lhs, const dnet_addr &rhs) -> bool {
			return dnet_addr_cmp(&lhs, &rhs) < 0;
		};

		std::map<dnet_addr, std::vector<dnet_id>, decltype(dnet_addr_comparator)> remotes_ids(
		dnet_addr_comparator); // node_address -> [list of keys]

		const bool has_direct_address = !!(m_session.get_cflags() & (DNET_FLAGS_DIRECT | DNET_FLAGS_DIRECT_BACKEND));

		if (!has_direct_address) {
			/* failed_result used as a container for storing responses for keys
			 * which are not in the route table
			 */
			dnet_addr address;
			dnet_cmd cmd;
			memset(&cmd, 0, sizeof(cmd));
			cmd.cmd = DNET_CMD_BULK_READ_NEW;
			cmd.trace_id = m_session.get_trace_id();
			cmd.flags = DNET_FLAGS_REPLY | DNET_FLAGS_MORE;
			if (m_session.get_trace_bit())
				cmd.flags |= DNET_FLAGS_TRACE_BIT;

			for (const auto &id : m_keys) {
				const int err = dnet_lookup_addr(m_session.get_native(), nullptr, 0, &id, id.group_id,
				                                 &address, nullptr);
				if (!err) {
					remotes_ids[address].emplace_back(id);
				} else {
					memset(&address, 0, sizeof(address));
					cmd.id = id;
					cmd.status = err;
					auto result_data = std::make_shared<callback_result_data>(&address, &cmd);
					result_data->error = create_error(err,
					                                  "send_bulk_read: could not locate address & "
					                                  "backend for requested key: %s",
					                                  dnet_dump_id(&id));
					ioremap::elliptics::callback_result_entry entry(result_data);
					process(callback_cast<read_result_entry>(entry));
				}
			}
		} else {
			const auto address = m_session.get_direct_address();
			remotes_ids.emplace(address.to_raw(), m_keys);
		}

		dnet_time deadline;
		dnet_current_time(&deadline);
		deadline.tsec += m_session.get_timeout();

		std::vector<async_read_result> results;
		results.reserve(remotes_ids.size());

		for (auto &pair : remotes_ids) {
			const auto &address = pair.first;
			auto &ids = pair.second;

			const dnet_bulk_read_request request{
				std::move(ids),
				m_session.get_ioflags(),
				read_flags,
				deadline
			};
			const auto packet = serialize(request);

			transport_control control;
			control.set_command(DNET_CMD_BULK_READ_NEW);
			control.set_cflags(m_session.get_cflags() | DNET_FLAGS_NEED_ACK | DNET_FLAGS_NOLOCK);
			control.set_data(packet.data(), packet.size());

			auto session = m_session.clean_clone();
			if (!has_direct_address)
				session.set_direct_id(address);

			results.emplace_back(session);
			auto handler = std::make_shared<single_bulk_read_handler>(results.back(), session, address);
			handler->start(control, request);
		}

		auto rr = aggregated(m_session, results);
		m_handler.set_total(rr.total());

		rr.connect(
			std::bind(&bulk_read_handler::process, shared_from_this(), std::placeholders::_1),
			std::bind(&bulk_read_handler::complete, shared_from_this(), std::placeholders::_1)
		);
	}

private:
	void process(const read_result_entry &entry) {
		m_handler.process(entry);

		const auto *cmd = entry.command();
		m_transes.emplace(cmd->trans);
		auto it = m_statuses.emplace(entry.status(), 1);
		if (!it.second)
			++it.first->second;
	}

	void complete(const error_info &error) {
		m_handler.complete(error);

		if (m_context) {
			m_context->add({{"transes", [&] {
				        	std::ostringstream result;
				        	result << m_transes;
				        	return std::move(result.str());
			                }()},
			                {"statuses", [&] {
				        	std::ostringstream result;
				        	result << m_statuses;
				        	return std::move(result.str());
			                }()},
			               });
			m_context.reset(); // destroy context to print access log
		}
	}

private:
	session m_session;
	async_result_handler<read_result_entry> m_handler;
	std::unique_ptr<dnet_logger> m_log;
	const std::vector<dnet_id> m_keys;
	std::unordered_set<uint64_t> m_transes;
	std::unordered_map<int, size_t> m_statuses;
	std::unique_ptr<dnet_access_context> m_context;
};

async_read_result send_bulk_read(session &session, const std::vector<dnet_id> &keys, uint64_t read_flags) {
	trace_scope scope{session};

	async_read_result result(session);
	auto handler = std::make_shared<bulk_read_handler>(result, session, keys);
	handler->start(read_flags);
	return result;
}

async_read_result session::bulk_read_json(const std::vector<dnet_id> &keys) {
	return send_bulk_read(*this, keys, DNET_READ_FLAGS_JSON);
}

async_read_result session::bulk_read_data(const std::vector<dnet_id> &keys) {
	return send_bulk_read(*this, keys, DNET_READ_FLAGS_DATA);
}

async_read_result session::bulk_read(const std::vector<dnet_id> &keys) {
	return send_bulk_read(*this, keys, DNET_READ_FLAGS_JSON | DNET_READ_FLAGS_DATA);
}

}}} // ioremap::elliptics::newapi
