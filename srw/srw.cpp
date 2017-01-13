/*
 * 2011+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
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

#ifdef HAVE_COCAINE_SUPPORT

#include <map>
#include <sstream>
#include <functional>

#include <elliptics/interface.h>
#include <elliptics/utils.hpp>

#include "elliptics.h"

#include <cocaine/context.hpp>
#include <cocaine/context/quote.hpp>
#include <cocaine/hpack/header.hpp>
#include <cocaine/api/stream.hpp>
#include <cocaine/logging.hpp>
#include <cocaine/repository.hpp>
#include <cocaine/repository/service.hpp>
#include <cocaine/rpc/actor.hpp>
#include <cocaine/service/node.hpp>
#include <cocaine/service/node/overseer.hpp>
#include <cocaine/trace/trace.hpp>

#include <blackhole/scope/holder.hpp>

#include "localnode.hpp"
#include "cocaine/traits/localnode.hpp"
#include "cocaine/api/elliptics_node.hpp"

#include "library/logger.hpp"
#include "bindings/cpp/exec_context_data_p.hpp"
#include "elliptics/srw.h"

using blackhole::attribute_list;

#define SRW_LOG(__log__, __level__, __app__, ...)                     \
	COCAINE_LOG(__log__, __level__, __VA_ARGS__, attribute_list{{ \
		{"source", "srw"},                                    \
		{"app", __app__}                                      \
	}});

namespace ioremap { namespace elliptics {
/*
 * Logger interface implementation.
 */
class logger_adapter : public blackhole::wrapper_t {
public:
	logger_adapter(dnet_logger *log)
	: blackhole::wrapper_t(*log, {{"source", "srw/cocaine"}}) {}

	virtual void log(blackhole::severity_t severity, const blackhole::message_t &message) {
		blackhole::wrapper_t::log(convert_severity(severity), message);
	}

	virtual void
	log(blackhole::severity_t severity, const blackhole::message_t &message, blackhole::attribute_pack &pack) {
		//FIXME: is it possible to detect if trace_id is already set?
		//XXX: what about tracebit? where to get it?
		blackhole::wrapper_t::log(convert_severity(severity), message, pack);
	}

	virtual void
	log(blackhole::severity_t severity, const blackhole::lazy_message_t &message, blackhole::attribute_pack &pack) {
		blackhole::wrapper_t::log(convert_severity(severity), message, pack);
	}

private:
	static dnet_log_level convert_severity(blackhole::severity_t severity) {
		switch (severity) {
		case cocaine::logging::debug:
			return DNET_LOG_DEBUG;
		case cocaine::logging::info:
			return DNET_LOG_INFO;
		case cocaine::logging::warning:
			return DNET_LOG_WARNING;
		case cocaine::logging::error:
		default:
			return DNET_LOG_ERROR;
		}
	}
};


/*
 * `client_session` represents open communication with the srw's client
 *  over elliptics channel.
 */
struct client_session
{
	client_session(dnet_net_state *state, dnet_cmd *cmd, const std::string &app, const std::string &signature,
	               const exec_context &exec_copy)
	: m_state(state)
	, m_cmd_copy(*cmd)
	, m_exec_copy(exec_copy)
	, m_app(app)
	, m_signature(signature) {
		dnet_state_get(m_state);
		SRW_LOG(dnet_node_get_logger(m_state->n), DNET_LOG_DEBUG, m_app, "{}: client session open", m_signature);

		// set DNET_SPH_FLAGS_REPLY flag, drop all others
		m_exec_copy.set_flags(DNET_SPH_FLAGS_REPLY);
	}

	~client_session() {
		SRW_LOG(dnet_node_get_logger(m_state->n), DNET_LOG_DEBUG, m_app, "{}: client session close", m_signature);
		dnet_state_put(m_state);
	}

	void send_chunk(const argument_data &data) {
		/*
		 * chunks of size 0 are just redundant, its safe to ignore them;
		 * also as ack is a reply with zero payload too, its better not
		 * to create a mess
		 */
		if (data.size() == 0) {
			return;
		}

		SRW_LOG(dnet_node_get_logger(m_state->n), DNET_LOG_DEBUG, m_app, "{}: client session sends data",
		        m_signature);

		/*
		 * FIXME: `data` payload gets copied here 2 times more than necessary:
		 *  1. in exec_context_data::copy, to prefix it with sph
		 *  2. in dnet_send, to prefix [sph,data] with dnet_cmd
		 * Those could be eliminated, for this case specifically.
		 * (Third copy of entire [cmd,sph,data] is performed in dnet_io_req_queue,
		 * and thats too deep, -- fixing that would mean changing a lot of elliptics
		 * entrails.)
		 */
		auto reply = exec_context_data::copy(m_exec_copy, m_exec_copy.event(), data);
		auto srw_packet = reply.native_data();
		dnet_send_reply(m_state, const_cast<dnet_cmd*>(&m_cmd_copy), srw_packet.data(), srw_packet.size(), 1);
	}

	void finish(int error_code = 0) {
		/*
		 * exec commands have NEED_ACK flag set unconditionally
		 * (same as all other nonsystem commands).
		 * If m_cmd_copy will have it unset then it will mean that client logic
		 * was changed incompatibly with server logic.
		 */

		SRW_LOG(dnet_node_get_logger(m_state->n), DNET_LOG_DEBUG, m_app, "{}: client session sends ack",
		        m_signature);
		dnet_send_ack(m_state, const_cast<dnet_cmd*>(&m_cmd_copy), error_code, 0);
	}

	dnet_net_state *m_state;
	const dnet_cmd m_cmd_copy;
	exec_context m_exec_copy;
	const std::string m_app;
	const std::string m_signature;
};


/*
 * `exec_back_stream` is a stream receiving responses from an app
 * (in cocaine terms response stream called upstream).
 *
 * It transfers replies back to the original elliptics client which
 * started EXEC transaction, it keeps client session used for that transfer
 * and it notifies srw when stream job is done.
 *
 * Method write() accepts strings chunks from worker.
 * It allows to write interactive worker application in a straightforward way:
 *  - read SPH + data from request stream
 *  - do some useful job
 *  - send reply via response stream
 * Chunked replies are allowed by elliptics protocol.
 */
class exec_back_stream : public cocaine::api::stream_t {
public:
	exec_back_stream(dnet_logger *logger, const std::shared_ptr<client_session> &client,
	                 std::function<void()> notify_completion)
	: m_logger(logger)
	, m_client(client)
	, m_tracebit(!!(client->m_cmd_copy.flags & DNET_FLAGS_TRACE_BIT))
	, m_app(client->m_app)
	, m_signature(client->m_signature)
	, m_notify_completion(notify_completion)
	{}

	// stream_t interface

	virtual ~exec_back_stream() = default;

	/*
	 * write() is called when worker sends chunk to the response stream.
	 * write() performs transfer of data back to elliptics client.
	 */
	virtual stream_t &write(cocaine::hpack::header_storage_t, const std::string &chunk) {
		// elliptics trace id is shown in logs, setting it from cocaine trace_id
		trace_scope scope{cocaine::trace_t::current().get_trace_id(), m_tracebit};

		if (chunk.empty()) {
			SRW_LOG(m_logger, DNET_LOG_DEBUG, m_app,
			        "{}: stream: got chunk from app, size 0 -- 'drop me' signal", m_signature);
			/*
			 * empty chunk is a signal of chaining: the worker will not provide
			 * the final result of event processing immediately but will instead
			 * pass processing further down the chain -- result will be provided
			 * eventually by a different channel and not through this stream
			 */
			m_client.reset();

		} else {
			SRW_LOG(m_logger, DNET_LOG_DEBUG, m_app, "{}: stream: got chunk from app, size {}", m_signature,
			        chunk.size());
			if (auto client = m_client.lock()) {
				client->send_chunk(chunk);

			} else {
				SRW_LOG(m_logger, DNET_LOG_ERROR, m_app, "{}: stream: client session already closed",
				        m_signature);
			}
		}

		return *this;
	}

	virtual void error(cocaine::hpack::header_storage_t, const std::error_code &code, const std::string &reason) {
		// elliptics trace id is shown in logs, setting it from cocaine trace_id
		trace_scope scope{cocaine::trace_t::current().get_trace_id(), m_tracebit};
		SRW_LOG(m_logger, DNET_LOG_ERROR, m_app, "{}: stream: got error from app: {}: {}", m_signature,
		        code.message(), reason);
		if (auto client = m_client.lock()) {
			//TODO: translate cocaine errors into elliptics error code space (errno),
			// for some errors, e.g. for "unknown/unhandled event" error
			client->finish(code.value());

			/* notify that we are done and this cocaine session closed
			 * TODO: move to client_session
			 */
			m_notify_completion();

			/* stream object could be held live long after its close() or error() was called,
			 * so explicitly dropping hold on client session helps
			 */
			m_client.reset();

		} else {
			SRW_LOG(m_logger, DNET_LOG_DEBUG, m_app, "{}: stream: client session already closed",
			        m_signature);
		}
	}

	virtual void close(cocaine::hpack::header_storage_t) {
		// elliptics trace id is shown in logs, setting it from cocaine trace_id
		trace_scope scope{cocaine::trace_t::current().get_trace_id(), m_tracebit};
		SRW_LOG(m_logger, DNET_LOG_DEBUG, m_app, "{}: stream: got close", m_signature);
		if (auto client = m_client.lock()) {
			client->finish();

			/* notify that we are done and this cocaine session closed
			 *TODO: move to client_session?
			 */
			m_notify_completion();

			/* stream object could be held live long after its close() or error() was called,
			 * so explicitly dropping hold on client session helps
			 */
			m_client.reset();

		} else {
			SRW_LOG(m_logger, DNET_LOG_DEBUG, m_app, "{}: stream: client session already closed",
			        m_signature);
		}
	}

private:
	dnet_logger *m_logger;
	std::weak_ptr<client_session> m_client;
	bool m_tracebit;
	const std::string m_app;
	const std::string m_signature;
	std::function<void()> m_notify_completion;
};


/*
 * `push_back_stream` is a stub for the reply stream (upstream in cocaine terms).
 *
 * In some cases srw expects the other end (the app) to send no reply,
 * so getting anything back indicate error in app behaviour.
 */
class push_back_stream : public cocaine::api::stream_t {
public:
	push_back_stream(dnet_logger *logger, const std::shared_ptr<client_session> &client)
	: m_logger(logger)
	, m_client(client)
	, m_tracebit(!!(client->m_cmd_copy.flags & DNET_FLAGS_TRACE_BIT))
	, m_app(client->m_app)
	, m_signature(client->m_signature)
	{}

	// stream_t interface

	virtual ~push_back_stream() {
		// elliptics trace id is shown in logs, setting it from cocaine trace_id
		trace_scope scope{cocaine::trace_t::current().get_trace_id(), m_tracebit};
		SRW_LOG(m_logger, DNET_LOG_DEBUG, m_app, "{}: stream: close", m_signature);
	}

	virtual stream_t& write(cocaine::hpack::header_storage_t, const std::string& chunk) {
		// elliptics trace id is shown in logs, setting it from cocaine trace_id
		trace_scope scope{cocaine::trace_t::current().get_trace_id(), m_tracebit};

		if (chunk.empty()) {
			SRW_LOG(m_logger, DNET_LOG_DEBUG, m_app,
			        "{}: stream: got chunk from app, size 0 -- 'drop me' signal", m_signature);
			m_client->finish();

			/* stream object could be held live long after its close() or error() was called,
			 * so explicitly dropping hold on client session helps
			 */
			m_client.reset();

		} else {
			SRW_LOG(m_logger, DNET_LOG_ERROR, m_app,
			        "{}: stream: got chunk from app in no-reply-expected mode", m_signature);
		}

		return *this;
	}

	virtual void error(cocaine::hpack::header_storage_t, const std::error_code& code, const std::string& reason) {
		// elliptics trace id is shown in logs, setting it from cocaine trace_id
		trace_scope scope{cocaine::trace_t::current().get_trace_id(), m_tracebit};
		SRW_LOG(m_logger, DNET_LOG_ERROR, m_app,
		        "{}: stream: got error from app in no-reply-expected mode: {}: {}", m_signature, code.message(),
		        reason);
		if (m_client) {
			m_client->finish(code.value());

			// stream object could be held live long after its close() or error() was called,
			// so explicitly dropping hold on client session helps
			m_client.reset();
		}
	}

	virtual void close(cocaine::hpack::header_storage_t) {
		// elliptics trace id is shown in logs, setting it from cocaine trace_id
		trace_scope scope{cocaine::trace_t::current().get_trace_id(), m_tracebit};
		SRW_LOG(m_logger, DNET_LOG_DEBUG, m_app, "{}: stream: got close", m_signature);
		if (m_client) {
			m_client->finish();

			/* stream object could be held live long after its close() or error() was called,
			 * so explicitly dropping hold on client session helps
			 */
			m_client.reset();
		}
	}

private:
	dnet_logger *m_logger;
	std::shared_ptr<client_session> m_client;
	bool m_tracebit;
	const std::string m_app;
	const std::string m_signature;
};


/*
 * Utility methods for use by srw class.
 */
std::shared_ptr<const cocaine::service::node_t> lookup_node_service(const cocaine::context_t &ctx) {
	//XXX: can we detect node service name automatically?
	if (const auto actor = ctx.locate("node")) {
		const auto &dispatch = actor.get().prototype;
		return std::dynamic_pointer_cast<const cocaine::service::node_t>(dispatch);
	}

	return nullptr;
}

std::string make_log_signature(struct dnet_net_state *st, struct dnet_cmd *cmd, const exec_context &exec) {
	//XXX: use more vivid formatting (cppformat?)
	std::ostringstream buf;

	buf << dnet_state_dump_addr(st) << ": trans: " << cmd->trans << ": " << dnet_dump_id(&cmd->id) << ", ";

	/* In `exec` commands src_id (or origin id) is equal to dnet_cmd::id.
	 * Same for simple cases of `reply` commands.
	 * Origin id could differ from dnet_cmd::id in `push` commands and in those
	 * `reply` commands that come from the end of `exec`/`push` chains.
	 *
	 * add origin id to signature only if it differs -- no need to clutter the log
	 */
	if (dnet_id_cmp_str(cmd->id.id, exec.src_id()->id) != 0) {
		// here and manually -- because family of dnet_id formatting functions
		// lack a variant that can accept dnet_raw_id (instead of dnet_id)
		char origin_id_str[DNET_DUMP_NUM * 2 + 1];
		dnet_dump_id_len_raw(exec.src_id()->id, DNET_DUMP_NUM, origin_id_str);
		buf << "(for origin id " << origin_id_str << "), ";
	}

	// exec_context's event have format {app}@{event}
	buf << exec.event();

	return buf.str();
}

std::tuple<std::string, std::string> parse_srw_event(const std::string &s) {
	auto found = s.find("@");
	if (found != std::string::npos) {
		return std::make_tuple(s.substr(0, found), s.substr(found + 1));
	}
	return std::make_tuple(s, std::string());
};


/*
 * Main class which implements `exec` command processing and glues elliptics with cocaine.
 */
struct srw {
	struct exec_session
	{
		std::shared_ptr<client_session> m_client_session;
		std::shared_ptr<cocaine::api::stream_t> m_back_stream;
	};

	srw(struct dnet_node *n, const std::string &config);

	void register_job(int job_id, const std::shared_ptr<exec_session> &exec_session);
	bool unregister_job(const std::string &signature, int job_id);
	bool unregister_job_nolock(const std::string &signature, int job_id);
	// std::shared_ptr<exec_session> pop_job(const std::string &signature, int job_id);

	int process(struct dnet_net_state *st, struct dnet_cmd *cmd, const void *data);

	// logger
	std::unique_ptr<dnet_logger> m_log;

	// main cocaine core object -- context
	std::unique_ptr<cocaine::context_t> m_ctx;

	// exec session map
	typedef std::map<uint64_t, std::shared_ptr<exec_session>> jobs_map_t;
	jobs_map_t m_jobs;
	atomic_t m_job_id_counter;

	// lock to serialize access to exec session map
	std::mutex m_lock;
};

srw::srw(struct dnet_node *n, const std::string &config)
	: m_log(new blackhole::wrapper_t(*n->log, {{"source", "srw"}}))
	// NOTE: context_t ctor throws an exception on config parse error
	, m_ctx()
{
	atomic_set(&m_job_id_counter, 0);

	using namespace cocaine::api;
	typedef elliptics_node_t::factory_t factory_t;

	/*
	 * Create repository manually to insert elliptics specific components
	 * (elliptics node provider and localnode service) before context initialization
	 */
	std::unique_ptr<cocaine::api::repository_t> repository(
	        new cocaine::api::repository_t(std::make_unique<logger_adapter>(get_base_logger(n->log))));

	repository->insert<elliptics_node_t>("elliptics_node", std::unique_ptr<factory_t>(new factory_t(n)));
	repository->insert<localnode>("localnode");

	m_ctx = cocaine::make_context(cocaine::make_config(config),
	                              std::make_unique<logger_adapter>(get_base_logger(n->log)),
	                              std::move(repository));
}

void srw::register_job(int job_id, const std::shared_ptr<exec_session> &exec_session)
{
	std::lock_guard<std::mutex> guard(m_lock);
	m_jobs.insert(std::make_pair(job_id, exec_session));
}

bool srw::unregister_job(const std::string &signature, int job_id)
{
	std::lock_guard<std::mutex> guard(m_lock);
	return unregister_job_nolock(signature, job_id);
}

bool srw::unregister_job_nolock(const std::string &signature, int job_id)
{
	DNET_LOG_DEBUG(m_log, "{}: srw: request to remove job {}", signature, job_id);
	jobs_map_t::iterator found = m_jobs.find(job_id);
	if (found != m_jobs.end()) {
		m_jobs.erase(found);
		DNET_LOG_DEBUG(m_log, "{}: srw: job {} found and removed", signature, job_id);
		return true;
	} else {
		//FIXME: fix log message text
		DNET_LOG_ERROR(m_log, "{}: srw: B, no job {} to complete", signature, job_id);
		return false;
	}
}

// std::shared_ptr<exec_session> srw::pop_job(const std::string &signature, int job_id)
// {
// 	{
// 		std::lock_guard<std::mutex> guard(m_lock);
// 		jobs_map_t::iterator found = m_jobs.find(job_id);
// 		if (found != m_jobs.end()) {
// 			std::shared_ptr<exec_stream> value = found->second;
// 			m_jobs.erase(found);
// 			return value;
// 		}
// 	}
// 	//FIXME: fix log message text
// 	DNET_LOG_ERROR(m_log, "{}: no job: {} to complete", signature, job_id);
// 	return std::shared_ptr<exec_session>();
// }

int srw::process(struct dnet_net_state *st, struct dnet_cmd *cmd, const void *data)
{
	exec_context exec;
	try {
		exec = exec_context::from_raw(data, cmd->size);

	} catch(const error &e) {
		//TODO: add logging attribute 'source: srw'
		DNET_LOG_ERROR(m_log, "{}: srw: invalid exec_context: {}", dnet_dump_id(&cmd->id), e.what());
		return e.error_code();
	}

	// srw event should look like "application@method"
	const std::string srw_event = exec.event();
	std::string app;
	std::string event;
	{
		std::tie(app, event) = parse_srw_event(srw_event);
		if (app.empty() || event.empty()) {
			//TODO: add logging attribute 'source: srw'
			DNET_LOG_ERROR(m_log, "{}: srw: invalid event (should be {{app}}@{{event}}): {}",
			               dnet_dump_id(&cmd->id), srw_event);
			return -EINVAL;
		}
	}

	const std::string signature = make_log_signature(st, cmd, exec);

	DNET_LOG_DEBUG(m_log, "{}: srw: start processing, payload size: {}", signature, exec.data().size());

	/**if ((event == "start-task") || (event == "start-multiple-task")) {
		std::unique_lock<std::mutex> guard(m_lock);
		eng_map_t::iterator it = m_map.find(app);
		if (it == m_map.end()) {
			auto eng = std::make_shared<dnet_app_t>(m_ctx, app, app);
			eng->start();

			if (event == "start-multiple-task") {
				auto storage = cocaine::api::storage(m_ctx, "core");
				Json::Value profile = storage->get<Json::Value>("profiles", app);

				int idle = profile["idle-timeout"].asInt();
				int pool_limit = profile["pool-limit"].asInt();
				const int idle_min = 60 * 60 * 24 * 30;

				DNET_LOG_INFO(m_log, "{}: multiple start: idle: {}/{}, workers: {}", signature, idle, idle_min, pool_limit);

				if (idle && idle < idle_min) {
					DNET_LOG_ERROR(m_log, "{}: multiple start: "
						"idle must be big enough, we check it to be larger than 30 days ({} seconds), "
						"current profile value is {}",
						signature, idle_min, idle);
					return -EINVAL;
				}

				eng->set_pool_size(pool_limit);

				if (sph->data_size) {
					std::string task_id(data + sph->event_size, sph->data_size);

					eng->set_task_id(task_id);
				}
			}

			m_map.insert(std::make_pair(app, eng));

			DNET_LOG_INFO(m_log, "{}: started", signature);

		} else {
			DNET_LOG_INFO(m_log, "{}: was already started", signature);
		}

	} else if (event == "stop-task") {
		std::unique_lock<std::mutex> guard(m_lock);
		eng_map_t::iterator it = m_map.find(app);
		// destructor stops engine
		if (it != m_map.end())
			m_map.erase(it);
		guard.unlock();

		DNET_LOG_INFO(m_log, "{}: stopped", signature);

	}
	*/

	// Handle control-over-elliptics-channel commands.

	if (event == "start-task"
			|| event == "start-multiple-task"
			|| event == "stop-task"
			|| event == "info") {

		DNET_LOG_INFO(m_log, "{}: srw: app control", signature);

		//XXX: how we can differentiate services from apps?

		//XXX: can we detect node service name automatically?
		if (auto node = lookup_node_service(*m_ctx)) {
			try {
				if (event == "info") {
					auto doc = node->info(app,
						cocaine::io::node::info::flags_t(
							cocaine::io::node::info::overseer_report
							| cocaine::io::node::info::expand_manifest
							| cocaine::io::node::info::expand_profile
						)
					);
					auto text = boost::lexical_cast<std::string>(doc);

					client_session client(st, cmd, app, signature, exec);
					client.send_chunk(text);
					client.finish();

					/* we've just sent ack with client.finish(),
					 * clearing NEED_ACK flag will turn off ack sending
					 * done in dnet_process_cmd_raw
					 */
					cmd->flags &= ~DNET_FLAGS_NEED_ACK;

				} else {
					/* TODO: reimplement support for other commands:
					 * their working over elliptics channel is not required right now,
					 * but still convenient and has value
					 */
					return -ENOTSUP;
				}

			} catch (const std::exception &e) {
				// exception text must be "app '{name}' is not running"
				DNET_LOG_ERROR(m_log, "{}: srw: {}", signature, e.what());
				return -ENOENT;
			}

		} else {
			DNET_LOG_ERROR(m_log, "{}: 'node' ('node::v2') service not found, but its required to be able "
			                      "to run user apps; check cocaine config",
			               signature);
			return -ENOENT;
		}

		return 0;
	}

	// So, here some non-control EXEC command came to us via elliptics channel.

	try {

		if (exec.is_reply()) {
			// This is a reply in a sequence of replies to some previous exec.

			DNET_LOG_INFO(m_log, "{}: srw: reply pass", signature);

			/* This segment could be marked as the final segment in a sequence,
			 * which means exec session should be finalized and closed.
			 */
			const int job_id = exec.src_key();

			std::unique_lock<std::mutex> guard(m_lock);

			jobs_map_t::iterator found = m_jobs.find(job_id);
			if (found == m_jobs.end()) {
				//FIXME: fix log message text
				DNET_LOG_ERROR(m_log, "{}: srw: A, no job {} to complete", signature, job_id);
				return -ENOENT;
			}

			// take our chance to release job map as soon as possible
			std::shared_ptr<exec_session> exec_session = found->second;
			if (exec.is_final()) {
				m_jobs.erase(found);
				// exec_session object should be released and actually destroyed
				// as soon as `exec_session` ptr goes out of scope
			}
			guard.unlock();

			//XXX: move addr fixup here?

			// and only then do the real work with reply
			exec_session->m_client_session->send_chunk(exec.data());
			if (exec.is_final()) {
				exec_session->m_client_session->finish();
			}

			// XXX: why that addr fixup? why it made after reply?
			// memcpy(&sph->addr, &st->n->addrs[0], sizeof(struct dnet_addr));

			/* NOTE: transient client that sent this `reply` is not the same
			 * as the original client that had sent original `exec` --
			 * -- original client was just answered through client_session
			 *
			 * Ack to the transient client will be sent by dnet_process_cmd_raw(),
			 * it does ack auto sending for all io commands --
			 * -- only if NEED_ACK flag is not specifically cleared,
			 * and we are not clearing NEED_ACK flag.
			 */
		} else {
			/* This is an original exec.
			 */
			DNET_LOG_INFO(m_log, "{}: srw: forward pass", signature);

			auto node = lookup_node_service(*m_ctx);
			if (!node) {
				DNET_LOG_ERROR(m_log, "{}: 'node' ('node::v2') service not found, but its required to "
				                      "be able to run user apps; check cocaine config",
				               signature);
				return -ENOENT;
			}

			std::shared_ptr<cocaine::service::node::overseer_t> app_overseer;
			try {
				app_overseer = node->overseer(app);

			} catch (const cocaine::error_t &e) {
				// exception text must be "app '{name}' is not running"
				DNET_LOG_ERROR(m_log, "{}: srw: {}", signature, e.what());
				return -ENOENT;
			}

			/* src_key in exec can be used to map processing to a specific worker,
			 * src_key in reply will be used as job_id to find job in job map.
			 * Original src_key gets saved into exec_session and substituted by the job_id
			 * generated by the srw.
			 */
			const int src_key = exec.src_key();
			const bool reply_expected = !!(exec.flags() & DNET_SPH_FLAGS_SRC_BLOCK);
			int job_id = 0;

			if (reply_expected) {
				job_id = atomic_inc(&m_job_id_counter);
				exec.set_src_key(job_id);
				memcpy(exec.src_id(), cmd->id.id, sizeof(exec.src_id()->id));
			}

			auto clean_copy = [] (const exec_context &other) -> exec_context {
				return exec_context_data::copy(other, other.event(), data_pointer());
			};

			// clean copy drops payload
			auto exec_clean_copy = clean_copy(exec);

			auto session = std::make_shared<client_session>(
				st, cmd, app, signature, exec_clean_copy
			);
			DNET_LOG_DEBUG(m_log,
			               "{}: srw: exec_context original, size: total {}, event {}({}), payload {}",
			               signature, exec.native_data().size(), exec.event().size(),
			               exec.native_data().data<sph>()->event_size, exec.data().size());
			DNET_LOG_DEBUG(
			        m_log, "{}: srw: exec_context session copy, size: total {}, event {}({}), payload {}",
			        signature, exec_clean_copy.native_data().size(), exec_clean_copy.event().size(),
			        exec_clean_copy.native_data().data<sph>()->event_size, exec_clean_copy.data().size());

			/* optional tag to stick processing to a certain worker
			 * FIXME: what about tagging of `push` requests?
			 */
			std::string tag;

			std::shared_ptr<cocaine::api::stream_t> back_stream;
			if (reply_expected) {
				// for `exec`
				DNET_LOG_INFO(m_log, "{}: srw: mode exec (src_key {} replaced with job {})", signature,
				              src_key, job_id);

				back_stream = std::make_shared<exec_back_stream>(m_log.get(), session,
					std::bind(&srw::unregister_job, this, signature, job_id)
				);

				if (src_key >= 0) {
					const int index = (src_key % app_overseer->profile().pool_limit);
					//TODO: think out tag format
					tag = /* {unique app instance id} + */ app + ".worker-" + std::to_string(index);
				}

			} else {
				// for `push`
				DNET_LOG_INFO(m_log, "{}: srw: mode push", signature);

				back_stream = std::make_shared<push_back_stream>(m_log.get(), session);
			}

			try {
				namespace h = cocaine::hpack;

				auto nd = exec_clean_copy.native_data();
				std::string sph_data(nd.data<char>(), nd.size());
				h::header_t sph_header("sph", std::move(sph_data));
				h::header_storage_t headers({std::move(sph_header)});

				//FIXME: get rid of this copy from data_pointer to a std::string
				const std::string chunk = exec.data().to_string();

				DNET_LOG_DEBUG(m_log, "{}: srw: enqueueing, tag '{}', event '{}', chunk size {}",
				               signature, tag, event, chunk.size());

				auto send_stream = app_overseer->enqueue(
					back_stream,
					cocaine::service::node::app::event_t(event, std::move(headers)),
					// TODO: there is some problem with tags in cocaine 12.7,
					// disable them for now
					// cocaine::service::node::slave::id_t(tag)
					boost::none
				);

				send_stream->write({}, chunk);

				// Request stream should be closed after all data was sent to prevent resource
				// leakage.
				send_stream->close({});

				DNET_LOG_INFO(m_log, "{}: srw: enqueued, src_key {}, job {}, payload size {}, block {}",
				              signature, src_key, job_id, exec.data().size(), reply_expected);

			} catch (const std::exception &e) {
				DNET_LOG_ERROR(
				        m_log,
				        "{}: srw: enqueue error, src_key {}, job {}, payload size {}, block {}: {}",
				        signature, src_key, job_id, exec.data().size(), reply_expected, e.what());
				return -EXFULL;
			}

			if (reply_expected) {
				// register exec session in job map
				register_job(job_id, std::make_shared<exec_session>(exec_session{session, back_stream}));
			}

			/* clearing NEED_ACK flag turns off ack auto sending
			 * (dnet_process_cmd_raw() does that) -- client should receive ack
			 * only after it'll get result of exec processing
			 */
			cmd->flags &= ~DNET_FLAGS_NEED_ACK;
		}

		return 0;

	} catch(const std::exception &e) {
		DNET_LOG_ERROR(m_log, "{}: processing failed: {}", signature, e.what());
	}

	return -EINVAL;
}

}} // namespace ioremap::elliptics


int dnet_srw_init(struct dnet_node *n, struct dnet_config *cfg)
{
	try {
		DNET_LOG_INFO(n, "srw: init, config: {}", cfg->srw.config);
		n->srw = new ioremap::elliptics::srw(n, cfg->srw.config);
		DNET_LOG_INFO(n, "srw: init done, config: {}", cfg->srw.config);
		return 0;

	} catch (const cocaine::error_t &e) {
		DNET_LOG_ERROR(n, "srw: init failed, config: {}, config error: {}", cfg->srw.config, e.what());
		return -EINVAL;

	} catch (const std::system_error &e) {
		DNET_LOG_ERROR(n, "srw: init failed, config: {}, exception: {}", cfg->srw.config, e.what());
		return -ENOMEM;
	}
}

void dnet_srw_cleanup(struct dnet_node *n)
{
	if (n->srw) {
		try {
			DNET_LOG_INFO(n, "srw: fini");
			auto *srw = static_cast<ioremap::elliptics::srw*>(n->srw);
			delete srw;
			DNET_LOG_INFO(n, "srw: fini done");

		} catch(const std::exception &e) {
			DNET_LOG_ERROR(n, "srw: fini failed: {}", e.what());

		} catch (...) {
			DNET_LOG_ERROR(n, "srw: fini failed by unknown reason");
		}

		n->srw = NULL;
	}
}

int dnet_cmd_exec(struct dnet_net_state *st, struct dnet_cmd *cmd, const void *payload)
{
	struct dnet_node *n = st->n;
	auto *srw = static_cast<ioremap::elliptics::srw*>(n->srw);

	if (!srw)
		return -ENOTSUP;

	// setup cocaine trace with elliptics trace_id
	// (cocaine trace_id will be randomly generated if elliptics trace_id is zero)
	cocaine::trace_t::current() = cocaine::trace_t(
	        // trace
	        cmd->trace_id, cmd->trace_id, cocaine::trace_t::zero_value,
	        // rpc_name
	        "srw"
	);

	ioremap::elliptics::trace_scope scope{cocaine::trace_t::current().get_trace_id(), !!(cmd->flags & DNET_FLAGS_TRACE_BIT)};

	try {
		return srw->process(st, cmd, payload);

	} catch(const std::exception &e) {
		DNET_LOG_ERROR(n, "srw: processing failed: {}", e.what());
		return -EINVAL;

	} catch (...) {
		DNET_LOG_ERROR(n, "srw: processing failed by unknown reason");
		return -EINVAL;
	}
}

int dnet_srw_update(struct dnet_node *, int)
{
	return 0;
}

#else // HAVE_COCAINE_SUPPORT = 0

// cocaine support disabled

#include <errno.h>

#include "elliptics/srw.h"

int dnet_srw_init(struct dnet_node *, struct dnet_config *)
{
	return -ENOTSUP;
}

void dnet_srw_cleanup(struct dnet_node *)
{
}

int dnet_cmd_exec(struct dnet_net_state *, struct dnet_cmd *, const void *)
{
	return -ENOTSUP;
}

int dnet_srw_update(struct dnet_node *, int)
{
	return 0;
}

#endif // HAVE_COCAINE_SUPPORT
