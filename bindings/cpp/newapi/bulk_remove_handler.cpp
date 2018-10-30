#include "bulk_remove_handler.h"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include <blackhole/attribute.hpp>

#include "bindings/cpp/callback_p.h"
#include "bindings/cpp/node_p.hpp"

#include "library/access_context.h"
#include "library/elliptics.h"
#include "library/common.hpp"

#include "bindings/cpp/functional_p.h"


namespace ioremap { namespace elliptics { namespace newapi {

using err_callback = std::function<void(const dnet_id &key, const int &err)>;
using keys_ts = std::vector<std::pair<dnet_id, dnet_time>>;

std::map<dnet_addr, keys_ts> split_keys_to_nodes(session &session, const keys_ts &keys,
                                                 err_callback callback);

void single_bulk_remove_handler::start(const transport_control &control, const dnet_bulk_remove_request &request) {
	DNET_LOG_NOTICE(log_, "{}: started: address: {}, num_keys: {}, request ioflags: {}",
	                dnet_cmd_string(control.get_native().cmd), dnet_addr_string(&address_),
	                request.keys.size(), dnet_flags_dump_ioflags(request.ioflags));

	keys_.assign(request.keys.begin(), request.keys.end());
	std::sort(keys_.begin(), keys_.end());
	key_responses_.resize(keys_.size(), false);

	auto rr = async_result_cast<remove_result_entry>(session_, send_to_single_state(session_, control));
	handler_.set_total(rr.total());

	rr.connect(
		std::bind(&single_bulk_remove_handler::process, shared_from_this(), std::placeholders::_1),
		std::bind(&single_bulk_remove_handler::complete, shared_from_this(), std::placeholders::_1)
	);
}

void single_bulk_remove_handler::process(const remove_result_entry &entry) {
	dnet_cmd *cmd  = entry.command();
	if (!entry.is_valid()) {
		DNET_LOG_ERROR(log_, "{}: {}: process: invalid response, status: {}",
		               dnet_dump_id(&cmd->id), dnet_cmd_string(cmd->cmd), cmd->status);
		return;
	}

	// mark responded key
	bool found = false;
	for (auto it = std::lower_bound(keys_.begin(), keys_.end(), cmd->id); it != keys_.end(); ++it) {
		if (dnet_id_cmp(&cmd->id, &*it) != 0)
			break;

		const auto index = std::distance(keys_.begin(), it);
		if (key_responses_[index])
			continue;

		handler_.process(entry);
		key_responses_[index] = true;
		found = true;
		break;
	}

	if (!found) {
		DNET_LOG_ERROR(log_, "{}: {}: process: unknown key, status: {}",
		               dnet_dump_id(&cmd->id), dnet_cmd_string(cmd->cmd), cmd->status);
	}
	last_error_ = cmd->status;
}

void single_bulk_remove_handler::complete(const error_info &error) {
	// process all non-responded keys:
	dnet_cmd cmd;
	memset(&cmd, 0, sizeof(cmd));
	cmd.status = error ? error.code() : last_error_;
	cmd.cmd = DNET_CMD_BULK_REMOVE_NEW;
	cmd.trace_id = session_.get_trace_id();
	cmd.flags = DNET_FLAGS_REPLY | DNET_FLAGS_MORE |
		    (session_.get_trace_bit() ? DNET_FLAGS_TRACE_BIT : 0);

	for (size_t i = 0; i < keys_.size(); ++i) {
		if (key_responses_[i])
			continue;
		DNET_LOG_ERROR(log_, "{}: did not get responce for key: {}",
		               dnet_cmd_string(DNET_CMD_BULK_REMOVE_NEW), dnet_dump_id(&keys_[i]));
		cmd.id = keys_[i];
		auto result_data = std::make_shared<ioremap::elliptics::callback_result_data>(&address_, &cmd);
		result_data->error = error ? error :
			create_error(last_error_, "send_bulk_remove: remove failed for key: %s",
		                     dnet_dump_id(&keys_[i]));
		ioremap::elliptics::callback_result_entry entry(result_data);
		handler_.process(callback_cast<remove_result_entry>(entry));
	}

	// finish
	handler_.complete(error);
	DNET_LOG_NOTICE(log_, "{}: finished: address: {}",
	                dnet_cmd_string(DNET_CMD_BULK_REMOVE_NEW), dnet_addr_string(&address_));
}

void bulk_remove_handler::start() {
	DNET_LOG_INFO(log_, "{}: started: keys: {}",
	              dnet_cmd_string(DNET_CMD_BULK_REMOVE_NEW), keys_.size());

	context_.reset(new dnet_access_context(session_.get_native_node()));
	if (context_) {
		context_->add({{"cmd", std::string(dnet_cmd_string(DNET_CMD_BULK_REMOVE_NEW))},
		                {"access", "client"},
		                {"ioflags", std::string(dnet_flags_dump_ioflags(session_.get_ioflags()))},
		                {"cflags", std::string(dnet_flags_dump_cflags(session_.get_cflags()))},
		                {"keys", keys_.size()},
		                {"trace_id", to_hex_string(session_.get_trace_id())},
		               });
	}
	if (keys_.empty()) {
		handler_.complete(create_error(-ENXIO, "send_bulk_remove: keys list is empty"));
		return;
	}

	// group keys
	std::map<dnet_addr, keys_ts> remote_ids; // node_address -> [list of keys]
	const bool has_direct_address = !!(session_.get_cflags() & (DNET_FLAGS_DIRECT | DNET_FLAGS_DIRECT_BACKEND));

	if (!has_direct_address) {
		// prepare handler for error of getting address
		auto error_handler = [&](const dnet_id &key, const int &err) {
			dnet_addr address;
			memset(&address, 0, sizeof(address));
			dnet_cmd cmd;
			memset(&cmd, 0, sizeof(cmd));
			cmd.cmd = DNET_CMD_BULK_REMOVE_NEW;
			cmd.trace_id = session_.get_trace_id();
			cmd.flags = DNET_FLAGS_REPLY | DNET_FLAGS_MORE;
			if (session_.get_trace_bit())
				cmd.flags |= DNET_FLAGS_TRACE_BIT;

			cmd.id = key;
			cmd.status = err;
			auto result_data = std::make_shared<callback_result_data>(&address, &cmd);
			result_data->error = create_error(err,
			                                  "bulk_remove_handler: could not locate address & "
			                                  "backend for requested key: %s",
			                                  dnet_dump_id(&key));
			ioremap::elliptics::callback_result_entry entry(result_data);
			process(callback_cast<remove_result_entry>(entry));
		};

		remote_ids = split_keys_to_nodes(session_, keys_, error_handler);
	} else {
		const auto address = session_.get_direct_address();
		remote_ids.emplace(address.to_raw(), keys_);
	}
	
	std::vector<async_remove_result> results;
	results.reserve(remote_ids.size());

	for (const auto &pair : remote_ids) {
		const dnet_addr &address = pair.first;
		const dnet_bulk_remove_request request(pair.second);
		const auto packet = serialize(request);

		transport_control control;
		control.set_command(DNET_CMD_BULK_REMOVE_NEW);
		control.set_cflags(session_.get_cflags() | DNET_FLAGS_NEED_ACK);
		control.set_data(packet.data(), packet.size());

		auto session = session_.clean_clone();
		if (!has_direct_address)
			session.set_direct_id(address);

		results.emplace_back(session); 
		auto handler = std::make_shared<single_bulk_remove_handler>(results.back(), session, address);
		handler->start(control, request);
	}

	auto rr = aggregated(session_, results);
	handler_.set_total(rr.total());

	rr.connect(
		std::bind(&bulk_remove_handler::process, shared_from_this(), std::placeholders::_1),
		std::bind(&bulk_remove_handler::complete, shared_from_this(), std::placeholders::_1)
	);
}

void bulk_remove_handler::process(const remove_result_entry &entry) {
	handler_.process(entry);

	const auto *cmd = entry.command();
	transes_.emplace(cmd->trans);
	++statuses_[entry.status()];
}

void bulk_remove_handler::complete(const error_info &error) {
	handler_.complete(error);

	if (context_) {
		context_->add({{"transes", [&] {
					std::ostringstream result;
					result << transes_;
					return std::move(result.str());
				}()},
				{"statuses", [&] {
					std::ostringstream result;
					result << statuses_;
					return std::move(result.str());
				}()},
			       });
		context_.reset(); // destroy context to print access log
	}
}

std::map<dnet_addr, keys_ts> split_keys_to_nodes(session &session, const keys_ts &keys,
                                                 err_callback callback) {
	std::map<dnet_addr, std::vector<std::pair<dnet_id, dnet_time>>>  remote_ids;
	dnet_addr address;
	memset(&address, 0, sizeof(address));

	for (const auto &id : keys) {
		const int err = dnet_lookup_addr(session.get_native(), nullptr, 0, &id.first, id.first.group_id,
		                                 &address, nullptr);

		if (!err) {
			remote_ids[address].emplace_back(id);
		} else {
			callback(id.first, err);
		}
	}
	return remote_ids;
}

} } } // namespace ioremap::elliptics::newapi
