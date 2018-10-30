#pragma once

#include "elliptics/newapi/session.hpp"
#include "elliptics/async_result_cast.hpp"

#include "library/protocol.hpp"

#include <unordered_map>

namespace ioremap { namespace elliptics { namespace newapi {

class single_bulk_remove_handler : public std::enable_shared_from_this<single_bulk_remove_handler> {
public:
	single_bulk_remove_handler(const async_remove_result &result,
	                           const session &session,
	                           const dnet_addr &address)
	: address_(address)
	, session_(session.clean_clone())
	, handler_(result)
	, log_(session.get_logger())
	{}

	void start(const transport_control &control, const dnet_bulk_remove_request &request);

private:
	void process(const remove_result_entry &entry);
	void complete(const error_info &error);

private:
	std::vector<dnet_id> keys_; // stores original keys from request
	const dnet_addr address_;
	session session_;
	async_result_handler<remove_result_entry> handler_;
	std::unique_ptr<dnet_logger> log_;
	std::vector<bool> key_responses_;
	int last_error_{0};
	std::unique_ptr<dnet_access_context> context_;
};

class bulk_remove_handler : public std::enable_shared_from_this<bulk_remove_handler> {
public:
	bulk_remove_handler(const async_remove_result &result,
	                    const session &session,
	                    const std::vector<std::pair<dnet_id, dnet_time>> &keys)
	: keys_(keys)
	, session_(session.clean_clone())
	, handler_(result)
	, log_(session.get_logger())
	{}

	void start();

private:
	void process(const remove_result_entry &entry);
	void complete(const error_info &error);

private:
	const std::vector<std::pair<dnet_id, dnet_time>> keys_;
	session session_;
	async_result_handler<remove_result_entry> handler_;
	std::unique_ptr<dnet_logger> log_;

	std::unordered_set<uint64_t> transes_;
	std::unordered_map<int, size_t> statuses_;
	std::unique_ptr<dnet_access_context> context_;
};

}}} // namespace ioremap::elliptics::newapi
