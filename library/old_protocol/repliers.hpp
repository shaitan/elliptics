#pragma once

#include <atomic>

#include "library/n2_protocol.hpp"
#include "serialize.hpp"

namespace ioremap { namespace elliptics { namespace n2 {

/*
 * Here are grouped the implementations of n2_repliers that are called from message handler as a result of message
 * processing. For each message type, calls of n2_repliers::on_reply* callbacks are dependent on each other. For
 * example, for simple scalar requests (e.g. lookup by key) only one of callbacks (on_reply or on_reply_error) must to
 * be called, and if any extra (unexpected) call occur, would be better to resolve this situation some way to not to
 * produce the harm. At least, any unexpected on_reply* call mustn't be passed to any underlying systems, and definitely
 * mustn't to be sent by net. For more complex logic of replying, the callbacks dependence is also more complex. To
 * serve this, n2_repliers are implemented via the instance of class that looks after the order of callback calls.
 */

class replier_base {
public:
	replier_base(const char *handler_name, dnet_net_state *st, const dnet_cmd &cmd);
	int reply(std::unique_ptr<n2_message> msg);
	int reply_error(int errc);

protected:
	dnet_net_state *st_;

private:
	virtual int reply_impl(std::unique_ptr<n2_message> msg);
	int reply_error_impl(int errc);

	const char *handler_name_;
	std::atomic_flag reply_has_sent_;

	dnet_cmd cmd_;
};

// Lookup request stuff

class lookup_replier : public replier_base {
public:
	lookup_replier(dnet_net_state *st, const dnet_cmd &cmd);

private:
	int reply_impl(std::unique_ptr<n2_message> msg) override;
};

}}} // namespace ioremap::elliptics::n2
