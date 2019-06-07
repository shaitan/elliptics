#include "repliers.hpp"

#include <blackhole/attribute.hpp>
#include <msgpack.hpp>

#include "deserialize.hpp"
#include "library/common.hpp"
#include "library/elliptics.h"

namespace ioremap { namespace elliptics { namespace n2 {

replier_base::replier_base(const char *handler_name, dnet_net_state *st, const dnet_cmd &cmd)
: st_(st)
, handler_name_(handler_name)
, reply_has_sent_(ATOMIC_FLAG_INIT)
, cmd_(cmd)
{}

int replier_base::reply(std::unique_ptr<n2_message> msg) {
	auto impl = [&] {
		msg->cmd.trans = cmd_.trans;
		return reply_impl(std::move(msg));
	};

	if (!reply_has_sent_.test_and_set()) {
		return c_exception_guard(impl, st_->n, __FUNCTION__);
	} else {
		return -EALREADY;
	}
}

int replier_base::reply_error(int errc) {
	if (!reply_has_sent_.test_and_set()) {
		return c_exception_guard(std::bind(&replier_base::reply_error_impl, this, errc),
		                         st_->n, __FUNCTION__);
	} else {
		return -EALREADY;
	}
}

int replier_base::reply_impl(std::unique_ptr<n2_message> /*msg*/) {
	return -EINVAL;
}

int replier_base::reply_error_impl(int errc) {
	if (!(cmd_.flags & DNET_FLAGS_NEED_ACK))
		return 0;

	dnet_cmd cmd = cmd_;
	cmd.size = 0;
	cmd.status = errc;

	std::unique_ptr<n2_serialized> serialized;
	int err = serialize_error_response(st_, cmd, serialized);
	if (err)
		return err;

	return enqueue_net(st_, std::move(serialized));
}

lookup_replier::lookup_replier(dnet_net_state *st, const dnet_cmd &cmd)
: replier_base("LOOKUP", st, cmd)
{}

int lookup_replier::reply_impl(std::unique_ptr<n2_message> msg) {
	std::unique_ptr<n2_serialized> serialized;
	int err = serialize_lookup_response(st_, std::move(msg), serialized);
	if (err)
		return err;

	return enqueue_net(st_, std::move(serialized));
}

lookup_new_replier::lookup_new_replier(dnet_net_state *st, const dnet_cmd &cmd)
: replier_base("LOOKUP_NEW", st, cmd)
{}

int lookup_new_replier::reply_impl(std::unique_ptr<n2_message> msg) {
	std::unique_ptr<n2_serialized> serialized;
	int err = serialize_lookup_new_response(st_, std::move(msg), serialized);
	if (err)
		return err;

	return enqueue_net(st_, std::move(serialized));
}

}}} // namespace ioremap::elliptics::n2
