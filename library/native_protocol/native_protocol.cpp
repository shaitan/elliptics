#include "native_protocol.hpp"

#include <blackhole/attribute.hpp>

#include "deserialize.hpp"
#include "library/common.hpp"
#include "library/elliptics.h"
#include "library/logger.hpp"

namespace ioremap { namespace elliptics { namespace native {

using namespace ioremap::elliptics::n2;

int protocol::send_request(dnet_net_state *st,
                           const n2_request &request,
                           n2_repliers &&repliers) {
	const dnet_cmd &cmd = request.cmd;

	{
		// Note: currently transaction is created outside from protocol. When we'll create it in protocol,
		// we shouldn't search it here

		pthread_mutex_lock(&st->trans_lock);
		std::unique_ptr<pthread_mutex_t, int (*)(pthread_mutex_t *)>
			trans_guard(&st->trans_lock, &pthread_mutex_unlock);
		std::unique_ptr<dnet_trans, void (*)(dnet_trans *)>
			t(dnet_trans_search(st, cmd.trans), &dnet_trans_put);

		if (!t || !t->repliers)
			return -EINVAL;

		*t->repliers = std::move(repliers);
	}

	n2_serialized::chunks_t chunks;

	switch (cmd.cmd) {
	case DNET_CMD_LOOKUP:
	case DNET_CMD_LOOKUP_NEW:
		break;
	case DNET_CMD_DEL_NEW:
		serialize_new<remove_request>(*request.body, chunks);
		break;
	default:
		return -EINVAL;
	}

	std::unique_ptr<n2_serialized> serialized(new n2_serialized{cmd, std::move(chunks)});
	return enqueue_net(st, std::move(serialized));
}

int protocol::recv_message(dnet_net_state *st, const dnet_cmd &cmd, data_pointer &&body) {
	if (cmd.flags & DNET_FLAGS_REPLY) {
		return recv_response(st, cmd, std::move(body));
	} else {
		return recv_request(st, cmd, std::move(body));
	}
}

int protocol::recv_request(dnet_net_state *st, const dnet_cmd &cmd, data_pointer &&body) {
	switch (cmd.cmd) {
	case DNET_CMD_LOOKUP:
		return translate_lookup_request(st, cmd);
	case DNET_CMD_LOOKUP_NEW:
		return translate_lookup_new_request(st, cmd);
	case DNET_CMD_DEL_NEW:
		return translate_remove_new_request(st, cmd, std::move(body));
	default:
		// Must never reach this code, due to is_supported_message() filter called before
		return -ENOTSUP;
	}
}

int protocol::recv_response(dnet_net_state *st, const dnet_cmd &cmd, data_pointer &&raw_body) {
	pthread_mutex_lock(&st->trans_lock);
	std::unique_ptr<dnet_trans, void (*)(dnet_trans *)>
		t(dnet_trans_search(st, cmd.trans), &dnet_trans_put);
	pthread_mutex_unlock(&st->trans_lock);

	if (!t || !t->repliers) {
		return -EINVAL;
	}

	n2_repliers &repliers = *t->repliers;
	bool last = !(cmd.flags & DNET_FLAGS_MORE);

	if (cmd.status) {
		return repliers.on_reply_error(cmd.status, last);
	}

	int err = 0;
	std::shared_ptr<n2_body> body;

	switch (cmd.cmd) {
	case DNET_CMD_LOOKUP:
		err = deserialize_lookup_response_body(st->n, std::move(raw_body), body);
		break;
	case DNET_CMD_LOOKUP_NEW:
		err = deserialize_new<lookup_response>(st->n, std::move(raw_body), body);
		break;
	case DNET_CMD_DEL_NEW:
		break;
	default:
		// Must never reach this code, due to is_supported_message() filter called before
		err = -ENOTSUP;
	}
	if (err)
		return err;

	return repliers.on_reply(body, last);
}

int protocol::translate_lookup_request(dnet_net_state *st, const dnet_cmd &cmd) {
	return translate_request<lookup_replier>(st, cmd, nullptr);
}

int protocol::translate_lookup_new_request(dnet_net_state *st, const dnet_cmd &cmd) {
	return translate_request<lookup_new_replier>(st, cmd, nullptr);
}

int protocol::translate_remove_new_request(dnet_net_state *st, const dnet_cmd &cmd, data_pointer &&body) {
	std::shared_ptr<n2_body> deserialized;
	int err = deserialize_new<remove_request>(st->n, std::move(body), deserialized);
	if (err)
		return err;
	return translate_request<replier_base>(st, cmd, deserialized);
}

}}} // namespace ioremap::elliptics::native

extern "C" {

int n2_native_protocol_io_start(struct dnet_node *n) {
	auto impl = [io = n->io] {
		io->native_protocol = new n2_native_protocol_io;
		return 0;
	};
	return c_exception_guard(impl, n, __FUNCTION__);
}

void n2_native_protocol_io_stop(struct dnet_node *n) {
	auto impl = [io = n->io] {
		delete io->native_protocol;
		io->native_protocol = nullptr;
		return 0;
	};
	c_exception_guard(impl, n, __FUNCTION__);
}

void n2_native_protocol_rcvbuf_create(struct dnet_net_state *st) {
	st->rcv_buffer = new n2_recv_buffer;
}

void n2_native_protocol_rcvbuf_destroy(struct dnet_net_state *st) {
	delete st->rcv_buffer;
	st->rcv_buffer = nullptr;
}

bool n2_native_protocol_is_supported_message(struct dnet_net_state *st) {
	const dnet_cmd *cmd = &st->rcv_cmd;

	// Replies addressed to client are currently passed via old mechanic. This condition branch will be removed
	// after client supports new mechanic for DNET_CMD_LOOKUP_NEW command.
	if (cmd->flags & DNET_FLAGS_REPLY) {
		std::unique_ptr<dnet_trans, void (*)(dnet_trans *)>
		        t(dnet_trans_search(st, cmd->trans), &dnet_trans_put);

		if (t && !t->repliers)
			return false;
	}

	return cmd->cmd == DNET_CMD_LOOKUP ||
	       cmd->cmd == DNET_CMD_LOOKUP_NEW ||
	       cmd->cmd == DNET_CMD_DEL_NEW;
}

int n2_native_protocol_prepare_message_buffer(struct dnet_net_state *st) {
	if (!n2_native_protocol_is_supported_message(st)) {
		st->rcv_buffer_used = 0;
		return -ENOTSUP;
	} else {
		st->rcv_buffer_used = 1;
	}

	const dnet_cmd *cmd = &st->rcv_cmd;

	st->rcv_buffer->buf = ioremap::elliptics::data_pointer::allocate(cmd->size);
	st->rcv_data = st->rcv_buffer->buf.data();
	st->rcv_offset = 0;
	st->rcv_end = cmd->size;
	return 0;
}

int n2_native_protocol_schedule_message(struct dnet_net_state *st) {
	if (!st->rcv_buffer_used)
		return -ENOTSUP;

	auto impl = [&] {
		return st->n->io->native_protocol->protocol.recv_message(st, st->rcv_cmd,
		                                                         std::move(st->rcv_buffer->buf));
	};
	return c_exception_guard(impl, st->n, __FUNCTION__);
}

void n2_serialized_free(struct n2_serialized *serialized) {
	delete serialized;
}

} // extern "С"
