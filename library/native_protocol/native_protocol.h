#pragma once

#ifdef __cplusplus
extern "C" {
#endif

struct dnet_cmd;
struct dnet_net_state;
struct dnet_node;

int n2_native_protocol_io_start(struct dnet_node *n);
void n2_native_protocol_io_stop(struct dnet_node *n);

void n2_native_protocol_rcvbuf_create(struct dnet_net_state *st);
void n2_native_protocol_rcvbuf_destroy(struct dnet_net_state *st);
int n2_native_protocol_prepare_message_buffer(struct dnet_net_state *st);
int n2_native_protocol_schedule_message(struct dnet_net_state *st);

void n2_serialized_free(struct n2_serialized *serialized);

#ifdef __cplusplus
}
#endif
