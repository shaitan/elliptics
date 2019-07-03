#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Helpers for integration with C

struct dnet_cmd;
struct dnet_io_req;
struct n2_request_info;
struct n2_response_info;

struct dnet_cmd *n2_io_req_get_cmd(struct dnet_io_req *r);
struct dnet_cmd *n2_request_info_get_cmd(struct n2_request_info *req_info);

int n2_io_req_set_request_backend_id(struct dnet_io_req *r, int backend_id);

void n2_request_info_free(struct n2_request_info *req_info);
void n2_response_info_free(struct n2_response_info *resp_info);

struct n2_response_info *n2_response_info_create_from_error(struct dnet_cmd *cmd, struct n2_repliers *repliers,
                                                            int err);
void n2_response_info_call_response(struct n2_response_info *response_info);

void n2_reply_error(struct n2_repliers *repliers, int error);
void n2_destroy_repliers(struct n2_repliers *repliers);

#ifdef __cplusplus
}
#endif
