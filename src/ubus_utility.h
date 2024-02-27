
/*
 *	BSD 3-Clause License
 *
 *	Copyright (c) 2019, Christian Marangi
 * 	All rights reserved.
 */

#ifndef NGINX_NGX_HTTP_UBUS_UTILITY_HEADERS_H
#define NGINX_NGX_HTTP_UBUS_UTILITY_HEADERS_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/avl.h>
#include <libubox/avl-cmp.h>

#include <pthread.h>
#include <semaphore.h>

#include <libubus.h>
#include <json-c/json.h>

#define UBUS_MAX_POST_SIZE 65536
#define UBUS_DEFAULT_SID "00000000000000000000000000000000"

struct dispatch_ubus {
	struct ubus_request req;

	struct json_object *jsobj;
	struct json_object *jsobj_cur;

	uint32_t obj;
	const char *func;
};

typedef struct {
	ngx_http_request_t *r;
	int res_len;
	ngx_chain_t *out_chain;
	ngx_chain_t *out_chain_start;
	struct ubus_context *ubus_ctx;
	sem_t *sem;
	/* Signal when at least a thread is free */
	sem_t *avail_thread;
	/* Special semaphore logic, thread increment this,
	 * producer decrement this. Is checked n times the
	 * object to process to check if everything has
	 * been processed. (instead of relying to pthread join)
	 */
	sem_t *obj_processed;
} request_ctx_t;

typedef struct {
	struct blob_buf *buf;
	struct dispatch_ubus *ubus;
	bool array;
	char **res_str;
	request_ctx_t *request;
} ubus_ctx_t;

enum {
	RPC_JSONRPC,
	RPC_METHOD,
	RPC_PARAMS,
	RPC_ID,
	__RPC_MAX,
};

static const struct blobmsg_policy rpc_policy[__RPC_MAX] = {
	[RPC_JSONRPC] = {.name = "jsonrpc", .type = BLOBMSG_TYPE_STRING},
	[RPC_METHOD] = {.name = "method", .type = BLOBMSG_TYPE_STRING},
	[RPC_PARAMS] = {.name = "params", .type = BLOBMSG_TYPE_ARRAY},
	[RPC_ID] = {.name = "id", .type = BLOBMSG_TYPE_UNSPEC},
};

enum {
	SES_ACCESS,
	__SES_MAX,
};

static const struct blobmsg_policy ses_policy[__SES_MAX] = {
	[SES_ACCESS] = {.name = "access", .type = BLOBMSG_TYPE_BOOL},
};

struct rpc_data {
	struct blob_attr *id;
	const char *sid;
	const char *method;
	const char *object;
	const char *function;
	struct blob_attr *data;
	struct blob_attr *params;
};

struct list_data {
	bool verbose;
	struct blob_buf *buf;
};

enum rpc_status {
	REQUEST_OK,
	ERROR_PARSE,
	ERROR_REQUEST,
	ERROR_METHOD,
	ERROR_PARAMS,
	ERROR_INTERNAL,
	ERROR_OBJECT,
	ERROR_SESSION,
	ERROR_ACCESS,
	ERROR_TIMEOUT,
	__ERROR_MAX
};

static const struct {
	int code;
	const char *msg;
} json_errors[__ERROR_MAX] = {
	[REQUEST_OK] = {0, "Request complete correctly"},
	[ERROR_PARSE] = {-32700, "Parse error"},
	[ERROR_REQUEST] = {-32600, "Invalid request"},
	[ERROR_METHOD] = {-32601, "Method not found"},
	[ERROR_PARAMS] = {-32602, "Invalid parameters"},
	[ERROR_INTERNAL] = {-32603, "Internal error"},
	[ERROR_OBJECT] = {-32000, "Object not found"},
	[ERROR_SESSION] = {-32001, "Session not found"},
	[ERROR_ACCESS] = {-32002, "Access denied"},
	[ERROR_TIMEOUT] = {-32003, "ubus request timed out"},
};

bool parse_json_rpc(struct rpc_data *d, struct blob_attr *data);
void ubus_init_response(struct blob_buf *buf, struct dispatch_ubus *du);
void ubus_allowed_cb(struct ubus_request *req, int type, struct blob_attr *msg);
void ubus_request_cb(struct ubus_request *req, int type, struct blob_attr *msg);
void ubus_list_cb(struct ubus_context *ctx, struct ubus_object_data *obj,
		  void *priv);
void ubus_close_fds(struct ubus_context *ctx);

#endif /* NGINX_NGX_HTTP_UBUS_UTILITY_HEADERS_H */
