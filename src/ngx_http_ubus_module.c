
/*
 *	BSD 3-Clause License
 *
 *	Copyright (c) 2019, Christian Marangi
 * 	All rights reserved.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ubus_utility.h"

static void *ngx_http_ubus_create_loc_conf(ngx_conf_t *cf);

static char *ngx_http_ubus_merge_loc_conf(ngx_conf_t *cf, void *parent,
					  void *child);

static char *ngx_http_ubus(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

typedef struct {
	ngx_str_t socket_path;
	ngx_flag_t cors;
	ngx_uint_t script_timeout;
	ngx_flag_t noauth;
	ngx_flag_t enable;
	ngx_uint_t parallel_req;
#ifdef NGX_THREADS
	ngx_thread_pool_t *thread_pool;
	pthread_mutex_t *ubus_mutex;
#endif
} ngx_http_ubus_loc_conf_t;

static ngx_command_t ngx_http_ubus_commands[] = {
	{ngx_string("ubus_interpreter"), NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
	 ngx_http_ubus, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL},

	{ngx_string("ubus_socket_path"), NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	 ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
	 offsetof(ngx_http_ubus_loc_conf_t, socket_path), NULL},

	{ngx_string("ubus_cors"), NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
	 ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
	 offsetof(ngx_http_ubus_loc_conf_t, cors), NULL},

	{ngx_string("ubus_script_timeout"), NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	 ngx_conf_set_num_slot, NGX_HTTP_LOC_CONF_OFFSET,
	 offsetof(ngx_http_ubus_loc_conf_t, script_timeout), NULL},

	{ngx_string("ubus_noauth"), NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
	 ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
	 offsetof(ngx_http_ubus_loc_conf_t, noauth), NULL},

	{ngx_string("ubus_parallel_req"), NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	 ngx_conf_set_num_slot, NGX_HTTP_LOC_CONF_OFFSET,
	 offsetof(ngx_http_ubus_loc_conf_t, parallel_req), NULL},

	ngx_null_command
};

static ngx_http_module_t ngx_http_ubus_module_ctx = {
	NULL,	/* preconfiguration */
	NULL,	/* postconfiguration */

	NULL,	/* create main configuration */
	NULL,	/* init main configuration */

	NULL,	/* create server configuration */
	NULL,	/* merge server configuration */

	ngx_http_ubus_create_loc_conf,	/* create location configuration */
	ngx_http_ubus_merge_loc_conf	/* merge location configuration */
};

ngx_module_t ngx_http_ubus_module = {
	NGX_MODULE_V1,
	&ngx_http_ubus_module_ctx,	/* module context */
	ngx_http_ubus_commands,		/* module directives */
	NGX_HTTP_MODULE,		/* module type */
	NULL,				/* init master */
	NULL,				/* init module */
	NULL,				/* init process */
	NULL,				/* init thread */
	NULL,				/* exit thread */
	NULL,				/* exit process */
	NULL,				/* exit master */
	NGX_MODULE_V1_PADDING
};

struct cors_data {
	char *ORIGIN;
	char *ACCESS_CONTROL_REQUEST_METHOD;
	char *ACCESS_CONTROL_REQUEST_HEADERS;
};

static void ubus_single_error(request_ctx_t *request, enum rpc_status type);
static ngx_int_t ngx_http_ubus_send_body(request_ctx_t *request);
static ngx_int_t append_to_output_chain(request_ctx_t *request,
					const char *str);
static void free_output_chain(ngx_http_request_t *r, ngx_chain_t *chain);
static struct dispatch_ubus *setup_dispatch_ubus(struct json_object *obj);
static void free_dispatch_ubus(struct dispatch_ubus *du);

static ngx_int_t set_custom_headers_out(ngx_http_request_t *r,
					const char *key_str,
					const char *value_str) {
	ngx_table_elt_t *h;
	ngx_str_t value;
	ngx_str_t key;

	unsigned char *tmp;
	int len;

	len = strlen(key_str);
	tmp = ngx_palloc(r->pool, len + 1);
	ngx_memcpy(tmp, key_str, len);

	key.data = tmp;
	key.len = len;

	len = strlen(value_str);
	tmp = ngx_palloc(r->pool, len + 1);
	ngx_memcpy(tmp, value_str, len);

	value.data = tmp;
	value.len = len;

	h = ngx_list_push(&r->headers_out.headers);
	if (!h)
		return NGX_ERROR;

	h->key = key;
	h->value = value;
	h->hash = 1;

	return NGX_OK;
}

static void parse_cors_from_header(ngx_http_request_t *r,
				   struct cors_data *cors) {
	ngx_list_part_t *part;
	ngx_table_elt_t *h;
	ngx_uint_t i;

	ngx_uint_t found_count = 0;

	part = &r->headers_in.headers.part;
	h = part->elts;

	for (i = 0; /* void */; i++) {
		if (found_count == 3)
			break;

		if (i >= part->nelts) {
			if (part->next == NULL) {
				break;
			}

			part = part->next;
			h = part->elts;
			i = 0;
		}

		if (ngx_strcmp("origin", h[i].key.data)) {
			cors->ORIGIN = (char *)h[i].key.data;
			found_count++;
		} else if (ngx_strcmp("access-control-request-method", h[i].key.data)) {
			cors->ACCESS_CONTROL_REQUEST_METHOD = (char *)h[i].key.data;
			found_count++;
		} else if (ngx_strcmp("access-control-request-headers", h[i].key.data)) {
			cors->ACCESS_CONTROL_REQUEST_HEADERS = (char *)h[i].key.data;
			found_count++;
		}
	}
}

static void ubus_add_cors_headers(ngx_http_request_t *r) {
	struct cors_data *cors;

	cors = ngx_pcalloc(r->pool, sizeof(struct cors_data));
	parse_cors_from_header(r, cors);

	if (!cors->ORIGIN)
		return;

	if (cors->ACCESS_CONTROL_REQUEST_METHOD) {
		char *req = cors->ACCESS_CONTROL_REQUEST_METHOD;
		if (strcmp(req, "POST") && strcmp(req, "OPTIONS"))
			return;
	}

	set_custom_headers_out(r, "Access-Control-Allow-Origin", cors->ORIGIN);
	if (cors->ACCESS_CONTROL_REQUEST_HEADERS)
		set_custom_headers_out(r, "Access-Control-Allow-Headers",
				       cors->ACCESS_CONTROL_REQUEST_HEADERS);
	set_custom_headers_out(r, "Access-Control-Allow-Methods", "POST, OPTIONS");
	set_custom_headers_out(r, "Access-Control-Allow-Credentials", "true");

	ngx_pfree(r->pool, cors);
}

static ngx_int_t ngx_http_ubus_send_header(ngx_http_request_t *r,
					   ngx_http_ubus_loc_conf_t *cglcf,
					   ngx_int_t status,
					   ngx_int_t post_len) {
	r->headers_out.status = status;
	r->headers_out.content_type.len = sizeof("application/json") - 1;
	r->headers_out.content_type.data = (u_char *)"application/json";
	r->headers_out.content_length_n = post_len;

	if (cglcf->cors)
		ubus_add_cors_headers(r);

	return ngx_http_send_header(r);
}

static char *gen_error_from_du(struct dispatch_ubus *du,
			       enum rpc_status type) {
	struct blob_buf *buf;
	char *str;
	void *c;

	buf = calloc(1, sizeof(*buf));

	ubus_init_response(buf, du);

	c = blobmsg_open_table(buf, "error");
	blobmsg_add_u32(buf, "code", json_errors[type].code);
	blobmsg_add_string(buf, "message", json_errors[type].msg);
	blobmsg_close_table(buf, c);

	str = blobmsg_format_json(buf->head, true);

	blob_buf_free(buf);
	free(buf);

	return str;
}

static char *gen_error_from_obj(struct json_object *obj,
			        enum rpc_status type) {
	struct dispatch_ubus *du;
	char *str;

	du = setup_dispatch_ubus(obj);

	str = gen_error_from_du(du, type);

	free_dispatch_ubus(du);

	return str;
}

static void ubus_single_error(request_ctx_t *request, enum rpc_status type) {
	ngx_http_ubus_loc_conf_t *cglcf;
	char *str;

	cglcf = ngx_http_get_module_loc_conf(request->r, ngx_http_ubus_module);
	ngx_log_error(NGX_LOG_ERR, request->r->connection->log, 0,
		      "Request generated error: %s", json_errors[type].msg);

	free_output_chain(request->r, request->out_chain_start);
	request->res_len = 0;

	str = gen_error_from_obj(NULL, type);
	append_to_output_chain(request, str);
	free(str);

	ngx_http_ubus_send_header(request->r, cglcf, NGX_HTTP_OK, request->res_len);
	ngx_http_ubus_send_body(request);
}

static ngx_int_t append_to_output_chain(request_ctx_t *request,
					const char *str) {
	ngx_chain_t *out_chain;
	ngx_int_t len;
	ngx_buf_t *b;

	unsigned char *data;

	len = strlen(str);
	data = ngx_pcalloc(request->r->pool, len);
	ngx_memcpy(data, str, len);

	b = ngx_pcalloc(request->r->pool, sizeof(ngx_buf_t));
	b->pos = data;
	b->last = data + len;
	b->memory = 1;
	request->res_len += len;

	out_chain = ngx_pcalloc(request->r->pool, sizeof(*out_chain));
	out_chain->buf = b;
	out_chain->next = NULL;

	if (!request->out_chain) /* First chain set start */
		request->out_chain_start = out_chain;
	else /* Else set next chain from the current chain */
		request->out_chain->next = out_chain;
	
	/* Set the current chain with the new one */
	request->out_chain = out_chain;

	return NGX_OK;
}

static struct dispatch_ubus *setup_dispatch_ubus(struct json_object *obj) {
	struct dispatch_ubus *du;

	du = malloc(sizeof(*du));
	if (!du)
		return NULL;

	du->jsobj = obj;

	return du;
}

static void free_dispatch_ubus(struct dispatch_ubus *du) {
	free(du);
}

static ngx_int_t setup_ubus_ctx_t(ubus_ctx_t *ctx, request_ctx_t *request,
				  struct json_object *obj, char **res_str) {
	ctx->ubus = setup_dispatch_ubus(obj);
	if (!ctx->ubus)
		return NGX_ERROR;

	ctx->request = request;
	ctx->res_str = res_str;

	return NGX_OK;
}

static void free_ubus_ctx_t(ubus_ctx_t *ctx) {
	free_dispatch_ubus(ctx->ubus);
}

static void free_output_chain(ngx_http_request_t *r, ngx_chain_t *chain) {
	ngx_chain_t *chain_tmp;

	while (chain) {
		ngx_pfree(r->pool, chain->buf->pos);
		ngx_pfree(r->pool, chain->buf);
		chain_tmp = chain;
		chain = chain->next;
		ngx_pfree(r->pool, chain_tmp);
	}
}

static ngx_int_t ngx_http_ubus_send_body(request_ctx_t *request) {
	ngx_int_t rc;

	request->out_chain->buf->last_buf = 1;
	rc = ngx_http_output_filter(request->r, request->out_chain_start);

	free_output_chain(request->r, request->out_chain_start);

	return rc;
}

static bool ubus_allowed(ubus_ctx_t *ctx, ngx_int_t script_timeout,
			 const char *sid, const char *obj, const char *fun) {
	request_ctx_t *request = ctx->request;
	struct blob_buf *req;
	bool allow = false;
	ngx_int_t rc;
	uint32_t id;

	UBUS_LOCK(request);
	rc = ubus_lookup_id(request->ubus_ctx, "session", &id);
	UBUS_UNLOCK(request);
	if (rc)
		return false;

	req = calloc(1, sizeof(*req));

	blob_buf_init(req, 0);
	blobmsg_add_string(req, "ubus_rpc_session", sid);
	blobmsg_add_string(req, "object", obj);
	blobmsg_add_string(req, "function", fun);

	UBUS_LOCK(request);
	ubus_invoke(request->ubus_ctx, id, "access", req->head,
		    ubus_allowed_cb, &allow, script_timeout * 500);
	UBUS_UNLOCK(request);

	blob_buf_free(req);
	free(req);

	return allow;
}

static enum rpc_status ubus_send_request(request_ctx_t *request,
					 ubus_ctx_t *ctx, const char *sid,
					 struct blob_attr *args) {
	void *r;
	int ret, rem;
	struct blob_attr *cur;
	enum rpc_status rc = REQUEST_OK;
	ngx_http_ubus_loc_conf_t *cglcf;
	struct dispatch_ubus *du = ctx->ubus;
	struct blob_buf *req, *data, *res_obj;

	cglcf = ngx_http_get_module_loc_conf(request->r, ngx_http_ubus_module);
	req = calloc(1, sizeof(*req));

	blob_buf_init(req, 0);
	blobmsg_for_each_attr(cur, args, rem) {
		if (!strcmp(blobmsg_name(cur), "ubus_rpc_session")) {
			rc = ERROR_PARAMS;
			goto out;
		}
		blobmsg_add_blob(req, cur);
	}

	blobmsg_add_string(req, "ubus_rpc_session", sid);

	data = calloc(1, sizeof(*data));
	blob_buf_init(data, 0);

	res_obj = calloc(1, sizeof(*res_obj));
	ubus_init_response(res_obj, du);

	r = blobmsg_open_array(res_obj, "result");

	UBUS_LOCK(request);
	ret = ubus_invoke(request->ubus_ctx, du->obj_id, du->func, req->head,
			  ubus_request_cb, data, cglcf->script_timeout * 1000);
	UBUS_UNLOCK(request);

	blobmsg_add_u32(res_obj, "", ret);
	if (!ret)
		blob_for_each_attr(cur, data->head, rem)
			blobmsg_add_blob(res_obj, cur);

	blobmsg_close_array(res_obj, r);

	*ctx->res_str = blobmsg_format_json(res_obj->head, true);

	blob_buf_free(data);
	free(data);
	blob_buf_free(res_obj);
	free(res_obj);
out:
	blob_buf_free(req);
	free(req);

	return rc;
}

static enum rpc_status ubus_send_list(request_ctx_t *request, ubus_ctx_t *ctx,
				      struct blob_attr *params) {
	struct blob_buf *res_obj;
	struct dispatch_ubus *du;
	struct list_data *data;
	struct blob_attr *cur;
	void *r, *t;
	int rem;

	du = ctx->ubus;
	res_obj = calloc(1, sizeof(*res_obj));
	data = malloc(sizeof(*data));
	data->buf = res_obj;
	data->verbose = false;

	ubus_init_response(res_obj, du);

	r = blobmsg_open_array(res_obj, "result");
	if (!params || blob_id(params) != BLOBMSG_TYPE_ARRAY) {
		t = blobmsg_open_array(res_obj, "");

		UBUS_LOCK(request);
		ubus_lookup(request->ubus_ctx, NULL, ubus_list_cb, data);
		UBUS_UNLOCK(request);

		blobmsg_close_array(res_obj, t);
	} else {
		rem = blobmsg_data_len(params);
		data->verbose = true;

		__blob_for_each_attr(cur, blobmsg_data(params), rem) {
			UBUS_LOCK(request);
			ubus_lookup(request->ubus_ctx, blobmsg_data(cur),
				    ubus_list_cb, data);
			UBUS_UNLOCK(request);
		}
	}
	blobmsg_close_array(res_obj, r);

	*ctx->res_str = blobmsg_format_json(res_obj->head, true);

	free(data);
	blob_buf_free(res_obj);
	free(res_obj);

	return REQUEST_OK;
}

static void ubus_post_object(void *data, ngx_log_t *log) {
	ubus_ctx_t *ctx = data;
	request_ctx_t *request = ctx->request;
	struct dispatch_ubus *du = ctx->ubus;
	ngx_http_ubus_loc_conf_t *cglcf;
	struct rpc_data *rpc_data;
	struct blob_buf *buf;
	enum rpc_status rc;
	int ret;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->r->connection->log, 0,
		       "Start processing json object");

	cglcf = ngx_http_get_module_loc_conf(request->r, ngx_http_ubus_module);

	if (json_object_get_type(du->jsobj) != json_type_object) {
		rc = ERROR_PARSE;
		goto out;
	}

	buf = calloc(1, sizeof(*buf));
	blob_buf_init(buf, 0);
	if (!blobmsg_add_object(buf, du->jsobj)) {
		rc = ERROR_PARSE;
		goto free_buf;
	}

	rpc_data = calloc(1, sizeof(*rpc_data));
	if (!parse_json_rpc(rpc_data, buf->head)) {
		rc = ERROR_PARSE;
		goto free_rpc_data;
	}

	if (!strcmp(rpc_data->method, "call")) {
		if (!rpc_data->sid || !rpc_data->object ||
		    !rpc_data->function || !rpc_data->data) {
			rc = ERROR_PARSE;
			goto free_rpc_data;
		}

		du->func = rpc_data->function;

		UBUS_LOCK(request);
		ret = ubus_lookup_id(request->ubus_ctx, rpc_data->object, &du->obj_id);
		UBUS_UNLOCK(request);
		if (ret) {
			rc = ERROR_OBJECT;
			goto free_rpc_data;
		}

		ret = ubus_allowed(ctx, cglcf->script_timeout, rpc_data->sid,
				   rpc_data->object, rpc_data->function);

		if (!cglcf->noauth && !ret) {
			rc = ERROR_ACCESS;
			goto free_rpc_data;
		}

		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->r->connection->log, 0,
			       "Start processing call request");

		rc = ubus_send_request(request, ctx, rpc_data->sid, rpc_data->data);
	} else if (!strcmp(rpc_data->method, "list")) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->r->connection->log, 0,
			       "Start processing list request");

		rc = ubus_send_list(request, ctx, rpc_data->params);
		if (rpc_data->params)
			free(rpc_data->params);
	} else {
		rc = ERROR_METHOD;
	}

free_rpc_data:
	free(rpc_data);

free_buf:
	blob_buf_free(buf);
	free(buf);

out:
	if (rc != REQUEST_OK) {
		*ctx->res_str = gen_error_from_du(du, rc);
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, request->r->connection->log, 0,
			       "Error in Json object processed: %d", rc);
	} else {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->r->connection->log, 0,
			       "Json object processed correctly");
	}
}

static void ubus_post_object_completition(ngx_event_t *ev) {
	ubus_ctx_t *ctx = ev->data;
#ifdef NGX_THREADS
	request_ctx_t *request;

	request = ctx->request;

	ngx_thread_mutex_lock(request->mutex, request->r->connection->log);
	request->objs_processed++;
	ngx_thread_mutex_unlock(request->mutex, request->r->connection->log);
	/* Wake finalize thread to signal object processed */
	ngx_thread_cond_signal(request->condition, request->r->connection->log);
#endif

	free_ubus_ctx_t(ctx);
}

static ngx_int_t ubus_process_object(request_ctx_t *request,
				     struct json_object *obj,
				     char **res_str) {
#ifdef NGX_THREADS
	ngx_http_ubus_loc_conf_t *cglcf;
	ngx_thread_task_t *task;
#endif
	ngx_event_t *event;
	ubus_ctx_t *ctx;
	ngx_int_t rc;

#ifdef NGX_THREADS
	cglcf = ngx_http_get_module_loc_conf(request->r, ngx_http_ubus_module);

	task = ngx_thread_task_alloc(request->r->pool, sizeof(*ctx));
	ctx = task->ctx;
	task->handler = ubus_post_object;
	event = &task->event;
	event->handler = ubus_post_object_completition;
	event->data = ctx;
#else
	event = malloc(sizeof(*event));
	ctx = malloc(sizeof(*ctx));
	event->data = ctx;
#endif

	rc = setup_ubus_ctx_t(ctx, request, obj, res_str);
	if (rc != NGX_OK)
		return rc;

#ifdef NGX_THREADS
	ngx_thread_task_post(cglcf->thread_pool, task);
#else
	ubus_post_object(ctx, request->r->connection->log);
	ubus_post_object_completition(event);
	free(event);
	free(ctx);
#endif

	return NGX_OK;
}

static ngx_int_t ubus_process_array(request_ctx_t *request,
				    struct json_object *obj) {
	ngx_int_t rc;
	int obj_num;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->r->connection->log, 0,
		       "Start processing array json object");

	for (obj_num = 0; obj_num < request->objs_num; obj_num++) {
		struct json_object *obj_tmp;

		obj_tmp = json_object_array_get_idx(obj, obj_num);

		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, request->r->connection->log, 0,
			       "Spawning thread %d to process request %d", concurrent,
			       obj_num);

		/* 
		 * If for some reason this errors out we can only handle it internally
		 * and print a warning. Onf finalize thread the res string won't be present
		 * and internal error will be reported.
		 */
		rc = ubus_process_object(request, obj_tmp, request->res_strs + obj_num);
		if (rc != NGX_OK)
			ngx_log_error(NGX_LOG_ERR, request->r->connection->log, 0,
				      "Failed to process array's object %d", obj_num);
	}

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->r->connection->log, 0,
		       "Request processed correctly");

	return NGX_OK;
}

#ifdef NGX_THREADS
static void ngx_http_ubus_finalize_req(void *data, ngx_log_t *log)
{
	request_ctx_t *request = data;

	/*
	 * Wait for every thread to finish processing all the objects.
	 */
	ngx_thread_mutex_lock(request->mutex, log);
	while (request->objs_processed != request->objs_num)
		ngx_thread_cond_wait(request->condition, request->mutex, log);
	ngx_thread_mutex_unlock(request->mutex, log);
}
#endif

static void ngx_http_ubus_finalize_req_completion(ngx_event_t *ev) {
	request_ctx_t *request = ev->data;
	ngx_http_ubus_loc_conf_t *cglcf;
	ngx_int_t rc;
	int obj_num;

	cglcf = ngx_http_get_module_loc_conf(request->r, ngx_http_ubus_module);

	if (request->array)
		append_to_output_chain(request, "[");
	for (obj_num = 0; obj_num < request->objs_num; obj_num++) {
		char *res_str = request->res_strs[obj_num];
		struct json_object *obj_tmp = NULL;

		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, request->r->connection->log, 0,
			       "Writing output of index %d to body", obj_num);
		if (obj_num > 0)
			append_to_output_chain(request, ",");
		if (!res_str) {
			if (request->array)
				obj_tmp = json_object_array_get_idx(request->jsobj, obj_num);
			res_str = gen_error_from_obj(obj_tmp, ERROR_INTERNAL);
		}
		append_to_output_chain(request, res_str);
		free(res_str);
	}
	if (request->array)
		append_to_output_chain(request, "]");

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Sending header");

	rc = ngx_http_ubus_send_header(request->r, cglcf, NGX_HTTP_OK, request->res_len);
	if (rc == NGX_ERROR || rc > NGX_OK)
		goto finalize;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Sending body");

	rc = ngx_http_ubus_send_body(request);

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Request complete");

finalize:
	free(request->res_strs);

#ifdef NGX_THREADS
	ngx_thread_mutex_destroy(request->mutex, request->r->connection->log);
	free(request->mutex);
	ngx_thread_cond_destroy(request->condition, request->r->connection->log);
	free(request->condition);
#endif

	json_object_put(request->jsobj);
	ubus_free(request->ubus_ctx);
	ngx_http_finalize_request(request->r, rc);
}

static ngx_int_t ngx_http_ubus_init_req(request_ctx_t *request,
					int objs_num, bool array)
{
	char **res_strs;
#ifdef NGX_THREADS
	ngx_http_ubus_loc_conf_t *cglcf;

	cglcf = ngx_http_get_module_loc_conf(request->r, ngx_http_ubus_module);
#endif

	res_strs = calloc(objs_num, sizeof(*res_strs));
	request->res_strs = res_strs;
	request->objs_num = objs_num;
	request->array = array;
#ifdef NGX_THREADS
	request->mutex = malloc(sizeof(*request->mutex));
	request->condition = malloc(sizeof(*request->condition));
	/* Add reference to ubus_mutex to make it easier to access */
	request->ubus_mutex = cglcf->ubus_mutex;

	ngx_thread_mutex_create(request->mutex, request->r->connection->log);
	ngx_thread_cond_create(request->condition, request->r->connection->log);
#endif

	return NGX_OK;
}

static ngx_int_t ngx_http_ubus_elaborate_req(request_ctx_t *request,
					     struct json_object *obj) {
	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->r->connection->log, 0,
		       "Analyzing json object");

	switch (obj ? json_object_get_type(obj) : json_type_null) {
	case json_type_object:
		ngx_http_ubus_init_req(request, 1, false);

		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->r->connection->log, 0,
			       "Json object detected");

		return ubus_process_object(request, obj, request->res_strs);
	case json_type_array:
		ngx_http_ubus_init_req(request, json_object_array_length(obj), true);

		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->r->connection->log, 0,
			       "Json array detected");

		return ubus_process_array(request, obj);
	default:
		ubus_single_error(request, ERROR_PARSE);
		return NGX_ERROR;
	}
}

static void ngx_http_ubus_req_handler(ngx_http_request_t *r) {
	off_t len;
	off_t pos = 0;
	ngx_chain_t *in;
	ngx_event_t *event;
	request_ctx_t *request;
	struct json_tokener *jstok;
	ngx_int_t rc = NGX_HTTP_OK;
	enum json_tokener_error jserr;
	struct ubus_context *ubus_ctx;
	ngx_http_ubus_loc_conf_t *cglcf;
	struct json_object *jsobj = NULL;

#ifdef NGX_THREADS
	ngx_thread_task_t *task;

	task = ngx_thread_task_alloc(r->pool, sizeof(*request));
	request = task->ctx;
#else	
	request = ngx_pcalloc(r->pool, sizeof(*request));
#endif
	request->r = r;

	cglcf = ngx_http_get_module_loc_conf(r, ngx_http_ubus_module);
	ubus_ctx = ubus_connect((char *)cglcf->socket_path.data);
	if (!ubus_ctx) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			      "Unable to connect to ubus socket: %s",
			      cglcf->socket_path.data);
		ubus_single_error(request, ERROR_INTERNAL);
		goto finalize;
	}
	request->ubus_ctx = ubus_ctx;

	jstok = json_tokener_new();
	if (!jstok) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			      "Error jstok struct not ok");
		ubus_single_error(request, ERROR_PARSE);
		goto free_ubus;
	}

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		       "Reading request body");

	for (in = r->request_body->bufs; in; in = in->next) {
		len = ngx_buf_size(in->buf);

		jsobj = json_tokener_parse_ex(jstok, (const char *)in->buf->pos, len);
		jserr = json_tokener_get_error(jstok);
		if (jserr != json_tokener_continue &&
		    jserr != json_tokener_success) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				      "Error in json tokener parsing");
			ubus_single_error(request, ERROR_PARSE);
			goto free_tok;
		}

		pos += len;
		if (pos > UBUS_MAX_POST_SIZE) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
				      "Error max post size for ubus socket");
			ubus_single_error(request, ERROR_PARSE);
			goto free_tok;
		}
	}

	if (!jsobj) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			      "Error in json tokener parsing");
		ubus_single_error(request, ERROR_PARSE);
		goto free_tok;
	}

	if (pos != r->headers_in.content_length_n) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			      "Readed buffer differ from header request len");
		ubus_single_error(request, ERROR_PARSE);
		goto free_obj;
	}
	request->jsobj = jsobj;

	rc = ngx_http_ubus_elaborate_req(request, jsobj);
	if (rc == NGX_ERROR) {
		// With ngx_error we are sending json error
		// and we say that the request is ok
		goto free_obj;
	}

#ifdef NGX_THREADS
	task->handler = ngx_http_ubus_finalize_req;
	event = &task->event;
	event->handler = ngx_http_ubus_finalize_req_completion;
	event->data = request;

	ngx_thread_task_post(cglcf->thread_pool, task);

	r->main->blocked++;
#else
	event = malloc(sizeof(*event));
	event->data = request;
	ngx_http_ubus_finalize_req_completion(event);
	free(event);
#endif

	json_tokener_free(jstok);

	return;

free_obj:
	json_object_put(jsobj);
free_tok:
	json_tokener_free(jstok);
free_ubus:
	ubus_free(ubus_ctx);
finalize:
#ifdef NGX_THREADS
	ngx_pfree(r->pool, task);
#else
	ngx_pfree(r->pool, request);
#endif
	ngx_http_finalize_request(request->r, NGX_HTTP_OK);
}

static ngx_int_t ngx_http_ubus_handler(ngx_http_request_t *r) {
	ngx_http_ubus_loc_conf_t *cglcf;
	ngx_int_t rc;

	cglcf = ngx_http_get_module_loc_conf(r, ngx_http_ubus_module);

	switch (r->method) {
	case NGX_HTTP_OPTIONS:
		r->header_only = 1;

		ngx_http_ubus_send_header(r, cglcf, NGX_HTTP_OK, 0);
		ngx_http_finalize_request(r, NGX_HTTP_OK);

		return NGX_DONE;
	case NGX_HTTP_POST:

		rc = ngx_http_read_client_request_body(r, ngx_http_ubus_req_handler);
		if (rc >= NGX_HTTP_SPECIAL_RESPONSE)
			return rc;

		return NGX_DONE;
	default:
		return NGX_HTTP_BAD_REQUEST;
	}
}

static char *ngx_http_ubus(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_http_core_loc_conf_t *clcf;
	ngx_http_ubus_loc_conf_t *cglcf = conf;

	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_http_ubus_handler;

	cglcf->enable = 1;

	return NGX_CONF_OK;
}

static void *ngx_http_ubus_create_loc_conf(ngx_conf_t *cf) {
	ngx_http_ubus_loc_conf_t *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ubus_loc_conf_t));
	if (!conf)
		return NGX_CONF_ERROR;

	conf->socket_path.data = NULL;
	conf->socket_path.len = -1;

	conf->cors = NGX_CONF_UNSET;
	conf->noauth = NGX_CONF_UNSET;
	conf->script_timeout = NGX_CONF_UNSET_UINT;
	conf->parallel_req = NGX_CONF_UNSET_UINT;
	conf->enable = NGX_CONF_UNSET;

	return conf;
}

#ifdef NGX_THREADS
static ngx_str_t ngx_http_ubus_thread_pool_name = ngx_string("ubus_interpreter");
#endif

static char *ngx_http_ubus_merge_loc_conf(ngx_conf_t *cf, void *parent,
					  void *child) {
	ngx_http_ubus_loc_conf_t *prev = parent;
	ngx_http_ubus_loc_conf_t *conf = child;

	// Skip merge of other, if we don't have a socket to connect...
	// We don't init the module at all.
	if (!conf->socket_path.data)
		return NGX_CONF_OK;

	ngx_conf_merge_value(conf->cors, prev->cors, 0);
	ngx_conf_merge_value(conf->noauth, prev->noauth, 0);
	ngx_conf_merge_uint_value(conf->script_timeout, prev->script_timeout, 60);
	ngx_conf_merge_value(conf->enable, prev->enable, 0);
	ngx_conf_merge_uint_value(conf->parallel_req, prev->parallel_req, 1);

	if (!conf->script_timeout) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
				   "ubus_script_timeout must be greater than 0");
		return NGX_CONF_ERROR;
	}

	if (!conf->parallel_req) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
				   "ubus_parallel_req must be greater than 0");
		return NGX_CONF_ERROR;
	}

#ifdef NGX_THREADS
	conf->thread_pool = ngx_thread_pool_add(cf, &ngx_http_ubus_thread_pool_name);

	/*
	 * Ubus have problem with concurrent request and cause deadlock and even
	 * heap corruption. To prevent this, init a global mutex that every request
	 * will use to enforce single ubus connection.
	 */
	conf->ubus_mutex = malloc(sizeof(*conf->ubus_mutex));
	pthread_mutex_init(conf->ubus_mutex, NULL);
#endif

	return NGX_CONF_OK;
}
