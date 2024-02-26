
/*
 *	BSD 3-Clause License
 *
 *	Copyright (c) 2019, Christian Marangi
 * 	All rights reserved.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ubus_utility.h>

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
static struct dispatch_ubus *setup_dispatch_ubus(struct json_object *obj,
						 ngx_http_request_t *r);
static void free_dispatch_ubus(struct dispatch_ubus *du,
			       ngx_http_request_t *r);

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

static char *gen_error_from_du(ngx_http_request_t *r, struct dispatch_ubus *du,
			       enum rpc_status type) {
	struct blob_buf *buf;
	char *str;
	void *c;

	buf = ngx_pcalloc(r->pool, sizeof(*buf));

	blob_buf_init(buf, 0);
	ubus_init_response(buf, du);

	c = blobmsg_open_table(buf, "error");
	blobmsg_add_u32(buf, "code", json_errors[type].code);
	blobmsg_add_string(buf, "message", json_errors[type].msg);
	blobmsg_close_table(buf, c);

	str = blobmsg_format_json(buf->head, true);

	blob_buf_free(buf);
	ngx_pfree(r->pool, buf);

	return str;
}

static char *gen_error_from_obj(ngx_http_request_t *r, struct json_object *obj,
			        enum rpc_status type) {
	struct dispatch_ubus *du;
	char *str;

	du = setup_dispatch_ubus(obj, r);

	str = gen_error_from_du(r, du, type);

	free_dispatch_ubus(du, r);

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

	str = gen_error_from_obj(request->r, NULL, type);
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

static struct dispatch_ubus *setup_dispatch_ubus(struct json_object *obj,
						 ngx_http_request_t *r) {
	struct dispatch_ubus *du;

	du = ngx_pcalloc(r->pool, sizeof(*du));
	du->jsobj = NULL;
	du->jsobj_cur = obj;
	du->jstok = json_tokener_new();

	return du;
}

static void free_dispatch_ubus(struct dispatch_ubus *du,
			       ngx_http_request_t *r) {
	json_object_put(du->jsobj);
	json_tokener_free(du->jstok);
	ngx_pfree(r->pool, du);
}

static ubus_ctx_t *setup_ubus_ctx_t(request_ctx_t *request,
				   struct json_object *obj) {
	ubus_ctx_t *ctx;

	ctx = ngx_pcalloc(request->r->pool, sizeof(*ctx));
	ctx->ubus = setup_dispatch_ubus(obj, request->r);
	ctx->buf = ngx_pcalloc(request->r->pool, sizeof(*ctx->buf));
	ctx->request = request;

	return ctx;
}

static void free_ubus_ctx_t(ubus_ctx_t *ctx, ngx_http_request_t *r) {
	free_dispatch_ubus(ctx->ubus, r);
	if (ctx->buf->buf)
		blob_buf_free(ctx->buf);
	ngx_pfree(r->pool, ctx->buf);
	ngx_pfree(r->pool, ctx);
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
	struct blob_buf *req;
	bool allow = false;
	uint32_t id;

	if (ubus_lookup_id(ctx->request->ubus_ctx, "session", &id))
		return false;

	req = ngx_pcalloc(ctx->request->r->pool, sizeof(*req));

	blob_buf_init(req, 0);
	blobmsg_add_string(req, "ubus_rpc_session", sid);
	blobmsg_add_string(req, "object", obj);
	blobmsg_add_string(req, "function", fun);

	ubus_invoke(ctx->request->ubus_ctx, id, "access", req->head, ubus_allowed_cb,
		    &allow, script_timeout * 500);

	blob_buf_free(req);
	ngx_pfree(ctx->request->r->pool, req);

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
	struct blob_buf *req = ngx_pcalloc(request->r->pool, sizeof(struct blob_buf));

	cglcf = ngx_http_get_module_loc_conf(request->r, ngx_http_ubus_module);
	du->buf = ngx_pcalloc(request->r->pool, sizeof(struct blob_buf));

	blob_buf_init(req, 0);

	ubus_init_response(ctx->buf, du);

	blobmsg_for_each_attr(cur, args, rem) {
		if (!strcmp(blobmsg_name(cur), "ubus_rpc_session")) {
			rc = ERROR_PARAMS;
			goto out;
		}
		blobmsg_add_blob(req, cur);
	}

	blobmsg_add_string(req, "ubus_rpc_session", sid);

	blob_buf_init(du->buf, 0);

	if (ctx->array)
		sem_wait(request->sem);

	ret = ubus_invoke(request->ubus_ctx, du->obj, du->func, req->head,
			  ubus_request_cb, ctx, cglcf->script_timeout * 1000);

	if (ctx->array)
		sem_post(request->sem);

	r = blobmsg_open_array(ctx->buf, "result");
	blobmsg_add_u32(ctx->buf, "", ret);

	if (!ret)
		blob_for_each_attr(cur, du->buf->head, rem) blobmsg_add_blob(ctx->buf, cur);

	blobmsg_close_array(ctx->buf, r);

	*ctx->res_str = blobmsg_format_json(ctx->buf->head, true);

out:
	blob_buf_free(req);
	ngx_pfree(request->r->pool, req);

	blob_buf_free(du->buf);
	ngx_pfree(request->r->pool, du->buf);

	return rc;
}

static enum rpc_status ubus_send_list(request_ctx_t *request, ubus_ctx_t *ctx,
				      struct blob_attr *params) {

	struct list_data data = {0};
	struct dispatch_ubus *du;
	struct blob_attr *cur;
	void *r;
	int rem;

	du = ctx->ubus;
	du->buf = ngx_pcalloc(request->r->pool, sizeof(struct blob_buf));
	data.buf = du->buf;

	blob_buf_init(data.buf, 0);

	ubus_init_response(ctx->buf, du);

	if (ctx->array)
		sem_wait(request->sem);

	r = blobmsg_open_array(data.buf, "result");
	if (!params || blob_id(params) != BLOBMSG_TYPE_ARRAY) {
		ubus_lookup(request->ubus_ctx, NULL, ubus_list_cb, &data);
	} else {
		rem = blobmsg_data_len(params);
		data.verbose = true;

		__blob_for_each_attr(cur, blobmsg_data(params), rem)
			ubus_lookup(request->ubus_ctx, blobmsg_data(cur),
				    ubus_list_cb, &data);
	}
	blobmsg_close_table(data.buf, r);

	if (ctx->array)
		sem_post(request->sem);

	blobmsg_add_blob(ctx->buf, blob_data(data.buf->head));

	*ctx->res_str = blobmsg_format_json(ctx->buf->head, true);

	blob_buf_free(du->buf);
	ngx_pfree(request->r->pool, du->buf);

	return REQUEST_OK;
}

static enum rpc_status ubus_post_object(ubus_ctx_t *ctx) {
	bool array = ctx->array;
	struct rpc_data data = {};
	ngx_http_ubus_loc_conf_t *cglcf;
	enum rpc_status rc = REQUEST_OK;
	enum rpc_status err = ERROR_PARSE;
	struct dispatch_ubus *du = ctx->ubus;
	request_ctx_t *request = ctx->request;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->r->connection->log, 0,
		       "Start processing json object");

	cglcf = ngx_http_get_module_loc_conf(request->r, ngx_http_ubus_module);

	if (json_object_get_type(du->jsobj_cur) != json_type_object)
		goto error;

	blob_buf_init(ctx->buf, 0);
	if (!blobmsg_add_object(ctx->buf, du->jsobj_cur))
		goto error;

	if (!parse_json_rpc(&data, ctx->buf->head))
		goto error;

	if (!strcmp(data.method, "call")) {
		if (!data.sid || !data.object || !data.function || !data.data)
			goto error;

		du->func = data.function;

		if (ctx->array)
			sem_wait(ctx->request->sem);

		if (ubus_lookup_id(ctx->request->ubus_ctx, data.object, &du->obj)) {
			err = ERROR_OBJECT;
			goto error;
		}

		if (ctx->array)
			sem_post(ctx->request->sem);

		if (ctx->array)
			sem_wait(ctx->request->sem);

		if (!cglcf->noauth && !ubus_allowed(ctx, cglcf->script_timeout, data.sid,
						    data.object, data.function)) {
			err = ERROR_ACCESS;
			goto error;
		}

		if (ctx->array)
			sem_post(ctx->request->sem);

		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->r->connection->log, 0,
			       "Start processing call request");

		rc = ubus_send_request(request, ctx, data.sid, data.data);
		goto out;
	} else if (!strcmp(data.method, "list")) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->r->connection->log, 0,
			       "Start processing list request");

		rc = ubus_send_list(request, ctx, data.params);
		goto out;
	} else {
		err = ERROR_METHOD;
		goto error;
	}

error:
	if (ctx->array)
		sem_post(ctx->request->sem);
	rc = err;
out:
	if (data.params)
		free(data.params);

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->r->connection->log, 0,
		       "Json object processed correctly");

	if (rc != REQUEST_OK)
		*ctx->res_str = gen_error_from_du(ctx->request->r,
						  ctx->ubus, rc);

	if (array) {
		/* Signal thread has finished */
		sem_post(ctx->request->avail_thread);
		/* Signal obj has been processed */
		sem_post(ctx->request->obj_processed);
	}

	free_ubus_ctx_t(ctx, request->r);

	return rc;
}

static ngx_int_t ubus_process_array(request_ctx_t *request,
				    struct json_object *obj) {
	char **res_strs;
	ubus_ctx_t *ctx;
	int len, obj_num = 0;
	ngx_int_t rc = NGX_OK;
	struct json_object *obj_tmp;
	ngx_http_ubus_loc_conf_t *cglcf;

	cglcf = ngx_http_get_module_loc_conf(request->r, ngx_http_ubus_module);
	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->r->connection->log, 0,
		       "Start processing array json object");

	request->sem = ngx_pcalloc(request->r->pool, sizeof(*request->sem));
	request->avail_thread = ngx_pcalloc(request->r->pool, sizeof(*request->avail_thread));
	request->obj_processed = ngx_pcalloc(request->r->pool, sizeof(*request->obj_processed));

	sem_init(request->sem, 0, 1);
	sem_init(request->avail_thread, 0, cglcf->parallel_req);
	sem_init(request->obj_processed, 0, 0);

	len = json_object_array_length(obj);
	res_strs = ngx_pcalloc(request->r->pool, len * sizeof(*res_strs));

	for (obj_num = 0; obj_num < len; obj_num++) {
		pthread_t thread = { 0 };

		/* Wait for an available thread if all busy */
		sem_wait(request->avail_thread);

		obj_tmp = json_object_array_get_idx(obj, obj_num);

		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, request->r->connection->log, 0,
			       "Spawning thread %d to process request %d", concurrent,
			       obj_num);

		ctx = setup_ubus_ctx_t(request, obj_tmp);

		ctx->array = true;
		ctx->res_str = res_strs + obj_num;

		pthread_create(&thread, NULL, (void *)ubus_post_object, ctx);
	}

	/* Loop len time to make sure every thread completed and
	 * every obj has been processed.
	 */
	for (obj_num = 0; obj_num < len; obj_num++)
		sem_wait(request->obj_processed);

	append_to_output_chain(request, "[");

	for (obj_num = 0; obj_num < len; obj_num++) {
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, request->r->connection->log, 0,
			       "Writing output of index %d to body", concurrent);
		if (obj_num > 0)
			append_to_output_chain(request, ",");
		if (!res_strs[obj_num]) {
			obj_tmp = json_object_array_get_idx(obj, obj_num);
			res_strs[obj_num] = gen_error_from_obj(request->r, obj_tmp, ERROR_INTERNAL);
		}
		append_to_output_chain(request, res_strs[obj_num]);
		free(res_strs[obj_num]);
	}

	append_to_output_chain(request, "]");

	ngx_pfree(request->r->pool, res_strs);

	sem_destroy(request->sem);
	ngx_pfree(request->r->pool, request->sem);
	sem_destroy(request->avail_thread);
	ngx_pfree(request->r->pool, request->avail_thread);
	sem_destroy(request->obj_processed);
	ngx_pfree(request->r->pool, request->obj_processed);

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->r->connection->log, 0,
		       "Request processed correctly");

	return rc;
}

static ngx_int_t ubus_process_object(request_ctx_t *request,
				     struct json_object *obj) {
	char **res_str;
	ubus_ctx_t *ctx;
	enum rpc_status rc;

	res_str = ngx_pcalloc(request->r->pool, sizeof(*res_str));

	ctx = setup_ubus_ctx_t(request, obj);
	ctx->res_str = res_str;

	rc = ubus_post_object(ctx);

	append_to_output_chain(request, *res_str);

	free(*res_str);
	ngx_pfree(request->r->pool, res_str);
	return rc == REQUEST_OK ? NGX_OK : NGX_ERROR;
}

static ngx_int_t ngx_http_ubus_elaborate_req(request_ctx_t *request,
					     struct json_object *obj) {
	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->r->connection->log, 0,
		       "Analyzing json object");

	switch (obj ? json_object_get_type(obj) : json_type_null) {
	case json_type_object:

		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->r->connection->log, 0,
			       "Json object detected");

		return ubus_process_object(request, obj);
	case json_type_array:

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
	request_ctx_t *request;
	struct json_tokener *jstok;
	ngx_int_t rc = NGX_HTTP_OK;
	enum json_tokener_error jserr;
	ngx_http_ubus_loc_conf_t *cglcf;
	struct json_object *jsobj = NULL;

	cglcf = ngx_http_get_module_loc_conf(r, ngx_http_ubus_module);

	request = ngx_pcalloc(r->pool, sizeof(request_ctx_t));
	request->r = r;

	request->ubus_ctx = ubus_connect((char *)cglcf->socket_path.data);

	if (!request->ubus_ctx) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			      "Unable to connect to ubus socket: %s",
			      cglcf->socket_path.data);
		ubus_single_error(request, ERROR_INTERNAL);
		goto finalize;
	}

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

	if (pos != r->headers_in.content_length_n) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			      "Readed buffer differ from header request len");
		ubus_single_error(request, ERROR_PARSE);
		goto free_tok;
	}

	rc = ngx_http_ubus_elaborate_req(request, jsobj);

	if (rc == NGX_ERROR) {
		// With ngx_error we are sending json error
		// and we say that the request is ok
		rc = NGX_HTTP_OK;
		goto free_obj;
	}

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Sending header");

	rc = ngx_http_ubus_send_header(r, cglcf, NGX_HTTP_OK, request->res_len);
	if (rc == NGX_ERROR || rc > NGX_OK)
		goto finalize;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Sending body");

	rc = ngx_http_ubus_send_body(request);

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Request complete");

free_obj:
	json_object_put(jsobj);
free_tok:
	json_tokener_free(jstok);
free_ubus:
	ubus_free(request->ubus_ctx);
finalize:
	ngx_pfree(r->pool, request);
	ngx_http_finalize_request(r, rc);
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

	return NGX_CONF_OK;
}
