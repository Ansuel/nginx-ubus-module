
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/avl.h>
#include <libubox/avl-cmp.h>

#include <libubus.h>
#include <json-c/json.h>

#define UBUS_MAX_POST_SIZE	65536
#define UBUS_DEFAULT_SID	"00000000000000000000000000000000"

static struct ubus_context *ctx;
static struct blob_buf buf;

struct dispatch_ubus {
	struct ubus_request req;

	struct json_tokener *jstok;
	struct json_object *jsobj;
	struct json_object *jsobj_cur;
	int post_len;

	uint32_t obj;
	const char *func;

	struct blob_buf buf;
	bool array;
	int array_idx;
};

static void* ngx_http_ubus_create_loc_conf(ngx_conf_t *cf);

static char* ngx_http_ubus_merge_loc_conf(ngx_conf_t *cf,
		void *parent, void *child);

typedef struct {
		ngx_str_t socket_path;
		ngx_flag_t cors;
		ngx_uint_t script_timeout;
		ngx_flag_t noauth;
		ngx_flag_t enable;
		ngx_uint_t req_len;
		ngx_uint_t res_len;
		ngx_chain_t* out_chain;
		ngx_chain_t* out_chain_start;
		struct dispatch_ubus ubus;
} ngx_http_ubus_loc_conf_t;

static ngx_int_t ngx_http_ubus_init(ngx_http_ubus_loc_conf_t *cf);

static char *
ngx_http_ubus(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t  ngx_http_ubus_commands[] = {
		{ ngx_string("ubus_interpreter"),
			NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
			ngx_http_ubus,
			NGX_HTTP_LOC_CONF_OFFSET,
			0,
			NULL },

		{ ngx_string("ubus_socket_path"),
			NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
			ngx_conf_set_str_slot,
			NGX_HTTP_LOC_CONF_OFFSET,
			offsetof(ngx_http_ubus_loc_conf_t, socket_path),
			NULL },

		{ ngx_string("ubus_cors"),
			NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
			ngx_conf_set_flag_slot,
			NGX_HTTP_LOC_CONF_OFFSET,
			offsetof(ngx_http_ubus_loc_conf_t, cors),
			NULL },

		{ ngx_string("ubus_script_timeout"),
			NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
			ngx_conf_set_num_slot,
			NGX_HTTP_LOC_CONF_OFFSET,
			offsetof(ngx_http_ubus_loc_conf_t, script_timeout),
			NULL },

		{ ngx_string("ubus_noauth"),
			NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
			ngx_conf_set_flag_slot,
			NGX_HTTP_LOC_CONF_OFFSET,
			offsetof(ngx_http_ubus_loc_conf_t, noauth),
			NULL },

			ngx_null_command
};


static ngx_http_module_t  ngx_http_ubus_module_ctx = {
		NULL,   /* preconfiguration */
		NULL,  /* postconfiguration */

		NULL,                          /* create main configuration */
		NULL,                          /* init main configuration */

		NULL,                          /* create server configuration */
		NULL,                          /* merge server configuration */

		ngx_http_ubus_create_loc_conf,  /* create location configuration */
		ngx_http_ubus_merge_loc_conf /* merge location configuration */
};


ngx_module_t  ngx_http_ubus_module = {
		NGX_MODULE_V1,
		&ngx_http_ubus_module_ctx, /* module context */
		ngx_http_ubus_commands,   /* module directives */
		NGX_HTTP_MODULE,               /* module type */
		NULL,                          /* init master */
		NULL,                          /* init module */
		NULL,                          /* init process */
		NULL,                          /* init thread */
		NULL,                          /* exit thread */
		NULL,                          /* exit process */
		NULL,                          /* exit master */
		NGX_MODULE_V1_PADDING
};

enum {
	RPC_JSONRPC,
	RPC_METHOD,
	RPC_PARAMS,
	RPC_ID,
	__RPC_MAX,
};

static const struct blobmsg_policy rpc_policy[__RPC_MAX] = {
	[RPC_JSONRPC] = { .name = "jsonrpc", .type = BLOBMSG_TYPE_STRING },
	[RPC_METHOD] = { .name = "method", .type = BLOBMSG_TYPE_STRING },
	[RPC_PARAMS] = { .name = "params", .type = BLOBMSG_TYPE_ARRAY },
	[RPC_ID] = { .name = "id", .type = BLOBMSG_TYPE_UNSPEC },
};

enum {
	SES_ACCESS,
	__SES_MAX,
};

static const struct blobmsg_policy ses_policy[__SES_MAX] = {
	[SES_ACCESS] = { .name = "access", .type = BLOBMSG_TYPE_BOOL },
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

struct cors_data {
	char* ORIGIN;
	char* ACCESS_CONTROL_REQUEST_METHOD;
	char* ACCESS_CONTROL_REQUEST_HEADERS;
};

struct list_data {
	bool verbose;
	struct blob_buf *buf;
};

enum rpc_error {
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
	[ERROR_PARSE] = { -32700, "Parse error" },
	[ERROR_REQUEST] = { -32600, "Invalid request" },
	[ERROR_METHOD] = { -32601, "Method not found" },
	[ERROR_PARAMS] = { -32602, "Invalid parameters" },
	[ERROR_INTERNAL] = { -32603, "Internal error" },
	[ERROR_OBJECT] = { -32000, "Object not found" },
	[ERROR_SESSION] = { -32001, "Session not found" },
	[ERROR_ACCESS] = { -32002, "Access denied" },
	[ERROR_TIMEOUT] = { -32003, "ubus request timed out" },
};

static void ubus_single_error(ngx_http_request_t *r, enum rpc_error type);
static ngx_int_t ngx_https_ubus_send_header(ngx_http_request_t *r, ngx_http_ubus_loc_conf_t  *cglcf, ngx_int_t status, ngx_int_t post_len);

static bool parse_json_rpc(struct rpc_data *d, struct blob_attr *data)
{
	const struct blobmsg_policy data_policy[] = {
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_TABLE },
	};
	struct blob_attr *tb[__RPC_MAX];
	struct blob_attr *tb2[4];
	struct blob_attr *cur;

	blobmsg_parse(rpc_policy, __RPC_MAX, tb, blob_data(data), blob_len(data));

	cur = tb[RPC_JSONRPC];
	if (!cur || strcmp(blobmsg_data(cur), "2.0") != 0)
		return false;

	cur = tb[RPC_METHOD];
	if (!cur)
		return false;

	d->id = tb[RPC_ID];
	d->method = blobmsg_data(cur);

	cur = tb[RPC_PARAMS];
	if (!cur)
		return true;

	d->params = blob_memdup(cur);
	if (!d->params)
		return false;

	blobmsg_parse_array(data_policy, ARRAY_SIZE(data_policy), tb2,
					blobmsg_data(d->params), blobmsg_data_len(d->params));

	if (tb2[0])
		d->sid = blobmsg_data(tb2[0]);

	if (!d->sid || !*d->sid)
		d->sid = UBUS_DEFAULT_SID;

	if (tb2[1])
		d->object = blobmsg_data(tb2[1]);

	if (tb2[2])
		d->function = blobmsg_data(tb2[2]);

	d->data = tb2[3];

	return true;
}

static void ubus_allowed_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr *tb[__SES_MAX];
	bool *allow = (bool *)req->priv;

	if (!msg)
		return;

	blobmsg_parse(ses_policy, __SES_MAX, tb, blob_data(msg), blob_len(msg));

	if (tb[SES_ACCESS])
		*allow = blobmsg_get_bool(tb[SES_ACCESS]);
}

static bool ubus_allowed(ngx_http_ubus_loc_conf_t  *cglcf, const char *sid, const char *obj, const char *fun)
{
	uint32_t id;
	bool allow = false;
	static struct blob_buf req;

	if (ubus_lookup_id(ctx, "session", &id))
		return false;

	blob_buf_init(&req, 0);
	blobmsg_add_string(&req, "ubus_rpc_session", sid);
	blobmsg_add_string(&req, "object", obj);
	blobmsg_add_string(&req, "function", fun);
	ubus_invoke(ctx, id, "access", req.head, ubus_allowed_cb, &allow, cglcf->script_timeout * 500);

	return allow;
}

static void ubus_init_response(struct dispatch_ubus *du)
{
	struct json_object *obj = du->jsobj_cur, *obj2 = NULL;

	blob_buf_init(&buf, 0);
	blobmsg_add_string(&buf, "jsonrpc", "2.0");

	if (obj)
		json_object_object_get_ex(obj, "id", &obj2);

	if (obj2)
		blobmsg_add_json_element(&buf, "id", obj2);
	else
		blobmsg_add_field(&buf, BLOBMSG_TYPE_UNSPEC, "id", NULL, 0);
}

static ngx_int_t append_to_output_chain(ngx_http_request_t *r, ngx_http_ubus_loc_conf_t *cglcf, const char* str)
{
	ngx_int_t len = strlen(str);

	char* data = ngx_pcalloc(r->pool, len + 1);
	ngx_memcpy(data,str,len);

	ngx_buf_t *b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
	b->pos = data;
	b->last = data + len;
	b->memory = 1;
	cglcf->res_len += len;

	// da controllare se bisogna spezzettare dati confronto tra bufer max e lunghezza dato
	if (!cglcf->out_chain) {
			cglcf->out_chain = (ngx_chain_t *) ngx_palloc(r->pool, sizeof(ngx_chain_t*));
			cglcf->out_chain->buf = b;
			cglcf->out_chain->next = NULL;
			cglcf->out_chain_start = cglcf->out_chain;
	} else {
			ngx_chain_t* out_aux = (ngx_chain_t *) ngx_palloc(r->pool, sizeof(ngx_chain_t*));
			out_aux->buf = b;
			out_aux->next = NULL;
			cglcf->out_chain->next = out_aux;
			cglcf->out_chain = out_aux;
	}
}

static void
ubus_request_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct dispatch_ubus *du = (struct dispatch_ubus *)req->priv;

	struct blob_attr *cur;
	void *r;
	int rem;

	blobmsg_add_field(&du->buf, BLOBMSG_TYPE_TABLE, "", blob_data(msg), blob_len(msg));

	r = blobmsg_open_array(&buf, "result");
	blobmsg_add_u32(&buf, "", type);
	blob_for_each_attr(cur, du->buf.head, rem)
	blobmsg_add_blob(&buf, cur);
	blobmsg_close_array(&buf, r);
}

static ngx_int_t ubus_send_request(ngx_http_request_t *r, json_object *obj, const char *sid, struct blob_attr *args)
{
	ngx_http_ubus_loc_conf_t  *cglcf;
	cglcf = ngx_http_get_module_loc_conf(r, ngx_http_ubus_module);

	struct dispatch_ubus *du = &cglcf->ubus;
	struct blob_attr *cur;
	static struct blob_buf req;
	int ret, rem;

	char *str;

	blob_buf_init(&req, 0);

	ubus_init_response(du);

	blobmsg_for_each_attr(cur, args, rem) {
		if (!strcmp(blobmsg_name(cur), "ubus_rpc_session")) {
			ubus_single_error(r, ERROR_PARAMS);
			return NGX_ERROR;
		}
		blobmsg_add_blob(&req, cur);
	}

	blobmsg_add_string(&req, "ubus_rpc_session", sid);

	blob_buf_init(&du->buf, 0);
	memset(&du->req, 0, sizeof(du->req));

	ubus_invoke(ctx, du->obj, du->func, req.head, ubus_request_cb, du, cglcf->script_timeout * 1000);

	str = blobmsg_format_json(buf.head, true);
	append_to_output_chain(r,cglcf,str);

	return NGX_OK;
}

static void ubus_list_cb(struct ubus_context *ctx, struct ubus_object_data *obj, void *priv)
{
	struct blob_attr *sig, *attr;
	struct list_data *data = priv;
	int rem, rem2;
	void *t, *o;

	if (!data->verbose) {
		blobmsg_add_string(data->buf, NULL, obj->path);
		return;
	}

	if (!obj->signature)
		return;

	o = blobmsg_open_table(data->buf, obj->path);
	blob_for_each_attr(sig, obj->signature, rem) {
		t = blobmsg_open_table(data->buf, blobmsg_name(sig));
		rem2 = blobmsg_data_len(sig);
		__blob_for_each_attr(attr, blobmsg_data(sig), rem2) {
			if (blob_id(attr) != BLOBMSG_TYPE_INT32)
				continue;

			switch (blobmsg_get_u32(attr)) {
			case BLOBMSG_TYPE_INT8:
				blobmsg_add_string(data->buf, blobmsg_name(attr), "boolean");
				break;
			case BLOBMSG_TYPE_INT32:
				blobmsg_add_string(data->buf, blobmsg_name(attr), "number");
				break;
			case BLOBMSG_TYPE_STRING:
				blobmsg_add_string(data->buf, blobmsg_name(attr), "string");
				break;
			case BLOBMSG_TYPE_ARRAY:
				blobmsg_add_string(data->buf, blobmsg_name(attr), "array");
				break;
			case BLOBMSG_TYPE_TABLE:
				blobmsg_add_string(data->buf, blobmsg_name(attr), "object");
				break;
			default:
				blobmsg_add_string(data->buf, blobmsg_name(attr), "unknown");
				break;
			}
		}
		blobmsg_close_table(data->buf, t);
	}
	blobmsg_close_table(data->buf, o);
}

static ngx_int_t ubus_send_list(ngx_http_request_t *request, json_object *obj, struct blob_attr *params)
{
	struct blob_attr *cur, *dup;

	ngx_http_ubus_loc_conf_t  *cglcf;
	cglcf = ngx_http_get_module_loc_conf(request, ngx_http_ubus_module);

	struct dispatch_ubus *du = &cglcf->ubus;

	struct list_data data = { .buf = &du->buf, .verbose = false };
	void *r;
	int rem;

	char *str;

	blob_buf_init(data.buf, 0);

	ubus_init_response(du);

	if (!params || blob_id(params) != BLOBMSG_TYPE_ARRAY) {
		r = blobmsg_open_array(data.buf, "result");
		ubus_lookup(ctx, NULL, ubus_list_cb, &data);
		blobmsg_close_array(data.buf, r);
	}
	else {
		r = blobmsg_open_table(data.buf, "result");
		dup = blob_memdup(params);
		if (dup)
		{
			rem = blobmsg_data_len(dup);
			data.verbose = true;
			__blob_for_each_attr(cur, blobmsg_data(dup), rem)
				ubus_lookup(ctx, blobmsg_data(cur), ubus_list_cb, &data);
			free(dup);
		}
		blobmsg_close_table(data.buf, r);
	}

	blobmsg_add_blob(&buf, blob_data(data.buf->head));

	str = blobmsg_format_json(buf.head, true);
	append_to_output_chain(request,cglcf,str);

	return NGX_OK;
}

static ngx_int_t ubus_handle_request_object(ngx_http_request_t *r, struct json_object *obj)
{
	ngx_int_t rc = NGX_OK;
	ngx_http_ubus_loc_conf_t  *cglcf;
	cglcf = ngx_http_get_module_loc_conf(r, ngx_http_ubus_module);

	struct dispatch_ubus *du = &cglcf->ubus;
	struct rpc_data data = {};
	enum rpc_error err = ERROR_PARSE;

	if (json_object_get_type(obj) != json_type_object)
		goto error;

	du->jsobj_cur = obj;
	blob_buf_init(&buf, 0);
	if (!blobmsg_add_object(&buf, obj))
		goto error;

	if (!parse_json_rpc(&data, buf.head))
		goto error;

	if (!strcmp(data.method, "call")) {
		if (!data.sid || !data.object || !data.function || !data.data)
			goto error;

		du->func = data.function;
		if (ubus_lookup_id(ctx, data.object, &du->obj)) {
			err = ERROR_OBJECT;
			goto error;
		}

		if (!cglcf->noauth && !ubus_allowed(cglcf, data.sid, data.object, data.function)) {
			err = ERROR_ACCESS;
			goto error;
		}

		rc = ubus_send_request(r, obj, data.sid, data.data);
		goto out;
	}
	else if (!strcmp(data.method, "list")) {
		rc = ubus_send_list(r, obj, data.params);
		goto out;
	}
	else {
		err = ERROR_METHOD;
		goto error;
	}

error:
	ubus_single_error(r, err);
	rc = NGX_ERROR;
out:
	if (data.params)
		free(data.params);

	return rc;
}

static ngx_int_t ubus_next_batched_request(ngx_http_request_t *r, json_object *obj)
{
	ngx_http_ubus_loc_conf_t  *cglcf;
	ngx_int_t rc;
	cglcf = ngx_http_get_module_loc_conf(r, ngx_http_ubus_module);

	struct dispatch_ubus *du = &cglcf->ubus;

	int len = json_object_array_length(obj);
	int index;

	for (index = 0 ; index < len ; index++ ) {
		struct json_object *obj_tmp = json_object_array_get_idx(obj, index );

		if ( index > 0 )
			append_to_output_chain(r,cglcf,",");
		
		rc = ubus_handle_request_object(r, obj_tmp);

		ngx_pfree(r->pool,obj_tmp);

		if ( rc != NGX_OK )
			return rc;
	}
			
	append_to_output_chain(r,cglcf,"]");
	return NGX_OK;
}

static ngx_int_t ngx_http_ubus_elaborate_req(ngx_http_request_t *r)
{
	ngx_http_ubus_loc_conf_t  *cglcf;
	cglcf = ngx_http_get_module_loc_conf(r, ngx_http_ubus_module);
	struct dispatch_ubus *du = &cglcf->ubus;
	struct json_object *obj = du->jsobj;

	switch (obj ? json_object_get_type(obj) : json_type_null) {
		case json_type_object:
			return ubus_handle_request_object(r, obj);
		case json_type_array:
			append_to_output_chain(r,cglcf,"[");
			return ubus_next_batched_request(r, obj);
		default:
			ubus_single_error(r, ERROR_PARSE);
			return NGX_ERROR;
	}
}

static void ngx_http_ubus_read_req(ngx_http_request_t *r)
{
	off_t pos = 0;
	off_t len;
	ngx_chain_t  *in;
	ngx_http_ubus_loc_conf_t  *cglcf;
	cglcf = ngx_http_get_module_loc_conf(r, ngx_http_ubus_module);
	char *buffer = ngx_pcalloc(r->pool, cglcf->req_len);
	struct dispatch_ubus *du = &cglcf->ubus;
	
	if (du->jsobj || !du->jstok) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Error ubus struct not ok");
		ubus_single_error(r, ERROR_PARSE);
		ngx_http_finalize_request(r, NGX_HTTP_OK);
		return;
	}

	for (in = r->request_body->bufs; in; in = in->next) {

		len = ngx_buf_size(in->buf);
		ngx_memcpy(buffer + pos,in->buf->pos,len);
		pos += len;

		if (pos > UBUS_MAX_POST_SIZE) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Error max post size for ubus socket");
			ubus_single_error(r, ERROR_PARSE);
			ngx_pfree(r->pool,buffer);
			ngx_http_finalize_request(r, NGX_HTTP_OK);
			return;
		}
	}

	du->jsobj = json_tokener_parse_ex(du->jstok, buffer, pos);
	ngx_pfree(r->pool,buffer);
	du->post_len = pos;
}

static ngx_int_t set_custom_headers_out(ngx_http_request_t *r, const char *key_str, const char *value_str) {
    ngx_table_elt_t   *h;
	ngx_str_t key;
	ngx_str_t value;

	char * tmp;
	int len;

	len = strlen(key_str);
	tmp = ngx_palloc(r->pool,len + 1);
	ngx_memcpy(tmp,key_str,len);

	key.data = tmp;
	key.len = len;

	len = strlen(value_str);
	tmp = ngx_palloc(r->pool,len + 1);
	ngx_memcpy(tmp,value_str,len);

	value.data = tmp;
	value.len = len;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->key = key;
    h->value = value;
    h->hash = 1;

    return NGX_OK;
}

static void parse_cors_from_header(ngx_http_request_t *r, struct cors_data *cors) {
    ngx_list_part_t            *part;
    ngx_table_elt_t            *h;
    ngx_uint_t                  i;

	ngx_uint_t found_count = 0;

    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */ ; i++) {
		if ( found_count == 3 )
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
            cors->ORIGIN = h[i].key.data;
			found_count++;
        }
		else if (ngx_strcmp("access-control-request-method", h[i].key.data)) {
            cors->ACCESS_CONTROL_REQUEST_METHOD = h[i].key.data;
			found_count++;
        }
		else if (ngx_strcmp("access-control-request-headers", h[i].key.data)) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ok3");
            cors->ACCESS_CONTROL_REQUEST_HEADERS = h[i].key.data;
			found_count++;
        }

    }
}

static void ubus_add_cors_headers(ngx_http_request_t *r)
{
	struct cors_data *cors;

	cors = ngx_pcalloc(r->pool,sizeof(struct cors_data));
	parse_cors_from_header(r,cors);

	char* req;

	if (!cors->ORIGIN)
		return;

	if (cors->ACCESS_CONTROL_REQUEST_METHOD)
	{
		char *req = cors->ACCESS_CONTROL_REQUEST_METHOD;
		if (strcmp(req, "POST") && strcmp(req, "OPTIONS"))
			return;
	}

	set_custom_headers_out(r,"Access-Control-Allow-Origin",cors->ORIGIN);

	if (cors->ACCESS_CONTROL_REQUEST_HEADERS)
		set_custom_headers_out(r,"Access-Control-Allow-Headers",cors->ACCESS_CONTROL_REQUEST_HEADERS);

	set_custom_headers_out(r,"Access-Control-Allow-Methods","POST, OPTIONS");
	set_custom_headers_out(r,"Access-Control-Allow-Credentials","true");

	ngx_pfree(r->pool,cors);
}

static ngx_int_t ngx_https_ubus_send_header(ngx_http_request_t *r, ngx_http_ubus_loc_conf_t  *cglcf, ngx_int_t status, ngx_int_t post_len)
{
	r->headers_out.status = status;
	r->headers_out.content_type.len = sizeof("application/json") - 1;
	r->headers_out.content_type.data = (u_char *) "application/json";
	r->headers_out.content_length_n = post_len;

	if (cglcf->cors)
		ubus_add_cors_headers(r);

	return ngx_http_send_header(r);
	
}

static ngx_int_t ngx_https_ubus_send_body(ngx_http_request_t *r, ngx_http_ubus_loc_conf_t  *cglcf)
{
	cglcf->out_chain->buf->last_buf = 1;
	cglcf->ubus.jsobj = NULL;
	cglcf->ubus.jstok = json_tokener_new();

	return ngx_http_output_filter(r, cglcf->out_chain_start);
}

static void ubus_single_error(ngx_http_request_t *r, enum rpc_error type)
{
	void *c;
	char *str;
	ngx_http_ubus_loc_conf_t  *cglcf;
	cglcf = ngx_http_get_module_loc_conf(r, ngx_http_ubus_module);

	struct dispatch_ubus *du = &cglcf->ubus;

	ubus_init_response(du);

	c = blobmsg_open_table(&buf, "error");
	blobmsg_add_u32(&buf, "code", json_errors[type].code);
	blobmsg_add_string(&buf, "message", json_errors[type].msg);
	blobmsg_close_table(&buf, c);

	str = blobmsg_format_json(buf.head, true);
	append_to_output_chain(r,cglcf,str);

	ngx_https_ubus_send_header(r,cglcf,NGX_HTTP_OK,strlen(str));
	ngx_https_ubus_send_body(r,cglcf);
}

static ngx_int_t
ngx_http_ubus_handler(ngx_http_request_t *r)
{
	ngx_int_t     rc;

	ngx_http_ubus_loc_conf_t  *cglcf;
	cglcf = ngx_http_get_module_loc_conf(r, ngx_http_ubus_module);

	cglcf->out_chain = NULL;
	cglcf->res_len = 0;

	ctx = ubus_connect(cglcf->socket_path.data);

	if (!ctx) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to connect to ubus socket: %s", cglcf->socket_path.data);
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	
	switch (r->method)
	{
		case NGX_HTTP_OPTIONS:
			r->header_only = 1;
			ngx_https_ubus_send_header(r,cglcf,NGX_HTTP_OK,0);
			ngx_http_finalize_request(r,NGX_HTTP_OK);
			return NGX_OK;

		case NGX_HTTP_POST:

			blob_buf_init(&buf, 0);

			cglcf->req_len = r->headers_in.content_length_n;

			rc = ngx_http_read_client_request_body(r, ngx_http_ubus_read_req);
			if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
				return rc;
			}

			rc = ngx_http_ubus_elaborate_req(r);
			if (rc == NGX_ERROR) {
				// With ngx_error we are sending json error 
				// and we say that the request is ok
				return NGX_OK;
			}

			rc = ngx_https_ubus_send_header(r,cglcf,NGX_HTTP_OK,cglcf->res_len);
			if (rc == NGX_ERROR || rc > NGX_OK) {
				return rc;
			}

			return ngx_https_ubus_send_body(r,cglcf);

		default:
			return NGX_HTTP_BAD_REQUEST;
	}
}

static char *
ngx_http_ubus(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
		ngx_http_core_loc_conf_t  *clcf;
		ngx_http_ubus_loc_conf_t *cglcf = conf;

		clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
		clcf->handler = ngx_http_ubus_handler;

		cglcf->enable = 1;

		return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_ubus_init(ngx_http_ubus_loc_conf_t *conf)
{

		conf->ubus.jsobj = NULL;
		conf->ubus.jstok = json_tokener_new();

		return NGX_OK;
}

static void *
ngx_http_ubus_create_loc_conf(ngx_conf_t *cf)
{
		ngx_http_ubus_loc_conf_t  *conf;

		conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ubus_loc_conf_t));
		if (conf == NULL) {
				return NGX_CONF_ERROR;
		}

		conf->socket_path.data = NULL;
		conf->socket_path.len = -1;

		conf->cors = NGX_CONF_UNSET;
		conf->noauth = NGX_CONF_UNSET;
		conf->script_timeout = NGX_CONF_UNSET_UINT;
		conf->enable = NGX_CONF_UNSET;
		return conf;
}

static char *
ngx_http_ubus_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
		ngx_http_ubus_loc_conf_t *prev = parent;
		ngx_http_ubus_loc_conf_t *conf = child;

		// Skip merge of other, if we don't have a socket to connect...
		// We don't init the module at all.
		if (conf->socket_path.data == NULL)
				return NGX_CONF_OK;

		ngx_conf_merge_value(conf->cors, prev->cors, 0);
		ngx_conf_merge_value(conf->noauth, prev->noauth, 0);
		ngx_conf_merge_uint_value(conf->script_timeout, prev->script_timeout, 60);
		ngx_conf_merge_value(conf->enable, prev->enable, 0);

		if (conf->script_timeout == 0 ) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ubus script timeout must be greater than zero"); 
				return NGX_CONF_ERROR;
		}

		if (conf->enable)
				ngx_http_ubus_init(conf);

		return NGX_CONF_OK;
}