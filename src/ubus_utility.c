
/* 
 *	BSD 3-Clause License
 *
 *	Copyright (c) 2019, Christian Marangi
 * 	All rights reserved. 
 */

#include <ubus_utility.h>

bool parse_json_rpc(struct rpc_data *d, struct blob_attr *data) {
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

void ubus_init_response(struct blob_buf *buf, struct dispatch_ubus *du) {
    struct json_object *obj = du->jsobj_cur, *obj2 = NULL;

    blob_buf_init(buf, 0);
    blobmsg_add_string(buf, "jsonrpc", "2.0");

    if (obj)
        json_object_object_get_ex(obj, "id", &obj2);

    if (obj2)
        blobmsg_add_json_element(buf, "id", obj2);
    else
        blobmsg_add_field(buf, BLOBMSG_TYPE_UNSPEC, "id", NULL, 0);
}

void ubus_allowed_cb(struct ubus_request *req,
    int type, struct blob_attr *msg) {
    struct blob_attr *tb[__SES_MAX];
    bool *allow = (bool *)req->priv;

    if (!msg)
        return;

    blobmsg_parse(ses_policy, __SES_MAX, tb, blob_data(msg), blob_len(msg));

    if (tb[SES_ACCESS])
        *allow = blobmsg_get_bool(tb[SES_ACCESS]);
}

void ubus_request_cb(struct ubus_request *req, int type,
    struct blob_attr *msg) {
    ubus_ctx_t *ctx = (ubus_ctx_t *)req->priv;
    struct dispatch_ubus *du = ctx->ubus;

    struct blob_attr *cur;
    void *r;
    int rem;
    int tes;

    blobmsg_add_field(du->buf, BLOBMSG_TYPE_TABLE, "",
        blob_data(msg), blob_len(msg));

    r = blobmsg_open_array(ctx->buf, "result");
    blobmsg_add_u32(ctx->buf, "", type);
    blob_for_each_attr(cur, du->buf->head, rem)
    blobmsg_add_blob(ctx->buf, cur);
    blobmsg_close_array(ctx->buf, r);
}

void ubus_list_cb(struct ubus_context *ctx,
    struct ubus_object_data *obj, void *priv) {
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

void ubus_close_fds(struct ubus_context *ctx) {
    if (ctx->sock.fd < 0)
        return;

    close(ctx->sock.fd);
    ctx->sock.fd = -1;
}
