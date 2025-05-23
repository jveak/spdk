/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2023 Intel Corporation.
 *   All rights reserved.
 */

#include "spdk/rpc.h"
#include "spdk/util.h"    // For SPDK_COUNTOF, spdk_min, spdk_max
#include "spdk/string.h"  // For spdk_strerror
#include "spdk/bdev_module.h" 
#include "vbdev_dualtier.h" 

#include "spdk/log.h" 
#include <stdlib.h>     // For calloc/free

struct rpc_construct_dualtier_bdev {
    char *name;
    char *fast_bdev_name;
    char *slow_bdev_name;
};

static const struct spdk_json_object_decoder rpc_construct_dualtier_bdev_decoders[] = {
    {"name", offsetof(struct rpc_construct_dualtier_bdev, name), spdk_json_decode_string},
    {"fast_bdev_name", offsetof(struct rpc_construct_dualtier_bdev, fast_bdev_name), spdk_json_decode_string},
    {"slow_bdev_name", offsetof(struct rpc_construct_dualtier_bdev, slow_bdev_name), spdk_json_decode_string},
};

static void
free_rpc_construct_dualtier_bdev(struct rpc_construct_dualtier_bdev *req)
{
    free(req->name);
    free(req->fast_bdev_name);
    free(req->slow_bdev_name);
}

static void
spdk_rpc_construct_dualtier_bdev(struct spdk_jsonrpc_request *request,
                  const struct spdk_json_val *params)
{
    struct rpc_construct_dualtier_bdev req = {0};
    struct spdk_json_write_ctx *w;
    int rc;

    if (spdk_json_decode_object(params, rpc_construct_dualtier_bdev_decoders,
                   SPDK_COUNTOF(rpc_construct_dualtier_bdev_decoders),
                   &req)) {
        SPDK_ERRLOG("spdk_json_decode_object failed for construct_dualtier_bdev\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS, "Invalid parameters");
        free_rpc_construct_dualtier_bdev(&req);
        return;
    }

    if (req.name == NULL || req.fast_bdev_name == NULL || req.slow_bdev_name == NULL) {
        SPDK_ERRLOG("Missing required parameters name, fast_bdev_name, or slow_bdev_name\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS, "Missing parameters");
        free_rpc_construct_dualtier_bdev(&req);
        return;
    }
    
    rc = bdev_dualtier_create_disk(req.name, req.fast_bdev_name, req.slow_bdev_name);
    if (rc != 0) {
        spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
        free_rpc_construct_dualtier_bdev(&req);
        return;
    }

    w = spdk_jsonrpc_begin_result(request);
    spdk_json_write_string(w, req.name); 
    spdk_jsonrpc_end_result(request, w);
    free_rpc_construct_dualtier_bdev(&req);
}
SPDK_RPC_REGISTER("construct_dualtier_bdev", spdk_rpc_construct_dualtier_bdev, SPDK_RPC_RUNTIME)

struct rpc_delete_dualtier_bdev {
    char *name;
};

static const struct spdk_json_object_decoder rpc_delete_dualtier_bdev_decoders[] = {
    {"name", offsetof(struct rpc_delete_dualtier_bdev, name), spdk_json_decode_string},
};

static void
free_rpc_delete_dualtier_bdev(struct rpc_delete_dualtier_bdev *req)
{
    free(req->name);
}

struct delete_dualtier_bdev_ctx {
    struct rpc_delete_dualtier_bdev req;
    struct spdk_jsonrpc_request *request;
};

static void
delete_dualtier_bdev_done(void *cb_arg, int bdeverrno)
{
    struct delete_dualtier_bdev_ctx *ctx = cb_arg;
    struct spdk_jsonrpc_request *request = ctx->request;
    struct spdk_json_write_ctx *w;

    if (bdeverrno != 0) {
        spdk_jsonrpc_send_error_response(request, bdeverrno, spdk_strerror(-bdeverrno));
        free_rpc_delete_dualtier_bdev(&ctx->req);
        free(ctx);
        return;
    }

    w = spdk_jsonrpc_begin_result(request);
    spdk_json_write_bool(w, true);
    spdk_jsonrpc_end_result(request, w);
    free_rpc_delete_dualtier_bdev(&ctx->req);
    free(ctx);
}

static void
spdk_rpc_delete_dualtier_bdev(struct spdk_jsonrpc_request *request,
                const struct spdk_json_val *params)
{
    struct delete_dualtier_bdev_ctx *ctx;

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        spdk_jsonrpc_send_error_response(request, -ENOMEM, "Unable to allocate context for delete RPC");
        return;
    }

    if (spdk_json_decode_object(params, rpc_delete_dualtier_bdev_decoders,
                   SPDK_COUNTOF(rpc_delete_dualtier_bdev_decoders),
                   &ctx->req)) {
        SPDK_ERRLOG("spdk_json_decode_object failed for delete_dualtier_bdev\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS, "Invalid parameters");
        free(ctx); // req members not allocated yet from spdk_json_decode_string
        return;
    }
    
    if (ctx->req.name == NULL) {
        SPDK_ERRLOG("Missing required parameter name for delete_dualtier_bdev\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS, "Missing name parameter");
        // free_rpc_delete_dualtier_bdev(&ctx->req); // name is NULL
        free(ctx);
        return;
    }

    ctx->request = request;
    bdev_dualtier_delete_disk(ctx->req.name, delete_dualtier_bdev_done, ctx);
}
SPDK_RPC_REGISTER("delete_dualtier_bdev", spdk_rpc_delete_dualtier_bdev, SPDK_RPC_RUNTIME)
