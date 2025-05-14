/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2024 Intel Corporation.
 *   All rights reserved.
 */

#include <spdk/stdinc.h>
#include "bdev_dualtier.h"
#include <spdk/rpc.h>
#include <spdk/util.h>
#include <spdk/string.h>
#include <spdk/log.h>

/* RPC命令参数结构 */
struct rpc_create_dualtier {
    char *name;           /* DualTier卷名称 */
    char *fast_bdev;      /* 高速bdev名称 */
    char *slow_bdev;      /* 低速bdev名称 */
};

/* RPC删除命令参数结构 */
struct rpc_delete_dualtier {
    char *name;           /* 要删除的DualTier卷名称 */
};

/* 释放创建命令参数 */
static void
free_rpc_create_dualtier(struct rpc_create_dualtier *req)
{
    if (!req) {
        return;
    }
    free(req->name);
    free(req->fast_bdev);
    free(req->slow_bdev);
}

/* 释放删除命令参数 */
static void
free_rpc_delete_dualtier(struct rpc_delete_dualtier *req)
{
    if (!req) {
        return;
    }
    free(req->name);
}

/* 创建命令参数解码器 */
static const struct spdk_json_object_decoder rpc_create_dualtier_decoders[] = {
    {"name", offsetof(struct rpc_create_dualtier, name), spdk_json_decode_string},
    {"fast_bdev", offsetof(struct rpc_create_dualtier, fast_bdev), spdk_json_decode_string},
    {"slow_bdev", offsetof(struct rpc_create_dualtier, slow_bdev), spdk_json_decode_string},
};

/* 删除命令参数解码器 */
static const struct spdk_json_object_decoder rpc_delete_dualtier_decoders[] = {
    {"name", offsetof(struct rpc_delete_dualtier, name), spdk_json_decode_string},
};

/* 创建DualTier bdev的RPC处理函数 */
static void
rpc_bdev_dualtier_create(struct spdk_jsonrpc_request *request,
                         const struct spdk_json_val *params)
{
    struct rpc_create_dualtier req = {};
    struct spdk_json_write_ctx *w;
    int rc;

    if (!request || !params) {
        SPDK_ERRLOG("Invalid RPC parameters\n");
        return;
    }

    if (spdk_json_decode_object(params, rpc_create_dualtier_decoders,
                               SPDK_COUNTOF(rpc_create_dualtier_decoders),
                               &req)) {
        SPDK_ERRLOG("spdk_json_decode_object failed\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
                                       "Invalid parameters");
        return;
    }

    rc = dualtier_bdev_create(req.name, req.fast_bdev, req.slow_bdev);
    if (rc != 0) {
        SPDK_ERRLOG("Failed to create dualtier bdev: %s\n", spdk_strerror(-rc));
        spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
        goto cleanup;
    }

    w = spdk_jsonrpc_begin_result(request);
    if (!w) {
        SPDK_ERRLOG("Failed to begin JSON response\n");
        goto cleanup;
    }
    spdk_json_write_string(w, req.name);
    spdk_jsonrpc_end_result(request, w);

cleanup:
    free_rpc_create_dualtier(&req);
}

/* 删除DualTier bdev的RPC处理函数 */
static void
rpc_bdev_dualtier_delete(struct spdk_jsonrpc_request *request,
                         const struct spdk_json_val *params)
{
    struct rpc_delete_dualtier req = {};
    struct spdk_json_write_ctx *w;
    int rc;

    if (!request || !params) {
        SPDK_ERRLOG("Invalid RPC parameters\n");
        return;
    }

    if (spdk_json_decode_object(params, rpc_delete_dualtier_decoders,
                               SPDK_COUNTOF(rpc_delete_dualtier_decoders),
                               &req)) {
        SPDK_ERRLOG("spdk_json_decode_object failed\n");
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
                                       "Invalid parameters");
        return;
    }

    rc = dualtier_bdev_delete(req.name);
    if (rc != 0) {
        SPDK_ERRLOG("Failed to delete dualtier bdev: %s\n", spdk_strerror(-rc));
        spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
        goto cleanup;
    }

    w = spdk_jsonrpc_begin_result(request);
    if (!w) {
        SPDK_ERRLOG("Failed to begin JSON response\n");
        goto cleanup;
    }
    spdk_json_write_bool(w, true);
    spdk_jsonrpc_end_result(request, w);

cleanup:
    free_rpc_delete_dualtier(&req);
}

/* 注册RPC方法 */
SPDK_RPC_REGISTER("bdev_dualtier_create", rpc_bdev_dualtier_create, SPDK_RPC_RUNTIME)
SPDK_RPC_REGISTER("bdev_dualtier_delete", rpc_bdev_dualtier_delete, SPDK_RPC_RUNTIME) 