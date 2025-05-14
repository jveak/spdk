/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2024 Intel Corporation.
 *   All rights reserved.
 */

#include "bdev_dualtier.h"
#include "spdk/rpc.h"
#include "spdk/util.h"
#include "spdk/string.h"
#include "spdk/log.h"

/* DualTier bdev列表 */
static TAILQ_HEAD(, dualtier_bdev) g_dualtier_bdev_list = TAILQ_HEAD_INITIALIZER(g_dualtier_bdev_list);

/* SPDK bdev模块结构 */
static struct spdk_bdev_module dualtier_if = {
    .name = "dualtier",
    .module_init = dualtier_bdev_init,
    .module_fini = dualtier_bdev_finish,
    .async_fini = false,
};

SPDK_BDEV_MODULE_REGISTER(dualtier, &dualtier_if)

/* IO完成回调函数 */
static void
dualtier_bdev_io_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
    struct dualtier_bdev_io *dualtier_io = cb_arg;
    struct spdk_bdev_io *parent_io = dualtier_io->bdev_io;

    spdk_bdev_free_io(bdev_io);
    spdk_bdev_io_complete(parent_io, success);
    free(dualtier_io);
}

/* 提交IO请求 */
static void
dualtier_bdev_submit_request(struct spdk_io_channel *ch, struct spdk_bdev_io *bdev_io)
{
    struct dualtier_bdev_channel *dualtier_ch = spdk_io_channel_get_ctx(ch);
    struct dualtier_bdev *dualtier_bdev = bdev_io->bdev->ctxt;
    struct dualtier_bdev_io *dualtier_io;
    int rc = 0;

    dualtier_io = calloc(1, sizeof(*dualtier_io));
    if (!dualtier_io) {
        spdk_bdev_io_complete(bdev_io, false);
        return;
    }

    dualtier_io->dualtier_bdev = dualtier_bdev;
    dualtier_io->bdev_io = bdev_io;

    /* 根据IO类型和目标层级选择合适的bdev和channel */
    struct spdk_bdev_desc *desc;
    struct spdk_io_channel *io_ch;
    
    /* 从IO控制信息中获取目标层级 */
    dualtier_io->tier = (enum dualtier_tier_type)bdev_io->u.bdev.ext_opts->metadata;
    
    if (dualtier_io->tier == DUALTIER_TIER_FAST) {
        desc = dualtier_bdev->fast_desc;
        io_ch = dualtier_ch->fast_ch;
    } else {
        desc = dualtier_bdev->slow_desc;
        io_ch = dualtier_ch->slow_ch;
    }

    switch (bdev_io->type) {
    case SPDK_BDEV_IO_TYPE_READ:
        rc = spdk_bdev_read_blocks(desc, io_ch,
                                 bdev_io->u.bdev.iovs,
                                 bdev_io->u.bdev.iovcnt,
                                 bdev_io->u.bdev.offset_blocks,
                                 bdev_io->u.bdev.num_blocks,
                                 dualtier_bdev_io_complete,
                                 dualtier_io);
        break;
    case SPDK_BDEV_IO_TYPE_WRITE:
        rc = spdk_bdev_write_blocks(desc, io_ch,
                                  bdev_io->u.bdev.iovs,
                                  bdev_io->u.bdev.iovcnt,
                                  bdev_io->u.bdev.offset_blocks,
                                  bdev_io->u.bdev.num_blocks,
                                  dualtier_bdev_io_complete,
                                  dualtier_io);
        break;
    default:
        rc = -ENOTSUP;
    }

    if (rc != 0) {
        free(dualtier_io);
        spdk_bdev_io_complete(bdev_io, false);
    }
}

/* 获取IO通道 */
static struct spdk_io_channel *
dualtier_bdev_get_io_channel(void *ctx)
{
    struct dualtier_bdev *dualtier_bdev = ctx;
    return spdk_get_io_channel(dualtier_bdev);
}

/* 创建IO通道 */
static int
dualtier_bdev_create_cb(void *io_device, void *ctx_buf)
{
    struct dualtier_bdev *dualtier_bdev = io_device;
    struct dualtier_bdev_channel *dualtier_ch = ctx_buf;

    dualtier_ch->fast_ch = spdk_bdev_get_io_channel(dualtier_bdev->fast_desc);
    if (!dualtier_ch->fast_ch) {
        return -1;
    }

    dualtier_ch->slow_ch = spdk_bdev_get_io_channel(dualtier_bdev->slow_desc);
    if (!dualtier_ch->slow_ch) {
        spdk_put_io_channel(dualtier_ch->fast_ch);
        return -1;
    }

    return 0;
}

/* 销毁IO通道 */
static void
dualtier_bdev_destroy_cb(void *io_device, void *ctx_buf)
{
    struct dualtier_bdev_channel *dualtier_ch = ctx_buf;

    spdk_put_io_channel(dualtier_ch->fast_ch);
    spdk_put_io_channel(dualtier_ch->slow_ch);
}

/* bdev操作函数表 */
static const struct spdk_bdev_fn_table dualtier_fn_table = {
    .destruct = dualtier_bdev_destruct,
    .submit_request = dualtier_bdev_submit_request,
    .get_io_channel = dualtier_bdev_get_io_channel,
};

/* 创建DualTier bdev */
int
dualtier_bdev_create(const char *name, const char *fast_bdev, const char *slow_bdev)
{
    struct dualtier_bdev *dualtier_bdev;
    int rc;

    dualtier_bdev = calloc(1, sizeof(*dualtier_bdev));
    if (!dualtier_bdev) {
        return -ENOMEM;
    }

    /* 设置配置信息 */
    dualtier_bdev->config.name = strdup(name);
    dualtier_bdev->config.fast_bdev = strdup(fast_bdev);
    dualtier_bdev->config.slow_bdev = strdup(slow_bdev);
    if (!dualtier_bdev->config.name || !dualtier_bdev->config.fast_bdev || 
        !dualtier_bdev->config.slow_bdev) {
        rc = -ENOMEM;
        goto error_alloc;
    }

    /* 打开基础bdev */
    rc = spdk_bdev_open_ext(fast_bdev, true, NULL, NULL, &dualtier_bdev->fast_desc);
    if (rc) {
        goto error_open_fast;
    }

    rc = spdk_bdev_open_ext(slow_bdev, true, NULL, NULL, &dualtier_bdev->slow_desc);
    if (rc) {
        goto error_open_slow;
    }

    /* 初始化bdev结构 */
    dualtier_bdev->bdev.name = dualtier_bdev->config.name;
    dualtier_bdev->bdev.product_name = "DualTier Disk";
    dualtier_bdev->bdev.write_cache = 0;
    dualtier_bdev->bdev.blocklen = spdk_bdev_get_block_size(spdk_bdev_desc_get_bdev(dualtier_bdev->fast_desc));
    dualtier_bdev->bdev.blockcnt = spdk_bdev_get_num_blocks(spdk_bdev_desc_get_bdev(dualtier_bdev->fast_desc));
    dualtier_bdev->bdev.required_alignment = spdk_bdev_get_buf_align(spdk_bdev_desc_get_bdev(dualtier_bdev->fast_desc));
    dualtier_bdev->bdev.ctxt = dualtier_bdev;
    dualtier_bdev->bdev.module = &dualtier_if;
    dualtier_bdev->bdev.fn_table = &dualtier_fn_table;

    spdk_uuid_generate(&dualtier_bdev->config.uuid);
    dualtier_bdev->config.state = DUALTIER_BDEV_STATE_ONLINE;

    /* 注册bdev */
    rc = spdk_bdev_register(&dualtier_bdev->bdev);
    if (rc) {
        goto error_register;
    }

    /* 注册IO通道 */
    spdk_io_device_register(dualtier_bdev, dualtier_bdev_create_cb,
                           dualtier_bdev_destroy_cb,
                           sizeof(struct dualtier_bdev_channel),
                           name);

    /* 添加到列表 */
    TAILQ_INSERT_TAIL(&g_dualtier_bdev_list, dualtier_bdev, link);

    return 0;

error_register:
    spdk_bdev_close(dualtier_bdev->slow_desc);
error_open_slow:
    spdk_bdev_close(dualtier_bdev->fast_desc);
error_open_fast:
error_alloc:
    free(dualtier_bdev->config.name);
    free(dualtier_bdev->config.fast_bdev);
    free(dualtier_bdev->config.slow_bdev);
    free(dualtier_bdev);
    return rc;
}

/* 删除DualTier bdev */
int
dualtier_bdev_delete(const char *name)
{
    struct dualtier_bdev *dualtier_bdev;

    TAILQ_FOREACH(dualtier_bdev, &g_dualtier_bdev_list, link) {
        if (strcmp(dualtier_bdev->config.name, name) == 0) {
            spdk_bdev_unregister(&dualtier_bdev->bdev, NULL, NULL);
            return 0;
        }
    }

    return -ENODEV;
}

/* 销毁DualTier bdev */
static int
dualtier_bdev_destruct(void *ctx)
{
    struct dualtier_bdev *dualtier_bdev = ctx;

    TAILQ_REMOVE(&g_dualtier_bdev_list, dualtier_bdev, link);
    spdk_io_device_unregister(dualtier_bdev, NULL);
    spdk_bdev_close(dualtier_bdev->fast_desc);
    spdk_bdev_close(dualtier_bdev->slow_desc);
    free(dualtier_bdev->config.name);
    free(dualtier_bdev->config.fast_bdev);
    free(dualtier_bdev->config.slow_bdev);
    free(dualtier_bdev);

    return 0;
}

/* 模块初始化 */
int
dualtier_bdev_init(void)
{
    return 0;
}

/* 模块清理 */
void
dualtier_bdev_finish(void)
{
    struct dualtier_bdev *dualtier_bdev, *tmp;

    TAILQ_FOREACH_SAFE(dualtier_bdev, &g_dualtier_bdev_list, link, tmp) {
        spdk_bdev_unregister(&dualtier_bdev->bdev, NULL, NULL);
    }
} 