/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2024 Intel Corporation.
 *   All rights reserved.
 */

#ifndef SPDK_BDEV_DUALTIER_H
#define SPDK_BDEV_DUALTIER_H

#include <spdk/stdinc.h>
#include <spdk/bdev_module.h>
#include <spdk/uuid.h>

/* DualTier bdev的状态 */
enum dualtier_bdev_state {
    DUALTIER_BDEV_STATE_ONLINE = 0,
    DUALTIER_BDEV_STATE_OFFLINE = 1,
};

/* 定义存储层级 */
enum dualtier_tier_type {
    DUALTIER_TIER_FAST = 0,  /* 高速存储层 */
    DUALTIER_TIER_SLOW = 1,  /* 低速存储层 */
};

/* DualTier bdev的配置信息 */
struct dualtier_bdev_config {
    char *name;                      /* DualTier卷的名称 */
    struct spdk_uuid uuid;          /* DualTier卷的UUID */
    char *fast_bdev;                /* 高速bdev的名称 */
    char *slow_bdev;                /* 低速bdev的名称 */
    enum dualtier_bdev_state state; /* DualTier卷的状态 */
};

/* DualTier bdev的主要数据结构 */
struct dualtier_bdev {
    struct dualtier_bdev_config config;     /* 配置信息 */
    struct spdk_bdev_desc *fast_desc;       /* 快速层描述符 */
    struct spdk_bdev_desc *slow_desc;       /* 慢速层描述符 */
    struct spdk_bdev bdev;                  /* 基础bdev结构 */
    TAILQ_ENTRY(dualtier_bdev) link;       /* 链表项 */
};

/* DualTier bdev的IO请求结构 */
struct dualtier_bdev_io {
    enum dualtier_tier_type tier;           /* IO请求的目标层级 */
    struct spdk_bdev_io_wait_entry bdev_io_wait; /* IO等待项 */
    struct dualtier_bdev *dualtier_bdev;    /* 对应的DualTier bdev */
    struct spdk_bdev_io *bdev_io;           /* 基础IO请求 */
};

/* DualTier bdev的IO通道结构 */
struct dualtier_bdev_channel {
    struct spdk_io_channel *fast_ch;        /* 高速bdev的IO通道 */
    struct spdk_io_channel *slow_ch;        /* 低速bdev的IO通道 */
};

/* 模块初始化函数 */
int dualtier_bdev_init(void);

/* 模块清理函数 */
void dualtier_bdev_finish(void);

/* 创建DualTier bdev */
int dualtier_bdev_create(const char *name, const char *fast_bdev, 
                        const char *slow_bdev);

/* 删除DualTier bdev */
int dualtier_bdev_delete(const char *name);

/* bdev销毁函数 */
int dualtier_bdev_destruct(void *ctx);

/* 确保IO结构大小合适 */
static_assert(sizeof(struct dualtier_bdev_io) <= SPDK_BDEV_LARGE_BUF_MAX_SIZE,
              "dualtier_bdev_io structure size exceeds maximum allowed size");

#endif /* SPDK_BDEV_DUALTIER_H */ 