// SPDX-License-Identifier: BSD-3-Clause
// Copyright (C) 2023 Intel Corporation.

#ifndef VBDEV_DUALTIER_H
#define VBDEV_DUALTIER_H

#include "spdk/stdinc.h"
#include "spdk/queue.h"
#include "spdk/bdev_module.h" // For spdk_bdev_unregister_cb

// Forward declarations
struct spdk_bdev;
struct spdk_bdev_desc;
struct spdk_io_channel;
struct spdk_thread;

struct vbdev_dualtier {
	struct spdk_bdev        *fast_bdev; /* The fast base bdev */
	struct spdk_bdev_desc   *fast_desc; /* Descriptor for the fast base bdev */
	struct spdk_bdev        *slow_bdev; /* The slow base bdev */
	struct spdk_bdev_desc   *slow_desc; /* Descriptor for the slow base bdev */
	struct spdk_bdev        dt_bdev;    /* The dualtier virtual bdev */
	TAILQ_ENTRY(vbdev_dualtier) link;   /* Entry in global list of dualtier bdevs */
	struct spdk_thread      *thread;    /* Thread where base devices were opened */
};

struct dt_io_channel {
	struct spdk_io_channel  *fast_ch; /* IO channel for the fast base bdev */
	struct spdk_io_channel  *slow_ch; /* IO channel for the slow base bdev */
};

// Public functions for RPCs (callable from vbdev_dualtier_rpc.c)
int bdev_dualtier_create_disk(const char *name, const char *fast_bdev_name, const char *slow_bdev_name);
void bdev_dualtier_delete_disk(const char *name, spdk_bdev_unregister_cb cb_fn, void *cb_arg);

#endif /* VBDEV_DUALTIER_H */
