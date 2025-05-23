// SPDX-License-Identifier: BSD-3-Clause
// Copyright (C) 2023 Intel Corporation.

#include "vbdev_dualtier.h"

#include "spdk/stdinc.h"
#include "spdk/rpc.h"
#include "spdk/env.h"
#include "spdk/endian.h"
#include "spdk/string.h"
#include "spdk/thread.h"
#include "spdk/util.h"
#include "spdk/bdev_module.h"
#include "spdk/log.h"
#include "spdk/io_device.h" // For spdk_io_device_register/unregister
#include "spdk/bdev.h"      // For spdk_bdev_get_by_name, spdk_bdev_open_ext etc.
#include "spdk/json.h"      // For spdk_json_write_ctx and related functions.
#include <stdlib.h>     // For calloc/free

// Define SPDK_LOG_VBDEV_DUALTIER if not defined by the build system
#ifndef SPDK_LOG_VBDEV_DUALTIER
#define SPDK_LOG_VBDEV_DUALTIER SPDK_LOG_DEBUG
#endif

static TAILQ_HEAD(, vbdev_dualtier) g_dt_nodes = TAILQ_HEAD_INITIALIZER(g_dt_nodes);

// Forward declarations for functions to be used in the fn_table
static int vbdev_dualtier_dump_info_json(void *ctx, struct spdk_json_write_ctx *w);
static void vbdev_dualtier_write_config_json(struct spdk_bdev *bdev, struct spdk_json_write_ctx *w);

static const struct spdk_bdev_fn_table vbdev_dualtier_fn_table = {
	.destruct		= vbdev_dualtier_destruct,
	.submit_request		= vbdev_dualtier_submit_request,
	.io_type_supported	= vbdev_dualtier_io_type_supported,
	.get_io_channel		= vbdev_dualtier_get_io_channel,
	.dump_info_json		= vbdev_dualtier_dump_info_json,
	.write_config_json	= vbdev_dualtier_write_config_json,
};

static int
vbdev_dualtier_dump_info_json(void *ctx, struct spdk_json_write_ctx *w)
{
	struct vbdev_dualtier *dt_node = (struct vbdev_dualtier *)ctx;

	spdk_json_write_name(w, "dualtier");
	spdk_json_write_object_begin(w);
	spdk_json_write_named_string(w, "name", spdk_bdev_get_name(&dt_node->dt_bdev));
	if (dt_node->fast_bdev) {
		spdk_json_write_named_string(w, "fast_bdev_name", spdk_bdev_get_name(dt_node->fast_bdev));
	}
	if (dt_node->slow_bdev) {
		spdk_json_write_named_string(w, "slow_bdev_name", spdk_bdev_get_name(dt_node->slow_bdev));
	}
	spdk_json_write_object_end(w);
	return 0;
}

static void
vbdev_dualtier_write_config_json(struct spdk_bdev *bdev, struct spdk_json_write_ctx *w)
{
	/* Configuration for individual dualtier bdevs is handled by the
	 * construct_dualtier_bdev RPC. The module-level config_json
	 * (vbdev_dualtier_dump_config_json) will list these constructors.
	 */
}

// Forward declaration for vbdev_dualtier_dump_config_json
static int vbdev_dualtier_dump_config_json(struct spdk_json_write_ctx *w);

// Forward declaration for vbdev_dualtier_submit_request
static void vbdev_dualtier_submit_request(struct spdk_io_channel *ch, struct spdk_bdev_io *bdev_io);
static void dt_read_get_buf_cb(struct spdk_io_channel *ch, struct spdk_bdev_io *bdev_io, bool success);

static bool
vbdev_dualtier_io_type_supported(void *ctx, enum spdk_bdev_io_type io_type)
{
	struct vbdev_dualtier *dt_node = (struct vbdev_dualtier *)ctx;

	switch (io_type) {
	case SPDK_BDEV_IO_TYPE_READ:
	case SPDK_BDEV_IO_TYPE_WRITE:
	case SPDK_BDEV_IO_TYPE_WRITE_ZEROES:
	case SPDK_BDEV_IO_TYPE_UNMAP:
	case SPDK_BDEV_IO_TYPE_FLUSH:
	case SPDK_BDEV_IO_TYPE_RESET:
		return spdk_bdev_io_type_supported(dt_node->fast_bdev, io_type) &&
		       spdk_bdev_io_type_supported(dt_node->slow_bdev, io_type);
	default:
		// For other types, delegate to fast_bdev or handle specifically
		// For now, assume if fast_bdev supports it, we are good.
		// This might need refinement for ZCOPY, ABORT etc.
		return spdk_bdev_io_type_supported(dt_node->fast_bdev, io_type);
	}
}

static struct spdk_io_channel *
vbdev_dualtier_get_io_channel(void *ctx)
{
	struct vbdev_dualtier *dt_node = (struct vbdev_dualtier *)ctx;
	return spdk_get_io_channel(dt_node); // dt_node is registered as io_device
}

static void
_dt_complete_io(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct spdk_bdev_io *orig_io = cb_arg;
	enum spdk_bdev_io_status status = success ? SPDK_BDEV_IO_STATUS_SUCCESS : SPDK_BDEV_IO_STATUS_FAILED;

	// If the underlying bdev_io failed with a specific status, propagate it.
	// Otherwise, use the general success/failure.
	if (!success && bdev_io->internal.status != SPDK_BDEV_IO_STATUS_FAILED) {
		spdk_bdev_io_complete_base_io_status(orig_io, bdev_io);
	} else {
		spdk_bdev_io_complete(orig_io, status);
	}
	spdk_bdev_free_io(bdev_io);
}

static void
_dt_complete_zcopy_io(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct spdk_bdev_io *orig_io = cb_arg;
	enum spdk_bdev_io_status status = success ? SPDK_BDEV_IO_STATUS_SUCCESS : SPDK_BDEV_IO_STATUS_FAILED;

	if (success) {
		// For zcopy, the buffer is already "in place" for the original IO.
		// We need to ensure the original IO's iovs point to the right buffer.
		// This is typically done by the underlying bdev when it calls the callback.
		// If the underlying bdev_io (passed as bdev_io here) has the correct iovs,
		// and orig_io is the one submitted to us, we might need to update orig_io's iovs.
		// However, spdk_bdev_io_set_buf is for non-zcopy reads usually.
		// For zcopy, the buffers should already be mapped.
		// The passthru example doesn't call set_buf here. It assumes the buffers
		// For zcopy, the buffer is already "in place" for the original IO.
		// We need to ensure the original IO's iovs point to the right buffer.
		// This is typically done by the underlying bdev when it calls the callback.
		// If the underlying bdev_io (passed as bdev_io here) has the correct iovs,
		// and orig_io is the one submitted to us, we might need to update orig_io's iovs.
		spdk_bdev_io_set_buf(orig_io, bdev_io->u.bdev.iovs[0].iov_base, bdev_io->u.bdev.iovs[0].iov_len);
	}
	spdk_bdev_io_complete(orig_io, status);
	spdk_bdev_free_io(bdev_io);
}

static void
dt_read_get_buf_cb(struct spdk_io_channel *ch, struct spdk_bdev_io *bdev_io, bool success)
{
	struct vbdev_dualtier *dt_node = SPDK_CONTAINEROF(bdev_io->bdev, struct vbdev_dualtier, dt_bdev);
	// 'ch' here is the dualtier vbdev's channel, got from spdk_get_io_channel(dt_node)
	struct dt_io_channel *dt_ch = spdk_io_channel_get_ctx(ch);
	struct spdk_bdev_desc *target_desc;
	struct spdk_io_channel *target_ch_underlying;
	int rc;

	if (!success) {
		SPDK_ERRLOG("spdk_bdev_io_get_buf failed for bdev_io %p\n", bdev_io);
		spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		return;
	}

	if (bdev_io->reserved0 == 0) {
		target_desc = dt_node->fast_desc;
		target_ch_underlying = dt_ch->fast_ch;
	} else {
		target_desc = dt_node->slow_desc;
		target_ch_underlying = dt_ch->slow_ch;
	}

	if (target_desc == NULL || target_ch_underlying == NULL) {
		SPDK_ERRLOG("Read: Target descriptor or channel is NULL for bdev_io type %u, reserved0 %u\n", bdev_io->type, bdev_io->reserved0);
		spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		// The buffer allocated by spdk_bdev_io_get_buf is part of bdev_io.
		// Completing bdev_io will free it.
		return;
	}

	if (bdev_io->u.bdev.md_buf == NULL) {
		rc = spdk_bdev_readv_blocks(target_desc, target_ch_underlying, bdev_io->u.bdev.iovs,
					bdev_io->u.bdev.iovcnt, bdev_io->u.bdev.offset_blocks,
					bdev_io->u.bdev.num_blocks, _dt_complete_io,
					bdev_io);
	} else {
		rc = spdk_bdev_readv_blocks_with_md(target_desc, target_ch_underlying,
						bdev_io->u.bdev.iovs, bdev_io->u.bdev.iovcnt,
						bdev_io->u.bdev.md_buf,
						bdev_io->u.bdev.offset_blocks,
						bdev_io->u.bdev.num_blocks,
						_dt_complete_io, bdev_io);
	}

	if (rc != 0) {
		if (rc == -ENOMEM) {
			SPDK_ERRLOG("No memory for read on dualtier vbdev %s\n", bdev_io->bdev->name);
			spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_NOMEM);
		} else {
			SPDK_ERRLOG("ERROR %d on read submission for dualtier vbdev %s\n", rc, bdev_io->bdev->name);
			spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		}
	}
}

static void
vbdev_dualtier_submit_request(struct spdk_io_channel *ch, struct spdk_bdev_io *bdev_io)
{
	struct vbdev_dualtier *dt_node = SPDK_CONTAINEROF(bdev_io->bdev, struct vbdev_dualtier, dt_bdev);
	struct dt_io_channel *dt_ch = spdk_io_channel_get_ctx(ch);
	struct spdk_bdev_desc *target_desc;
	struct spdk_io_channel *target_ch;
	int rc = 0;

	// Default to fast tier if not specified by reserved0
	// reserved0 = 0 -> fast tier
	// reserved0 != 0 -> slow tier
	if (bdev_io->reserved0 == 0) { // Fast Tier
		target_desc = dt_node->fast_desc;
		target_ch = dt_ch->fast_ch;
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_DUALTIER, "IO for %s (type %u, offset %lu, len %u) routed to FAST tier.\n",
			      dt_node->dt_bdev.name, bdev_io->type, bdev_io->u.bdev.offset_blocks, bdev_io->u.bdev.num_blocks);
	} else { // Slow Tier
		target_desc = dt_node->slow_desc;
		target_ch = dt_ch->slow_ch;
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_DUALTIER, "IO for %s (type %u, offset %lu, len %u) routed to SLOW tier (reserved0=%u).\n",
			      dt_node->dt_bdev.name, bdev_io->type, bdev_io->u.bdev.offset_blocks, bdev_io->u.bdev.num_blocks, bdev_io->reserved0);
	}


	if (target_desc == NULL || target_ch == NULL) {
		SPDK_ERRLOG("Target descriptor or channel is NULL for bdev_io type %u, reserved0 %u on %s\n",
			    bdev_io->type, bdev_io->reserved0, dt_node->dt_bdev.name);
		spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		return;
	}

	switch (bdev_io->type) {
	case SPDK_BDEV_IO_TYPE_READ:
		spdk_bdev_io_get_buf(bdev_io, dt_read_get_buf_cb,
				     bdev_io->u.bdev.num_blocks * bdev_io->bdev->blocklen);
		break;
	case SPDK_BDEV_IO_TYPE_WRITE:
		if (bdev_io->u.bdev.md_buf == NULL) {
			rc = spdk_bdev_writev_blocks(target_desc, target_ch, bdev_io->u.bdev.iovs,
						     bdev_io->u.bdev.iovcnt, bdev_io->u.bdev.offset_blocks,
						     bdev_io->u.bdev.num_blocks, _dt_complete_io,
						     bdev_io);
		} else {
			rc = spdk_bdev_writev_blocks_with_md(target_desc, target_ch,
							     bdev_io->u.bdev.iovs, bdev_io->u.bdev.iovcnt,
							     bdev_io->u.bdev.md_buf,
							     bdev_io->u.bdev.offset_blocks,
							     bdev_io->u.bdev.num_blocks,
							     _dt_complete_io, bdev_io);
		}
		break;
	case SPDK_BDEV_IO_TYPE_WRITE_ZEROES:
		rc = spdk_bdev_write_zeroes_blocks(target_desc, target_ch,
						   bdev_io->u.bdev.offset_blocks,
						   bdev_io->u.bdev.num_blocks,
						   _dt_complete_io, bdev_io);
		break;
	case SPDK_BDEV_IO_TYPE_UNMAP:
		rc = spdk_bdev_unmap_blocks(target_desc, target_ch,
					    bdev_io->u.bdev.offset_blocks,
					    bdev_io->u.bdev.num_blocks,
					    _dt_complete_io, bdev_io);
		break;
	case SPDK_BDEV_IO_TYPE_FLUSH:
		rc = spdk_bdev_flush_blocks(target_desc, target_ch,
					    bdev_io->u.bdev.offset_blocks,
					    bdev_io->u.bdev.num_blocks, /* num_blocks for flush can be 0 */
					    _dt_complete_io, bdev_io);
		break;
	case SPDK_BDEV_IO_TYPE_RESET:
		rc = spdk_bdev_reset(target_desc, target_ch,
				     _dt_complete_io, bdev_io);
		break;
	case SPDK_BDEV_IO_TYPE_ZCOPY:
		if (bdev_io->u.bdev.zcopy.start) {
			rc = spdk_bdev_zcopy_start(target_desc, target_ch, bdev_io->u.bdev.iovs,
						   bdev_io->u.bdev.iovcnt, bdev_io->u.bdev.offset_blocks,
						   bdev_io->u.bdev.num_blocks, bdev_io->u.bdev.zcopy.populate,
						   _dt_complete_zcopy_io, bdev_io);
		} else {
			// For zcopy end, the bdev_io is the one returned by the underlying bdev from zcopy_start.
			// The current code assumes bdev_io is the *original* IO.
			// This is a simplification and might not be correct for all zcopy scenarios.
			// The passthru module forwards bdev_io directly.
			rc = spdk_bdev_zcopy_end(bdev_io, bdev_io->u.bdev.zcopy.commit, _dt_complete_io, bdev_io);
		}
		break;
	case SPDK_BDEV_IO_TYPE_ABORT:
		// Abort is complex. It needs to find the original IO on the target device.
		// The bio_to_abort in bdev_io->u.abort.bio_to_abort is the one submitted to dualtier.
		// This requires mapping this to the one submitted to the underlying bdev.
		// For now, attempt to pass it through. This is a simplification.
		rc = spdk_bdev_abort(target_desc, target_ch, bdev_io->u.abort.bio_to_abort,
				     _dt_complete_io, bdev_io);
		break;
	default:
		SPDK_ERRLOG("dualtier %s: unknown I/O type %d\n", dt_node->dt_bdev.name, bdev_io->type);
		spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		return;
	}

	if (rc != 0) {
		if (rc == -ENOMEM) {
			SPDK_ERRLOG("No memory, cannot submit or queue I/O for dualtier vbdev %s (type %d)\n",
				    bdev_io->bdev->name, bdev_io->type);
			// TODO: Implement queuing logic if -ENOMEM, similar to passthru_queue_io.
			spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_NOMEM);
		} else {
			SPDK_ERRLOG("ERROR %d on bdev_io submission for dualtier vbdev %s (type %d)\n",
				    rc, bdev_io->bdev->name, bdev_io->type);
			spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		}
	}
}


static int
dt_bdev_ch_create_cb(void *io_device, void *ctx_buf)
{
	struct dt_io_channel *dt_ch = ctx_buf;
	struct vbdev_dualtier *dt_node = io_device;

	dt_ch->fast_ch = spdk_bdev_get_io_channel(dt_node->fast_desc);
	if (!dt_ch->fast_ch) {
		SPDK_ERRLOG("Failed to get I/O channel for fast_desc\n");
		return -ENOMEM;
	}

	dt_ch->slow_ch = spdk_bdev_get_io_channel(dt_node->slow_desc);
	if (!dt_ch->slow_ch) {
		spdk_put_io_channel(dt_ch->fast_ch);
		SPDK_ERRLOG("Failed to get I/O channel for slow_desc\n");
		return -ENOMEM;
	}

	return 0;
}

static void
dt_bdev_ch_destroy_cb(void *io_device, void *ctx_buf)
{
	struct dt_io_channel *dt_ch = ctx_buf;

	spdk_put_io_channel(dt_ch->fast_ch);
	spdk_put_io_channel(dt_ch->slow_ch);
}

static void
_device_unregister_cb(void *io_device)
{
	struct vbdev_dualtier *dt_node  = io_device;

	SPDK_NOTICELOG("Dualtier vbdev %s unregistered.\n", dt_node->dt_bdev.name);
	free(dt_node->dt_bdev.name);
	free(dt_node);
}

struct dualtier_destruct_ctx {
	struct spdk_bdev_desc *fast_desc;
	struct spdk_bdev_desc *slow_desc;
};

static void
_vbdev_dualtier_destruct_sync(void *ctx)
{
	struct dualtier_destruct_ctx *destruct_ctx = ctx;
	spdk_bdev_close(destruct_ctx->fast_desc);
	spdk_bdev_close(destruct_ctx->slow_desc);
	free(destruct_ctx);
}

static int
vbdev_dualtier_destruct(void *ctx)
{
	struct vbdev_dualtier *dt_node = (struct vbdev_dualtier *)ctx;
	struct dualtier_destruct_ctx *destruct_ctx;

	TAILQ_REMOVE(&g_dt_nodes, dt_node, link);

	/* Unclaim the underlying bdevs. */
	/* It's safe to call release even if claim was not done or failed. */
	if (dt_node->fast_bdev) {
		spdk_bdev_module_release_bdev(dt_node->fast_bdev);
	}
	if (dt_node->slow_bdev) {
		spdk_bdev_module_release_bdev(dt_node->slow_bdev);
	}

	destruct_ctx = calloc(1, sizeof(*destruct_ctx));
	if (!destruct_ctx) {
		SPDK_ERRLOG("Failed to allocate context for closing bdev descriptors for %s\n",
			    dt_node->dt_bdev.name);
		/* This is problematic, as descriptors won't be closed.
		 * SPDK might complain or leak. For now, proceed with unregister.
		 */
	} else {
		destruct_ctx->fast_desc = dt_node->fast_desc;
		destruct_ctx->slow_desc = dt_node->slow_desc;

		/* Close the underlying bdevs on their original opened thread. */
		if (dt_node->thread && dt_node->thread != spdk_get_thread()) {
			spdk_thread_send_msg(dt_node->thread, _vbdev_dualtier_destruct_sync, destruct_ctx);
		} else {
			_vbdev_dualtier_destruct_sync(destruct_ctx);
		}
	}

	/* Unregister the io_device. This will call _device_unregister_cb when done. */
	/* _device_unregister_cb will free dt_node and its name. */
	spdk_io_device_unregister(dt_node, _device_unregister_cb);

	/* Return 0 to indicate that this function has initiated the tear down.
	 * The actual freeing of memory happens in _device_unregister_cb.
	 */
	return 0;
}

static int
vbdev_dualtier_init(void)
{
	SPDK_NOTICELOG("Initializing dualtier vbdev module.\n");
	return 0;
}

static int
vbdev_dualtier_get_ctx_size(void)
{
	/* No custom bdev_io context for now. */
	return 0;
}

static struct spdk_bdev_module dualtier_if;

static void
vbdev_dualtier_examine(struct spdk_bdev *bdev)
{
	/* Dualtier vbdevs will be created via RPC, not by examining base bdevs automatically. */
	spdk_bdev_module_examine_done(&dualtier_if);
}

static void
vbdev_dualtier_finish(void)
{
	SPDK_NOTICELOG("Finishing dualtier vbdev module.\n");
	/* Cleanup global lists if any were populated, e.g. g_bdev_names if used for config. */
}

static int
vbdev_dualtier_dump_config_json(struct spdk_json_write_ctx *w)
{
	struct vbdev_dualtier *dt_node;

	TAILQ_FOREACH(dt_node, &g_dt_nodes, link) {
		spdk_json_write_object_begin(w);
		spdk_json_write_named_string(w, "method", "construct_dualtier_bdev");
		spdk_json_write_named_object_begin(w, "params");
		spdk_json_write_named_string(w, "name", dt_node->dt_bdev.name);
		if (dt_node->fast_bdev) {
			spdk_json_write_named_string(w, "fast_bdev_name", dt_node->fast_bdev->name);
		}
		if (dt_node->slow_bdev) {
			spdk_json_write_named_string(w, "slow_bdev_name", dt_node->slow_bdev->name);
		}
		spdk_json_write_object_end(w); // end params
		spdk_json_write_object_end(w); // end method object
	}
	return 0;
}

int
bdev_dualtier_create_disk(const char *name, const char *fast_bdev_name, const char *slow_bdev_name)
{
	struct vbdev_dualtier *dt_node;
	int rc = 0;
	uint32_t min_blockcnt;

	if (spdk_bdev_get_by_name(name)) {
		SPDK_ERRLOG("Dualtier bdev %s already exists\n", name);
		return -EEXIST;
	}

	dt_node = calloc(1, sizeof(*dt_node));
	if (!dt_node) {
		SPDK_ERRLOG("calloc failed for dt_node\n");
		return -ENOMEM;
	}

	dt_node->dt_bdev.name = strdup(name);
	if (!dt_node->dt_bdev.name) {
		rc = -ENOMEM;
		goto error_after_dt_node_alloc;
	}
	dt_node->dt_bdev.product_name = "DualtierVbdev";

	rc = spdk_bdev_open_ext(fast_bdev_name, true, NULL, NULL, &dt_node->fast_desc);
	if (rc) {
		SPDK_ERRLOG("Could not open fast bdev %s, error %d\n", fast_bdev_name, rc);
		goto error_after_dt_bdev_name_alloc;
	}
	dt_node->fast_bdev = spdk_bdev_desc_get_bdev(dt_node->fast_desc);

	rc = spdk_bdev_open_ext(slow_bdev_name, true, NULL, NULL, &dt_node->slow_desc);
	if (rc) {
		SPDK_ERRLOG("Could not open slow bdev %s, error %d\n", slow_bdev_name, rc);
		goto error_after_fast_desc_open;
	}
	dt_node->slow_bdev = spdk_bdev_desc_get_bdev(dt_node->slow_desc);

	if (dt_node->fast_bdev->blocklen != dt_node->slow_bdev->blocklen) {
		SPDK_ERRLOG("Fast bdev (%s) blocklen %u != Slow bdev (%s) blocklen %u\n",
			    fast_bdev_name, dt_node->fast_bdev->blocklen,
			    slow_bdev_name, dt_node->slow_bdev->blocklen);
		rc = -EINVAL;
		goto error_after_slow_desc_open;
	}

	dt_node->dt_bdev.blocklen = dt_node->fast_bdev->blocklen;
	min_blockcnt = spdk_min(dt_node->fast_bdev->blockcnt, dt_node->slow_bdev->blockcnt);
	if (min_blockcnt == 0) {
		SPDK_ERRLOG("One of the base bdevs has zero blocks. Fast: %lu, Slow: %lu\n",
			    dt_node->fast_bdev->blockcnt, dt_node->slow_bdev->blockcnt);
		rc = -EINVAL;
		goto error_after_slow_desc_open;
	}
	dt_node->dt_bdev.blockcnt = min_blockcnt;
	dt_node->dt_bdev.write_cache = dt_node->fast_bdev->write_cache && dt_node->slow_bdev->write_cache;
	dt_node->dt_bdev.required_alignment = spdk_max(dt_node->fast_bdev->required_alignment, dt_node->slow_bdev->required_alignment);
	dt_node->dt_bdev.optimal_io_boundary = dt_node->fast_bdev->optimal_io_boundary;
	dt_node->dt_bdev.split_on_optimal_io_boundary = dt_node->fast_bdev->split_on_optimal_io_boundary || dt_node->slow_bdev->split_on_optimal_io_boundary;
	dt_node->dt_bdev.split_on_write_unit = dt_node->fast_bdev->split_on_write_unit || dt_node->slow_bdev->split_on_write_unit;


	dt_node->dt_bdev.ctxt = dt_node;
	dt_node->dt_bdev.fn_table = &vbdev_dualtier_fn_table;
	dt_node->dt_bdev.module = &dualtier_if;

	rc = spdk_bdev_module_claim_bdev(dt_node->fast_bdev, dt_node->fast_desc, &dualtier_if);
	if (rc) {
		SPDK_ERRLOG("Failed to claim fast_bdev %s (rc=%d)\n", fast_bdev_name, rc);
		goto error_after_slow_desc_open;
	}
	rc = spdk_bdev_module_claim_bdev(dt_node->slow_bdev, dt_node->slow_desc, &dualtier_if);
	if (rc) {
		SPDK_ERRLOG("Failed to claim slow_bdev %s (rc=%d)\n", slow_bdev_name, rc);
		spdk_bdev_module_release_bdev(dt_node->fast_bdev);
		goto error_after_slow_desc_open;
	}

	dt_node->thread = spdk_get_thread();

	spdk_io_device_register(dt_node, dt_bdev_ch_create_cb, dt_bdev_ch_destroy_cb,
				sizeof(struct dt_io_channel), dt_node->dt_bdev.name);

	rc = spdk_bdev_register(&dt_node->dt_bdev);
	if (rc) {
		SPDK_ERRLOG("Failed to register dualtier bdev %s (rc=%d)\n", name, rc);
		spdk_io_device_unregister(dt_node, NULL);
		spdk_bdev_module_release_bdev(dt_node->slow_bdev);
		spdk_bdev_module_release_bdev(dt_node->fast_bdev);
		goto error_after_slow_desc_open;
	}

	TAILQ_INSERT_TAIL(&g_dt_nodes, dt_node, link);
	SPDK_NOTICELOG("Created dualtier vbdev %s on %s (fast) and %s (slow)\n",
		       name, fast_bdev_name, slow_bdev_name);
	return 0;

error_after_slow_desc_open:
	if (dt_node->slow_desc) spdk_bdev_close(dt_node->slow_desc);
error_after_fast_desc_open:
	if (dt_node->fast_desc) spdk_bdev_close(dt_node->fast_desc);
error_after_dt_bdev_name_alloc:
	free(dt_node->dt_bdev.name);
error_after_dt_node_alloc:
	free(dt_node);

	return rc;
}

void
bdev_dualtier_delete_disk(const char *name, spdk_bdev_unregister_cb cb_fn, void *cb_arg)
{
	struct vbdev_dualtier *dt_node, *tmp;
	int rc = -ENODEV;

	TAILQ_FOREACH_SAFE(dt_node, &g_dt_nodes, link, tmp) {
		if (strcmp(spdk_bdev_get_name(&dt_node->dt_bdev), name) == 0) {
			spdk_bdev_unregister(&dt_node->dt_bdev, cb_fn, cb_arg);
			// vbdev_dualtier_destruct will remove from g_dt_nodes and free memory.
			return;
		}
	}

	// If not found
	if (cb_fn) {
		cb_fn(cb_arg, rc);
	}
}

static struct spdk_bdev_module dualtier_if = {
	.name = "dualtier",
	.module_init = vbdev_dualtier_init,
	.get_ctx_size = vbdev_dualtier_get_ctx_size,
	.examine_config = vbdev_dualtier_examine, /* Use examine_config for synchronous decisions */
	.module_fini = vbdev_dualtier_finish,
	.config_json = vbdev_dualtier_dump_config_json, /* Updated */
	.async_init = false,
	.async_fini = false
};

SPDK_BDEV_MODULE_REGISTER(dualtier_vbdev, &dualtier_if);
