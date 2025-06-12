/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2022 Intel Corporation.
 *   All rights reserved.
 */

#include "bdev_raid.h"

#include "spdk/env.h"
#include "spdk/thread.h"
#include "spdk/string.h"
#include "spdk/util.h"
#include "spdk/likely.h"
#include "spdk/log.h"
#include "spdk/accel.h"

/* Maximum concurrent full stripe writes per io channel */
#define RAID5F_MAX_STRIPES 32

struct chunk {
	/* Corresponds to base_bdev index */
	uint8_t index;

	/* Array of iovecs */
	struct iovec *iovs;

	/* Number of used iovecs */
	int iovcnt;

	/* Total number of available iovecs in the array */
	int iovcnt_max;

	/* Pointer to buffer with I/O metadata */
	void *md_buf;
};

struct stripe_request;
typedef void (*stripe_req_xor_cb)(struct stripe_request *stripe_req, int status);

struct stripe_request {
	enum stripe_request_type {
		STRIPE_REQ_WRITE,
		STRIPE_REQ_RECONSTRUCT,
	} type;

	struct raid5f_io_channel *r5ch;

	/* The associated raid_bdev_io */
	struct raid_bdev_io *raid_io;

	/* The stripe's index in the raid array. */
	uint64_t stripe_index;

	/* The stripe's parity chunk */
	struct chunk *parity_chunk;

	union {
		struct {
			/* Buffer for stripe parity */
			void *parity_buf;

			/* Buffer for stripe io metadata parity */
			void *parity_md_buf;
		} write;

		struct {
			/* Array of buffers for reading chunk data */
			void **chunk_buffers;

			/* Array of buffers for reading chunk metadata */
			void **chunk_md_buffers;

			/* Chunk to reconstruct from parity */
			struct chunk *chunk;

			/* Offset from chunk start */
			uint64_t chunk_offset;
		} reconstruct;
	};

	/* Array of iovec iterators for each chunk */
	struct spdk_ioviter *chunk_iov_iters;

	/* Array of source buffer pointers for parity calculation */
	void **chunk_xor_buffers;

	/* Array of source buffer pointers for parity calculation of io metadata */
	void **chunk_xor_md_buffers;

	struct {
		size_t len;
		size_t remaining;
		size_t remaining_md;
		int status;
		stripe_req_xor_cb cb;
	} xor;

	TAILQ_ENTRY(stripe_request) link;

	/* New fields for RMW */
	enum {
		RMW_IDLE,
		RMW_READING_OLD_DATA,
		RMW_READING_OLD_PARITY,
		RMW_CALCULATING_NEW_PARITY,
		RMW_WRITING_NEW_DATA,
		RMW_WRITING_NEW_PARITY,
		RMW_COMPLETED
	} rmw_state;

	uint8_t rmw_data_chunks_to_read_total; /* Total data chunks in the stripe */
	uint8_t rmw_data_chunks_read_count;   /* Counter for completed old data reads */
	bool rmw_old_parity_read_done;

	void **rmw_old_data_bufs; /* Array of DMA'ble buffers, one per data chunk in the stripe */
	void *rmw_old_parity_buf;  /* DMA'ble buffer for old parity */

	/* Information about the original partial write request */
	uint64_t rmw_original_stripe_offset_blocks; /* Offset of the partial write within the logical stripe */
	uint64_t rmw_original_num_blocks;          /* Number of blocks in the partial write */
	struct iovec *rmw_original_iovs;           /* User's iovecs for the new data */
	int rmw_original_iovcnt;                   /* Count of user's iovecs */
	void *rmw_original_md_buf;                 /* User's metadata buffer */

	/* Fields for RMW XOR stage */
	void **rmw_new_data_bufs_for_xor; /* Array of DMA'ble buffers for constructing the full new data stripe for XOR */
	void *rmw_new_parity_buf;         /* DMA'ble buffer for the newly calculated parity */
	struct spdk_ioviter rmw_xor_iov_iter; /* If we iterate for XOR */
	bool rmw_xor_in_progress;

	/* Counters for RMW write phase */
	uint8_t rmw_data_chunks_to_write_total; /* Number of data chunks that need to be written (due to partial write) */
	uint8_t rmw_data_chunks_written_count;  /* Counter for completed new data chunk writes */
	bool rmw_new_parity_chunk_written;    /* Flag to indicate if the new parity chunk has been written */

	/* Array of chunks corresponding to base_bdevs */
	struct chunk chunks[0];
};

struct raid5f_info {
	/* The parent raid bdev */
	struct raid_bdev *raid_bdev;

	/* Number of data blocks in a stripe (without parity) */
	uint64_t stripe_blocks;

	/* Number of stripes on this array */
	uint64_t total_stripes;

	/* Alignment for buffer allocation */
	size_t buf_alignment;

	/* block length bit shift for optimized calculation, only valid when no interleaved md */
	uint32_t blocklen_shift;
};

struct raid5f_io_channel {
	/* All available stripe requests on this channel */
	struct {
		TAILQ_HEAD(, stripe_request) write;
		TAILQ_HEAD(, stripe_request) reconstruct;
	} free_stripe_requests;

	/* accel_fw channel */
	struct spdk_io_channel *accel_ch;

	/* For retrying xor if accel_ch runs out of resources */
	TAILQ_HEAD(, stripe_request) xor_retry_queue;

	/* For iterating over chunk iovecs during xor calculation */
	void **chunk_xor_buffers;
	struct iovec **chunk_xor_iovs;
	size_t *chunk_xor_iovcnt;
};

#define __CHUNK_IN_RANGE(req, c) \
	c < req->chunks + raid5f_ch_to_r5f_info(req->r5ch)->raid_bdev->num_base_bdevs

#define FOR_EACH_CHUNK_FROM(req, c, from) \
	for (c = from; __CHUNK_IN_RANGE(req, c); c++)

#define FOR_EACH_CHUNK(req, c) \
	FOR_EACH_CHUNK_FROM(req, c, req->chunks)

#define __NEXT_DATA_CHUNK(req, c) \
	c == req->parity_chunk ? c+1 : c

#define FOR_EACH_DATA_CHUNK(req, c) \
	for (c = __NEXT_DATA_CHUNK(req, req->chunks); __CHUNK_IN_RANGE(req, c); \
	     c = __NEXT_DATA_CHUNK(req, c+1))

static inline struct raid5f_info *
raid5f_ch_to_r5f_info(struct raid5f_io_channel *r5ch)
{
	return spdk_io_channel_get_io_device(spdk_io_channel_from_ctx(r5ch));
}

static inline struct stripe_request *
raid5f_chunk_stripe_req(struct chunk *chunk)
{
	return SPDK_CONTAINEROF((chunk - chunk->index), struct stripe_request, chunks);
}

static inline uint8_t
raid5f_stripe_data_chunks_num(const struct raid_bdev *raid_bdev)
{
	return raid_bdev->min_base_bdevs_operational;
}

static inline uint8_t
raid5f_stripe_parity_chunk_index(const struct raid_bdev *raid_bdev, uint64_t stripe_index)
{
	return raid5f_stripe_data_chunks_num(raid_bdev) - stripe_index % raid_bdev->num_base_bdevs;
}

static inline void
raid5f_stripe_request_release(struct stripe_request *stripe_req)
{
	if (spdk_likely(stripe_req->type == STRIPE_REQ_WRITE)) {
		TAILQ_INSERT_HEAD(&stripe_req->r5ch->free_stripe_requests.write, stripe_req, link);
	} else if (stripe_req->type == STRIPE_REQ_RECONSTRUCT) {
		TAILQ_INSERT_HEAD(&stripe_req->r5ch->free_stripe_requests.reconstruct, stripe_req, link);
	} else {
		assert(false);
	}
}

static void raid5f_xor_stripe_retry(struct stripe_request *stripe_req);

static void
raid5f_xor_stripe_done(struct stripe_request *stripe_req)
{
	struct raid5f_io_channel *r5ch = stripe_req->r5ch;

	if (stripe_req->xor.status != 0) {
		SPDK_ERRLOG("stripe xor failed: %s\n", spdk_strerror(-stripe_req->xor.status));
	}

	stripe_req->xor.cb(stripe_req, stripe_req->xor.status);

	if (!TAILQ_EMPTY(&r5ch->xor_retry_queue)) {
		stripe_req = TAILQ_FIRST(&r5ch->xor_retry_queue);
		TAILQ_REMOVE(&r5ch->xor_retry_queue, stripe_req, link);
		raid5f_xor_stripe_retry(stripe_req);
	}
}

static void raid5f_xor_stripe_continue(struct stripe_request *stripe_req);

static void
_raid5f_xor_stripe_cb(struct stripe_request *stripe_req, int status)
{
	if (status != 0) {
		stripe_req->xor.status = status;
	}

	if (stripe_req->xor.remaining + stripe_req->xor.remaining_md == 0) {
		raid5f_xor_stripe_done(stripe_req);
	}
}

static void
raid5f_xor_stripe_cb(void *_stripe_req, int status)
{
	struct stripe_request *stripe_req = _stripe_req;

	stripe_req->xor.remaining -= stripe_req->xor.len;

	if (stripe_req->xor.remaining > 0) {
		stripe_req->xor.len = spdk_ioviter_nextv(stripe_req->chunk_iov_iters,
				      stripe_req->r5ch->chunk_xor_buffers);
		raid5f_xor_stripe_continue(stripe_req);
	}

	_raid5f_xor_stripe_cb(stripe_req, status);
}

static void
raid5f_xor_stripe_md_cb(void *_stripe_req, int status)
{
	struct stripe_request *stripe_req = _stripe_req;

	stripe_req->xor.remaining_md = 0;

	_raid5f_xor_stripe_cb(stripe_req, status);
}

static void
raid5f_xor_stripe_continue(struct stripe_request *stripe_req)
{
	struct raid5f_io_channel *r5ch = stripe_req->r5ch;
	struct raid_bdev_io *raid_io = stripe_req->raid_io;
	struct raid_bdev *raid_bdev = raid_io->raid_bdev;
	uint8_t n_src = raid5f_stripe_data_chunks_num(raid_bdev);
	uint8_t i;
	int ret;

	assert(stripe_req->xor.len > 0);

	for (i = 0; i < n_src; i++) {
		stripe_req->chunk_xor_buffers[i] = r5ch->chunk_xor_buffers[i];
	}

	ret = spdk_accel_submit_xor(r5ch->accel_ch, r5ch->chunk_xor_buffers[n_src],
				    stripe_req->chunk_xor_buffers, n_src, stripe_req->xor.len,
				    raid5f_xor_stripe_cb, stripe_req);
	if (spdk_unlikely(ret)) {
		if (ret == -ENOMEM) {
			TAILQ_INSERT_HEAD(&r5ch->xor_retry_queue, stripe_req, link);
		} else {
			stripe_req->xor.status = ret;
			raid5f_xor_stripe_done(stripe_req);
		}
	}
}

static void
raid5f_xor_stripe(struct stripe_request *stripe_req, stripe_req_xor_cb cb)
{
	struct raid5f_io_channel *r5ch = stripe_req->r5ch;
	struct raid_bdev_io *raid_io = stripe_req->raid_io;
	struct raid_bdev *raid_bdev = raid_io->raid_bdev;
	struct chunk *chunk;
	struct chunk *dest_chunk = NULL;
	uint64_t num_blocks = 0;
	uint8_t c;

	assert(cb != NULL);

	if (spdk_likely(stripe_req->type == STRIPE_REQ_WRITE)) {
		num_blocks = raid_bdev->strip_size;
		dest_chunk = stripe_req->parity_chunk;
	} else if (stripe_req->type == STRIPE_REQ_RECONSTRUCT) {
		num_blocks = raid_io->num_blocks;
		dest_chunk = stripe_req->reconstruct.chunk;
	} else {
		assert(false);
	}

	c = 0;
	FOR_EACH_CHUNK(stripe_req, chunk) {
		if (chunk == dest_chunk) {
			continue;
		}
		r5ch->chunk_xor_iovs[c] = chunk->iovs;
		r5ch->chunk_xor_iovcnt[c] = chunk->iovcnt;
		c++;
	}
	r5ch->chunk_xor_iovs[c] = dest_chunk->iovs;
	r5ch->chunk_xor_iovcnt[c] = dest_chunk->iovcnt;

	stripe_req->xor.len = spdk_ioviter_firstv(stripe_req->chunk_iov_iters,
			      raid_bdev->num_base_bdevs,
			      r5ch->chunk_xor_iovs,
			      r5ch->chunk_xor_iovcnt,
			      r5ch->chunk_xor_buffers);
	stripe_req->xor.remaining = num_blocks * raid_bdev->bdev.blocklen;
	stripe_req->xor.status = 0;
	stripe_req->xor.cb = cb;

	if (raid_io->md_buf != NULL) {
		uint8_t n_src = raid5f_stripe_data_chunks_num(raid_bdev);
		uint64_t len = num_blocks * raid_bdev->bdev.md_len;
		int ret;

		stripe_req->xor.remaining_md = len;

		c = 0;
		FOR_EACH_CHUNK(stripe_req, chunk) {
			if (chunk != dest_chunk) {
				stripe_req->chunk_xor_md_buffers[c] = chunk->md_buf;
				c++;
			}
		}

		ret = spdk_accel_submit_xor(stripe_req->r5ch->accel_ch, dest_chunk->md_buf,
					    stripe_req->chunk_xor_md_buffers, n_src, len,
					    raid5f_xor_stripe_md_cb, stripe_req);
		if (spdk_unlikely(ret)) {
			if (ret == -ENOMEM) {
				TAILQ_INSERT_HEAD(&stripe_req->r5ch->xor_retry_queue, stripe_req, link);
			} else {
				stripe_req->xor.status = ret;
				raid5f_xor_stripe_done(stripe_req);
			}
			return;
		}
	}

	raid5f_xor_stripe_continue(stripe_req);
}

static void
raid5f_xor_stripe_retry(struct stripe_request *stripe_req)
{
	if (stripe_req->xor.remaining_md) {
		raid5f_xor_stripe(stripe_req, stripe_req->xor.cb);
	} else {
		raid5f_xor_stripe_continue(stripe_req);
	}
}

static void raid5f_rmw_read_old_data_chunk_done(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg);
static void raid5f_rmw_read_old_parity_done(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg);
static void raid5f_initiate_rmw_old_data_reads(struct stripe_request *stripe_req);
static void raid5f_initiate_rmw_old_parity_read(struct stripe_request *stripe_req);
static int raid5f_submit_partial_write_request(struct raid_bdev_io *raid_io, uint64_t stripe_index, uint64_t stripe_offset_in_stripe_blocks);
static void raid5f_rmw_prepare_data_and_calculate_new_parity(struct stripe_request *stripe_req);
static void _raid5f_rmw_xor_done_cb(void *cb_arg, int status);
static void raid5f_initiate_rmw_write_new_data(struct stripe_request *stripe_req);
static void raid5f_rmw_write_data_chunk_done(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg);
static void raid5f_initiate_rmw_write_new_parity(struct stripe_request *stripe_req);

static void
raid5f_stripe_request_chunk_write_complete(struct stripe_request *stripe_req,
		enum spdk_bdev_io_status status)
{
	if (raid_bdev_io_complete_part(stripe_req->raid_io, 1, status)) {
		raid5f_stripe_request_release(stripe_req);
	}
}

static void
raid5f_stripe_request_chunk_read_complete(struct stripe_request *stripe_req,
		enum spdk_bdev_io_status status)
{
	struct raid_bdev_io *raid_io = stripe_req->raid_io;

	raid_bdev_io_complete_part(raid_io, 1, status);
}

static void
raid5f_chunk_complete_bdev_io(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct chunk *chunk = cb_arg;
	struct stripe_request *stripe_req = raid5f_chunk_stripe_req(chunk);
	enum spdk_bdev_io_status status = success ? SPDK_BDEV_IO_STATUS_SUCCESS :
					  SPDK_BDEV_IO_STATUS_FAILED;

	spdk_bdev_free_io(bdev_io);

	if (spdk_likely(stripe_req->type == STRIPE_REQ_WRITE)) {
		raid5f_stripe_request_chunk_write_complete(stripe_req, status);
	} else if (stripe_req->type == STRIPE_REQ_RECONSTRUCT) {
		raid5f_stripe_request_chunk_read_complete(stripe_req, status);
	} else {
		assert(false);
	}
}

static void raid5f_stripe_request_submit_chunks(struct stripe_request *stripe_req);

static void
raid5f_chunk_submit_retry(void *_raid_io)
{
	struct raid_bdev_io *raid_io = _raid_io;
	struct stripe_request *stripe_req = raid_io->module_private;

	raid5f_stripe_request_submit_chunks(stripe_req);
}

static inline void
raid5f_init_ext_io_opts(struct spdk_bdev_ext_io_opts *opts, struct raid_bdev_io *raid_io)
{
	memset(opts, 0, sizeof(*opts));
	opts->size = sizeof(*opts);
	opts->memory_domain = raid_io->memory_domain;
	opts->memory_domain_ctx = raid_io->memory_domain_ctx;
	opts->metadata = raid_io->md_buf;
}

static int
raid5f_chunk_submit(struct chunk *chunk)
{
	struct stripe_request *stripe_req = raid5f_chunk_stripe_req(chunk);
	struct raid_bdev_io *raid_io = stripe_req->raid_io;
	struct raid_bdev *raid_bdev = raid_io->raid_bdev;
	struct raid_base_bdev_info *base_info = &raid_bdev->base_bdev_info[chunk->index];
	struct spdk_io_channel *base_ch = raid_bdev_channel_get_base_channel(raid_io->raid_ch,
					  chunk->index);
	uint64_t base_offset_blocks = (stripe_req->stripe_index << raid_bdev->strip_size_shift);
	struct spdk_bdev_ext_io_opts io_opts;
	int ret;

	raid5f_init_ext_io_opts(&io_opts, raid_io);
	io_opts.metadata = chunk->md_buf;

	raid_io->base_bdev_io_submitted++;

	switch (stripe_req->type) {
	case STRIPE_REQ_WRITE:
		if (base_ch == NULL) {
			raid_bdev_io_complete_part(raid_io, 1, SPDK_BDEV_IO_STATUS_SUCCESS);
			return 0;
		}

		ret = raid_bdev_writev_blocks_ext(base_info, base_ch, chunk->iovs, chunk->iovcnt,
						  base_offset_blocks, raid_bdev->strip_size,
						  raid5f_chunk_complete_bdev_io, chunk, &io_opts);
		break;
	case STRIPE_REQ_RECONSTRUCT:
		if (chunk == stripe_req->reconstruct.chunk) {
			raid_bdev_io_complete_part(raid_io, 1, SPDK_BDEV_IO_STATUS_SUCCESS);
			return 0;
		}

		base_offset_blocks += stripe_req->reconstruct.chunk_offset;

		ret = raid_bdev_readv_blocks_ext(base_info, base_ch, chunk->iovs, chunk->iovcnt,
						 base_offset_blocks, raid_io->num_blocks,
						 raid5f_chunk_complete_bdev_io, chunk, &io_opts);
		break;
	default:
		assert(false);
		ret = -EINVAL;
		break;
	}

	if (spdk_unlikely(ret)) {
		raid_io->base_bdev_io_submitted--;
		if (ret == -ENOMEM) {
			raid_bdev_queue_io_wait(raid_io, spdk_bdev_desc_get_bdev(base_info->desc),
						base_ch, raid5f_chunk_submit_retry);
		} else {
			/*
			 * Implicitly complete any I/Os not yet submitted as FAILED. If completing
			 * these means there are no more to complete for the stripe request, we can
			 * release the stripe request as well.
			 */
			uint64_t base_bdev_io_not_submitted;

			if (stripe_req->type == STRIPE_REQ_WRITE) {
				base_bdev_io_not_submitted = raid_bdev->num_base_bdevs -
							     raid_io->base_bdev_io_submitted;
			} else {
				base_bdev_io_not_submitted = raid5f_stripe_data_chunks_num(raid_bdev) -
							     raid_io->base_bdev_io_submitted;
			}

			if (raid_bdev_io_complete_part(raid_io, base_bdev_io_not_submitted,
						       SPDK_BDEV_IO_STATUS_FAILED)) {
				raid5f_stripe_request_release(stripe_req);
			}
		}
	}

	return ret;
}

static int
raid5f_chunk_set_iovcnt(struct chunk *chunk, int iovcnt)
{
	if (iovcnt > chunk->iovcnt_max) {
		struct iovec *iovs = chunk->iovs;

		iovs = realloc(iovs, iovcnt * sizeof(*iovs));
		if (!iovs) {
			return -ENOMEM;
		}
		chunk->iovs = iovs;
		chunk->iovcnt_max = iovcnt;
	}
	chunk->iovcnt = iovcnt;

	return 0;
}

static int
raid5f_stripe_request_map_iovecs(struct stripe_request *stripe_req)
{
	struct raid_bdev_io *raid_io = stripe_req->raid_io;
	struct raid_bdev *raid_bdev = raid_io->raid_bdev;
	struct raid5f_info *r5f_info = raid_bdev->module_private;
	struct chunk *chunk;
	int raid_io_iov_idx = 0;
	size_t raid_io_offset = 0;
	size_t raid_io_iov_offset = 0;
	int i;

	FOR_EACH_DATA_CHUNK(stripe_req, chunk) {
		int chunk_iovcnt = 0;
		uint64_t len = raid_bdev->strip_size * raid_bdev->bdev.blocklen;
		size_t off = raid_io_iov_offset;
		int ret;

		for (i = raid_io_iov_idx; i < raid_io->iovcnt; i++) {
			chunk_iovcnt++;
			off += raid_io->iovs[i].iov_len;
			if (off >= raid_io_offset + len) {
				break;
			}
		}

		assert(raid_io_iov_idx + chunk_iovcnt <= raid_io->iovcnt);

		ret = raid5f_chunk_set_iovcnt(chunk, chunk_iovcnt);
		if (ret) {
			return ret;
		}

		if (raid_io->md_buf != NULL) {
			chunk->md_buf = raid_io->md_buf +
					(raid_io_offset >> r5f_info->blocklen_shift) * raid_bdev->bdev.md_len;
		}

		for (i = 0; i < chunk_iovcnt; i++) {
			struct iovec *chunk_iov = &chunk->iovs[i];
			const struct iovec *raid_io_iov = &raid_io->iovs[raid_io_iov_idx];
			size_t chunk_iov_offset = raid_io_offset - raid_io_iov_offset;

			chunk_iov->iov_base = raid_io_iov->iov_base + chunk_iov_offset;
			chunk_iov->iov_len = spdk_min(len, raid_io_iov->iov_len - chunk_iov_offset);
			raid_io_offset += chunk_iov->iov_len;
			len -= chunk_iov->iov_len;

			if (raid_io_offset >= raid_io_iov_offset + raid_io_iov->iov_len) {
				raid_io_iov_idx++;
				raid_io_iov_offset += raid_io_iov->iov_len;
			}
		}

		if (spdk_unlikely(len > 0)) {
			return -EINVAL;
		}
	}

	stripe_req->parity_chunk->iovs[0].iov_base = stripe_req->write.parity_buf;
	stripe_req->parity_chunk->iovs[0].iov_len = raid_bdev->strip_size * raid_bdev->bdev.blocklen;
	stripe_req->parity_chunk->iovcnt = 1;
	stripe_req->parity_chunk->md_buf = stripe_req->write.parity_md_buf;

	return 0;
}

static void
raid5f_stripe_request_submit_chunks(struct stripe_request *stripe_req)
{
	struct raid_bdev_io *raid_io = stripe_req->raid_io;
	struct chunk *start = &stripe_req->chunks[raid_io->base_bdev_io_submitted];
	struct chunk *chunk;

	FOR_EACH_CHUNK_FROM(stripe_req, chunk, start) {
		if (spdk_unlikely(raid5f_chunk_submit(chunk) != 0)) {
			break;
		}
	}
}

static inline void
raid5f_stripe_request_init(struct stripe_request *stripe_req, struct raid_bdev_io *raid_io,
			   uint64_t stripe_index)
{
	stripe_req->raid_io = raid_io;
	stripe_req->stripe_index = stripe_index;
	stripe_req->parity_chunk = &stripe_req->chunks[raid5f_stripe_parity_chunk_index(raid_io->raid_bdev,
				   stripe_index)];
}

static void
raid5f_stripe_write_request_xor_done(struct stripe_request *stripe_req, int status)
{
	struct raid_bdev_io *raid_io = stripe_req->raid_io;

	if (status != 0) {
		raid5f_stripe_request_release(stripe_req);
		raid_bdev_io_complete(raid_io, SPDK_BDEV_IO_STATUS_FAILED);
	} else {
		raid5f_stripe_request_submit_chunks(stripe_req);
	}
}

static int
raid5f_submit_partial_write_request(struct raid_bdev_io *raid_io, uint64_t stripe_index, uint64_t stripe_offset_in_stripe_blocks)
{
    struct raid_bdev *raid_bdev = raid_io->raid_bdev;
    struct raid5f_io_channel *r5ch = raid_bdev_channel_get_module_ctx(raid_io->raid_ch);
    struct raid5f_info *r5f_info = raid_bdev->module_private;
    struct stripe_request *stripe_req;
    uint8_t num_data_chunks = raid5f_stripe_data_chunks_num(raid_bdev);
    int i;

    stripe_req = TAILQ_FIRST(&r5ch->free_stripe_requests.write);
    if (!stripe_req) {
        return -ENOMEM;
    }

    TAILQ_REMOVE(&r5ch->free_stripe_requests.write, stripe_req, link);

    raid5f_stripe_request_init(stripe_req, raid_io, stripe_index);

    stripe_req->rmw_state = RMW_IDLE;
    stripe_req->rmw_data_chunks_read_count = 0;
    stripe_req->rmw_data_chunks_to_read_total = num_data_chunks;
    stripe_req->rmw_old_parity_read_done = false;
    stripe_req->rmw_old_data_bufs = NULL;
    stripe_req->rmw_old_parity_buf = NULL;
    stripe_req->rmw_data_chunks_to_write_total = 0;
    stripe_req->rmw_data_chunks_written_count = 0;
    stripe_req->rmw_new_parity_chunk_written = false;

    stripe_req->rmw_original_stripe_offset_blocks = stripe_offset_in_stripe_blocks;
    stripe_req->rmw_original_num_blocks = raid_io->num_blocks;
    stripe_req->rmw_original_iovs = raid_io->iovs;
    stripe_req->rmw_original_iovcnt = raid_io->iovcnt;
    stripe_req->rmw_original_md_buf = raid_io->md_buf;

    stripe_req->rmw_old_data_bufs = calloc(num_data_chunks, sizeof(void *));
    if (!stripe_req->rmw_old_data_bufs) {
        SPDK_ERRLOG("Failed to allocate rmw_old_data_bufs array\n");
        raid5f_stripe_request_release(stripe_req);
        return -ENOMEM;
    }
    for (i = 0; i < num_data_chunks; ++i) {
        stripe_req->rmw_old_data_bufs[i] = spdk_dma_malloc(raid_bdev->strip_size * raid_bdev->bdev.blocklen,
                                                          r5f_info->buf_alignment, NULL);
        if (!stripe_req->rmw_old_data_bufs[i]) {
            SPDK_ERRLOG("Failed to allocate rmw_old_data_bufs[%d]\n", i);
            for (int j = 0; j < i; ++j) spdk_dma_free(stripe_req->rmw_old_data_bufs[j]);
            free(stripe_req->rmw_old_data_bufs);
            stripe_req->rmw_old_data_bufs = NULL;
            raid5f_stripe_request_release(stripe_req);
            return -ENOMEM;
        }
    }

    stripe_req->rmw_old_parity_buf = spdk_dma_malloc(raid_bdev->strip_size * raid_bdev->bdev.blocklen,
                                                    r5f_info->buf_alignment, NULL);
    if (!stripe_req->rmw_old_parity_buf) {
        SPDK_ERRLOG("Failed to allocate rmw_old_parity_buf\n");
        /* Free each old data buffer and then the array */
        for (i = 0; i < num_data_chunks; ++i) {
            if (stripe_req->rmw_old_data_bufs[i]) {
                spdk_dma_free(stripe_req->rmw_old_data_bufs[i]);
            }
        }
        free(stripe_req->rmw_old_data_bufs);
        stripe_req->rmw_old_data_bufs = NULL;
        raid5f_stripe_request_release(stripe_req);
        return -ENOMEM;
    }

    raid_io->module_private = stripe_req;
    raid_io->base_bdev_io_submitted = 0;
    /* For the old data read stage */
    raid_io->base_bdev_io_remaining = num_data_chunks;

    raid5f_initiate_rmw_old_data_reads(stripe_req);

    return 0;
}

static void
raid5f_initiate_rmw_old_data_reads(struct stripe_request *stripe_req)
{
    struct raid_bdev_io *raid_io = stripe_req->raid_io;
    struct raid_bdev *raid_bdev = raid_io->raid_bdev;
    struct raid_base_bdev_info *base_info;
    struct spdk_io_channel *base_ch;
    uint64_t base_offset_blocks;
    struct spdk_bdev_ext_io_opts io_opts;
    int ret;
    struct chunk *data_chunk_iter;
    int data_chunk_idx = 0;

    stripe_req->rmw_state = RMW_READING_OLD_DATA;
    raid_io->base_bdev_io_submitted = 0;
    raid_io->base_bdev_io_remaining = stripe_req->rmw_data_chunks_to_read_total;

    SPDK_DEBUGLOG(bdev_raid5f, "Stripe %lu: Initiating RMW: Reading %u old data chunks.\n",
                  stripe_req->stripe_index, stripe_req->rmw_data_chunks_to_read_total);

    FOR_EACH_DATA_CHUNK(stripe_req, data_chunk_iter) {
        base_info = &raid_bdev->base_bdev_info[data_chunk_iter->index];
        base_ch = raid_bdev_channel_get_base_channel(raid_io->raid_ch, data_chunk_iter->index);
        base_offset_blocks = stripe_req->stripe_index << raid_bdev->strip_size_shift;

        struct iovec read_iov;
        read_iov.iov_base = stripe_req->rmw_old_data_bufs[data_chunk_idx];
        read_iov.iov_len = raid_bdev->strip_size * raid_bdev->bdev.blocklen;

        raid5f_init_ext_io_opts(&io_opts, raid_io);
        io_opts.metadata = NULL; /* Ensure we don't pass user's write metadata for these internal reads */

        if (base_ch == NULL) {
            SPDK_ERRLOG("Stripe %lu: Base device %u offline during RMW old data read. Aborting chunk read.\n",
                        stripe_req->stripe_index, data_chunk_iter->index);
             raid5f_rmw_read_old_data_chunk_done(NULL, false, stripe_req);
             data_chunk_idx++;
             continue;
        }

        ret = raid_bdev_readv_blocks_ext(base_info, base_ch, &read_iov, 1,
                                         base_offset_blocks, raid_bdev->strip_size,
                                         raid5f_rmw_read_old_data_chunk_done, stripe_req, &io_opts);

        if (spdk_likely(ret == 0)) {
            raid_io->base_bdev_io_submitted++;
        } else {
            SPDK_ERRLOG("Stripe %lu: Error %d submitting RMW old data read for chunk %u. Aborting chunk read.\n",
                        stripe_req->stripe_index, ret, data_chunk_iter->index);
            raid5f_rmw_read_old_data_chunk_done(NULL, false, stripe_req);
        }
        data_chunk_idx++;
    }
}

static void
raid5f_rmw_write_data_chunk_done(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
    struct raid5f_rmw_write_cb_ctx *write_ctx = cb_arg;
    struct stripe_request *stripe_req = write_ctx->stripe_req;
    struct raid_bdev_io *raid_io = stripe_req->raid_io;

    if (write_ctx->temp_buf_to_free) { // Free the temporary buffer used for this write
        spdk_dma_free(write_ctx->temp_buf_to_free);
    }
    free(write_ctx);

    if (bdev_io) {
        spdk_bdev_free_io(bdev_io);
    }

    if (!success && raid_io->status == SPDK_BDEV_IO_STATUS_SUCCESS) {
        // If this is the first failure in this stage, mark the overall raid_io as failed.
        // raid_bdev_io_complete_part will also do this, but this is for clarity.
        raid_io->status = SPDK_BDEV_IO_STATUS_FAILED;
    }

    // stripe_req->rmw_data_chunks_written_count++; // Manual count not needed if using complete_part correctly with total.

    if (raid_bdev_io_complete_part(raid_io, 1, success ? SPDK_BDEV_IO_STATUS_SUCCESS : SPDK_BDEV_IO_STATUS_FAILED)) {
        // All submitted data writes for RMW are complete.
        if (raid_io->status == SPDK_BDEV_IO_STATUS_SUCCESS) {
            SPDK_DEBUGLOG(bdev_raid5f, "Stripe %lu: All RMW new data writes successful. Proceeding to write new parity.\n", stripe_req->stripe_index);
            raid5f_initiate_rmw_write_new_parity(stripe_req);
        } else {
            SPDK_ERRLOG("Stripe %lu: RMW failed during new data write stage. Overall status %d. Cleaning up.\n",
                        stripe_req->stripe_index, raid_io->status);
            // Cleanup: new_parity_buf is the main remaining RMW-specific buffer.
            if (stripe_req->rmw_new_parity_buf) {
                spdk_dma_free(stripe_req->rmw_new_parity_buf);
                stripe_req->rmw_new_parity_buf = NULL;
            }
            raid5f_stripe_request_release(stripe_req);
            // raid_bdev_io_complete is called by raid_bdev_io_complete_part if it was the last one.
        }
    }
}

static void
raid5f_rmw_read_old_parity_done(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
    struct stripe_request *stripe_req = cb_arg;
    struct raid_bdev_io *raid_io = stripe_req->raid_io;

    if (bdev_io) {
        spdk_bdev_free_io(bdev_io);
    }

    stripe_req->rmw_old_parity_read_done = success;

    if (raid_bdev_io_complete_part(raid_io, 1, success ? SPDK_BDEV_IO_STATUS_SUCCESS : SPDK_BDEV_IO_STATUS_FAILED)) {
        if (raid_io->status == SPDK_BDEV_IO_STATUS_SUCCESS) {
            stripe_req->rmw_state = RMW_CALCULATING_NEW_PARITY;
            SPDK_DEBUGLOG(bdev_raid5f, "Stripe %lu: RMW: Old data and old parity reads complete successfully. Proceeding to calculate new parity.\n", stripe_req->stripe_index);
            raid5f_rmw_prepare_data_and_calculate_new_parity(stripe_req);
        } else {
            SPDK_ERRLOG("Stripe %lu: RMW failed during old parity read stage or previous stage. Overall status %d. Cleaning up.\n",
                        stripe_req->stripe_index, raid_io->status);
            /* Cleanup of rmw_old_data_bufs and rmw_old_parity_buf should happen here or in the function that set the error */
            if (stripe_req->rmw_old_data_bufs) {
                for (int i = 0; i < stripe_req->rmw_data_chunks_to_read_total; ++i) {
                     if (stripe_req->rmw_old_data_bufs[i]) spdk_dma_free(stripe_req->rmw_old_data_bufs[i]);
                }
                free(stripe_req->rmw_old_data_bufs);
                stripe_req->rmw_old_data_bufs = NULL;
            }
            if (stripe_req->rmw_old_parity_buf) {
                spdk_dma_free(stripe_req->rmw_old_parity_buf);
                stripe_req->rmw_old_parity_buf = NULL;
            }
            raid5f_stripe_request_release(stripe_req);
        }
    }
}

static void
raid5f_rmw_prepare_data_and_calculate_new_parity(struct stripe_request *stripe_req)
{
    struct raid_bdev_io *raid_io = stripe_req->raid_io;
    struct raid_bdev *raid_bdev = raid_io->raid_bdev;
    struct raid5f_info *r5f_info = raid_bdev->module_private;
    uint8_t num_data_chunks = raid5f_stripe_data_chunks_num(raid_bdev);
    size_t chunk_size_bytes = raid_bdev->strip_size * raid_bdev->bdev.blocklen;
    size_t block_size_bytes = raid_bdev->bdev.blocklen;
    int i, ret;

    stripe_req->rmw_new_data_bufs_for_xor = calloc(num_data_chunks, sizeof(void *));
    if (!stripe_req->rmw_new_data_bufs_for_xor) {
        SPDK_ERRLOG("Stripe %lu: Failed to allocate rmw_new_data_bufs_for_xor array\n", stripe_req->stripe_index);
        goto err_cleanup;
    }

    for (i = 0; i < num_data_chunks; ++i) {
        stripe_req->rmw_new_data_bufs_for_xor[i] = spdk_dma_malloc(chunk_size_bytes, r5f_info->buf_alignment, NULL);
        if (!stripe_req->rmw_new_data_bufs_for_xor[i]) {
            SPDK_ERRLOG("Stripe %lu: Failed to allocate rmw_new_data_bufs_for_xor[%d]\n", stripe_req->stripe_index, i);
            for (int j = 0; j < i; ++j) spdk_dma_free(stripe_req->rmw_new_data_bufs_for_xor[j]);
            free(stripe_req->rmw_new_data_bufs_for_xor);
            stripe_req->rmw_new_data_bufs_for_xor = NULL;
            goto err_cleanup;
        }
        /* Copy old data into new data buffers */
        memcpy(stripe_req->rmw_new_data_bufs_for_xor[i], stripe_req->rmw_old_data_bufs[i], chunk_size_bytes);
    }

    stripe_req->rmw_new_parity_buf = spdk_dma_malloc(chunk_size_bytes, r5f_info->buf_alignment, NULL);
    if (!stripe_req->rmw_new_parity_buf) {
        SPDK_ERRLOG("Stripe %lu: Failed to allocate rmw_new_parity_buf\n", stripe_req->stripe_index);
        /* Clean up new data buffers */
        if (stripe_req->rmw_new_data_bufs_for_xor) {
            for (int i = 0; i < num_data_chunks; ++i) {
                if (stripe_req->rmw_new_data_bufs_for_xor[i]) spdk_dma_free(stripe_req->rmw_new_data_bufs_for_xor[i]);
            }
            free(stripe_req->rmw_new_data_bufs_for_xor);
            stripe_req->rmw_new_data_bufs_for_xor = NULL;
        }
        /* Clean up old data buffers and array */
        if (stripe_req->rmw_old_data_bufs) {
            for (int i = 0; i < stripe_req->rmw_data_chunks_to_read_total; ++i) {
                if (stripe_req->rmw_old_data_bufs[i]) {
                    spdk_dma_free(stripe_req->rmw_old_data_bufs[i]);
                }
            }
            free(stripe_req->rmw_old_data_bufs);
            stripe_req->rmw_old_data_bufs = NULL;
        }
        /* Clean up old parity buffer */
        if (stripe_req->rmw_old_parity_buf) {
            spdk_dma_free(stripe_req->rmw_old_parity_buf);
            stripe_req->rmw_old_parity_buf = NULL;
        }
        raid_bdev_io_complete(raid_io, SPDK_BDEV_IO_STATUS_FAILED);
        raid5f_stripe_request_release(stripe_req);
        return;
    }

    /* Overlay user's new data onto rmw_new_data_bufs_for_xor */
    uint64_t current_req_offset_bytes = 0;
    int current_iov_idx = 0;
    uint64_t current_iov_offset_bytes = 0;

    for (uint64_t k = 0; k < stripe_req->rmw_original_num_blocks; ++k) {
        uint64_t logical_block_in_stripe = stripe_req->rmw_original_stripe_offset_blocks + k;
        uint8_t target_data_chunk_array_idx = logical_block_in_stripe / raid_bdev->strip_size;
        uint64_t offset_in_target_chunk_blocks = logical_block_in_stripe % raid_bdev->strip_size;
        uint64_t dest_offset_bytes = offset_in_target_chunk_blocks * block_size_bytes;
        char *dest_buf_ptr = (char *)stripe_req->rmw_new_data_bufs_for_xor[target_data_chunk_array_idx];

        /* Advance through iovecs to find the source data for this block */
        while (current_iov_idx < stripe_req->rmw_original_iovcnt &&
               current_iov_offset_bytes >= stripe_req->rmw_original_iovs[current_iov_idx].iov_len) {
            current_iov_offset_bytes -= stripe_req->rmw_original_iovs[current_iov_idx].iov_len;
            current_iov_idx++;
        }

        if (current_iov_idx >= stripe_req->rmw_original_iovcnt) {
            SPDK_ERRLOG("Stripe %lu: Ran out of iovecs while overlaying new data. Offset %lu, Block %lu\n",
                        stripe_req->stripe_index, stripe_req->rmw_original_stripe_offset_blocks, k);
            goto err_cleanup_all_rmw_bufs;
        }

        char *src_buf_ptr = (char *)stripe_req->rmw_original_iovs[current_iov_idx].iov_base + current_iov_offset_bytes;
        memcpy(dest_buf_ptr + dest_offset_bytes, src_buf_ptr, block_size_bytes);

        current_req_offset_bytes += block_size_bytes;
        current_iov_offset_bytes += block_size_bytes;
    }

    /* Now, XOR the rmw_new_data_bufs_for_xor to rmw_new_parity_buf */
    /* This part mimics parts of raid5f_xor_stripe and raid5f_xor_stripe_continue */
    /* We need to set up source pointers for the accel framework. */
    /* The existing stripe_req->chunk_xor_buffers can be repurposed or we use a new one. */
    /* Let's use a temporary one for clarity for now. */

    void **xor_src_buffers = calloc(num_data_chunks, sizeof(void *));
    if (!xor_src_buffers) {
         SPDK_ERRLOG("Stripe %lu: Failed to allocate xor_src_buffers\n", stripe_req->stripe_index);
         goto err_cleanup_all_rmw_bufs;
    }
    for (i = 0; i < num_data_chunks; ++i) {
        xor_src_buffers[i] = stripe_req->rmw_new_data_bufs_for_xor[i];
    }

    stripe_req->rmw_xor_in_progress = true;
    /* Assuming strip_size is constant and XOR is done in one shot for simplicity here. */
    /* A more robust solution would use ioviter like in raid5f_xor_stripe if data is scattered or very large. */
    /* For now, direct call to spdk_accel_submit_xor with full chunk_size_bytes. */
    ret = spdk_accel_submit_xor(stripe_req->r5ch->accel_ch,
                                stripe_req->rmw_new_parity_buf, /* dest */
                                xor_src_buffers,       /* sources */
                                num_data_chunks,       /* n_src */
                                chunk_size_bytes,      /* len */
                                _raid5f_rmw_xor_done_cb, /* cb */
                                stripe_req);           /* cb_arg */

    free(xor_src_buffers); /* xor_src_buffers is only needed for submission */

    if (spdk_unlikely(ret != 0)) {
        SPDK_ERRLOG("Stripe %lu: spdk_accel_submit_xor failed with ret %d\n", stripe_req->stripe_index, ret);
        stripe_req->rmw_xor_in_progress = false;
        if (ret == -ENOMEM) {
            /* TODO: Proper retry mechanism for XOR. For now, fail. */
            SPDK_ERRLOG("Stripe %lu: spdk_accel_submit_xor failed with ENOMEM. RMW failing.\n", stripe_req->stripe_index);
        }
        goto err_cleanup_all_rmw_bufs;
    }

    /* If submission is successful, _raid5f_rmw_xor_done_cb will be called. */
    return;

err_cleanup_all_rmw_bufs:
    spdk_dma_free(stripe_req->rmw_new_parity_buf);
    stripe_req->rmw_new_parity_buf = NULL;
err_cleanup_new_data_bufs:
    if (stripe_req->rmw_new_data_bufs_for_xor) {
        for (i = 0; i < num_data_chunks; ++i) {
            if (stripe_req->rmw_new_data_bufs_for_xor[i]) spdk_dma_free(stripe_req->rmw_new_data_bufs_for_xor[i]);
        }
        free(stripe_req->rmw_new_data_bufs_for_xor);
        stripe_req->rmw_new_data_bufs_for_xor = NULL;
    }
err_cleanup:
    /* Free originally read data/parity as well */
    if (stripe_req->rmw_old_data_bufs) {
        for (i = 0; i < stripe_req->rmw_data_chunks_to_read_total; ++i) { /* Use _to_read_total for old bufs */
            if (stripe_req->rmw_old_data_bufs[i]) spdk_dma_free(stripe_req->rmw_old_data_bufs[i]);
        }
        free(stripe_req->rmw_old_data_bufs);
        stripe_req->rmw_old_data_bufs = NULL;
    }
    if (stripe_req->rmw_old_parity_buf) {
        spdk_dma_free(stripe_req->rmw_old_parity_buf);
        stripe_req->rmw_old_parity_buf = NULL;
    }
    raid_bdev_io_complete(raid_io, SPDK_BDEV_IO_STATUS_FAILED);
    raid5f_stripe_request_release(stripe_req);
}

static void
_raid5f_rmw_xor_done_cb(void *cb_arg, int status)
{
    struct stripe_request *stripe_req = cb_arg;
    struct raid_bdev_io *raid_io = stripe_req->raid_io;

    struct raid_bdev_io *raid_io = stripe_req->raid_io;
    int i; /* Declare i for loops */

    stripe_req->rmw_xor_in_progress = false;

    if (status != 0) {
        SPDK_ERRLOG("Stripe %lu: RMW XOR operation failed with status %d\n", stripe_req->stripe_index, status);
        /* Clean up ALL RMW buffers */
        if (stripe_req->rmw_new_data_bufs_for_xor) {
            for (i = 0; i < raid5f_stripe_data_chunks_num(raid_io->raid_bdev); ++i) { /* Use num_data_chunks */
                if (stripe_req->rmw_new_data_bufs_for_xor[i]) spdk_dma_free(stripe_req->rmw_new_data_bufs_for_xor[i]);
            }
            free(stripe_req->rmw_new_data_bufs_for_xor);
            stripe_req->rmw_new_data_bufs_for_xor = NULL;
        }
        if (stripe_req->rmw_new_parity_buf) {
            spdk_dma_free(stripe_req->rmw_new_parity_buf);
            stripe_req->rmw_new_parity_buf = NULL;
        }
        /* Clean up old buffers as well */
        if (stripe_req->rmw_old_data_bufs) {
            for (int i = 0; i < stripe_req->rmw_data_chunks_to_read_total; ++i) {
                if (stripe_req->rmw_old_data_bufs[i]) spdk_dma_free(stripe_req->rmw_old_data_bufs[i]);
            }
            free(stripe_req->rmw_old_data_bufs);
            stripe_req->rmw_old_data_bufs = NULL;
        }
        if (stripe_req->rmw_old_parity_buf) {
            spdk_dma_free(stripe_req->rmw_old_parity_buf);
            stripe_req->rmw_old_parity_buf = NULL;
        }
        raid_bdev_io_complete(raid_io, SPDK_BDEV_IO_STATUS_FAILED);
        raid5f_stripe_request_release(stripe_req);
        return;
    }

    SPDK_DEBUGLOG(bdev_raid5f, "Stripe %lu: RMW XOR calculation successful. Proceeding to write new data.\n", stripe_req->stripe_index);
    stripe_req->rmw_state = RMW_WRITING_NEW_DATA;

    /* Old data buffers are no longer needed after this point if XOR is successful */
    if (stripe_req->rmw_old_data_bufs) {
        for (int i = 0; i < stripe_req->rmw_data_chunks_to_read_total; ++i) {
            if (stripe_req->rmw_old_data_bufs[i]) spdk_dma_free(stripe_req->rmw_old_data_bufs[i]);
        }
        free(stripe_req->rmw_old_data_bufs);
        stripe_req->rmw_old_data_bufs = NULL;
    }
    if (stripe_req->rmw_old_parity_buf) {
        spdk_dma_free(stripe_req->rmw_old_parity_buf);
        stripe_req->rmw_old_parity_buf = NULL;
    }

    /* The rmw_new_data_bufs_for_xor were only for XOR calculation with current approach. */
    /* If writes happen from original user bufs, these can be freed. */
    /* If writes happen from these merged bufs, keep them until after writes. */
    /* Plan: write user data directly, so these can be freed. */
    if (stripe_req->rmw_new_data_bufs_for_xor) {
        for (int i = 0; i < raid5f_stripe_data_chunks_num(raid_io->raid_bdev); ++i) {
            if (stripe_req->rmw_new_data_bufs_for_xor[i]) spdk_dma_free(stripe_req->rmw_new_data_bufs_for_xor[i]);
        }
        free(stripe_req->rmw_new_data_bufs_for_xor);
        stripe_req->rmw_new_data_bufs_for_xor = NULL;
    }

    /* rmw_new_parity_buf IS needed for writing new parity later. DO NOT FREE IT HERE. */

    raid5f_initiate_rmw_write_new_data(stripe_req); /* New call */
}

/* Helper struct for callback context */
struct raid5f_rmw_write_cb_ctx {
    struct stripe_request *stripe_req;
    void *temp_buf_to_free; /* To free the temporary write buffer */
};

static void
raid5f_initiate_rmw_write_new_data(struct stripe_request *stripe_req)
{
    struct raid_bdev_io *raid_io = stripe_req->raid_io;
    struct raid_bdev *raid_bdev = raid_io->raid_bdev;
    size_t block_size_bytes = raid_bdev->bdev.blocklen;
    uint64_t strip_size_blocks = raid_bdev->strip_size;
    struct spdk_bdev_ext_io_opts io_opts;
    int ret;

    uint64_t user_req_len_bytes = stripe_req->rmw_original_num_blocks * block_size_bytes;
    struct spdk_ioviter iov_iter;
    struct iovec temp_iov; // For submitting parts of user iovecs
    uint64_t current_logical_block_in_stripe;
    uint64_t remaining_user_req_len_bytes = user_req_len_bytes;
    uint64_t user_data_submitted_bytes = 0;
    int submitted_io_count = 0;

    stripe_req->rmw_state = RMW_WRITING_NEW_DATA;
    raid_io->base_bdev_io_submitted = 0;
    /* We need to calculate how many separate writes this will be. */
    /* This is tricky. Let's defer setting base_bdev_io_remaining until we know. */

    SPDK_DEBUGLOG(bdev_raid5f, "Stripe %lu: Initiating RMW: Writing new data segments.\n", stripe_req->stripe_index);

    spdk_ioviter_begin(&iov_iter, stripe_req->rmw_original_iovs, stripe_req->rmw_original_iovcnt, 0);

    current_logical_block_in_stripe = stripe_req->rmw_original_stripe_offset_blocks;

    while(user_data_submitted_bytes < user_req_len_bytes) {
        uint8_t p_idx = raid5f_stripe_parity_chunk_index(raid_bdev, stripe_req->stripe_index);
        uint8_t target_data_chunk_array_idx = current_logical_block_in_stripe / strip_size_blocks;
        uint8_t target_chunk_phys_idx = target_data_chunk_array_idx < p_idx ?
                                       target_data_chunk_array_idx : target_data_chunk_array_idx + 1;

        uint64_t offset_in_target_chunk_blocks = current_logical_block_in_stripe % strip_size_blocks;
        uint64_t base_write_offset_blocks = (stripe_req->stripe_index << raid_bdev->strip_size_shift) + offset_in_target_chunk_blocks;

        uint64_t max_len_in_this_chunk_blocks = strip_size_blocks - offset_in_target_chunk_blocks;
        uint64_t remaining_user_req_blocks = (user_req_len_bytes - user_data_submitted_bytes) / block_size_bytes;
        uint64_t num_blocks_this_write = spdk_min(max_len_in_this_chunk_blocks, remaining_user_req_blocks);
        uint64_t len_this_write_bytes = num_blocks_this_write * block_size_bytes;

        if (num_blocks_this_write == 0) break; /* Should not happen if loop condition is correct */

        struct raid_base_bdev_info *base_info = &raid_bdev->base_bdev_info[target_chunk_phys_idx];
        struct spdk_io_channel *base_ch = raid_bdev_channel_get_base_channel(raid_io->raid_ch, target_chunk_phys_idx);

        void *write_buf = spdk_dma_malloc(len_this_write_bytes, raid_bdev->bdev.buf_align, NULL);
        if (!write_buf) {
            SPDK_ERRLOG("Stripe %lu: Failed to alloc tmp write_buf. Failing RMW.\n", stripe_req->stripe_index);
            // Error handling needs to be robust: complete previously submitted IOs, then fail.
            // For now, simplified:
            raid_bdev_io_complete(raid_io, SPDK_BDEV_IO_STATUS_NOMEM); // This doesn't clean up stripe_req
            // TODO: Proper cleanup of stripe_req and other resources.
            return;
        }
        size_t copied_len = spdk_ioviter_copy_from_v(&iov_iter, write_buf, len_this_write_bytes);
        if (copied_len != len_this_write_bytes) {
             SPDK_ERRLOG("Stripe %lu: Could not copy enough data from ioviter. Failing RMW.\n", stripe_req->stripe_index);
             spdk_dma_free(write_buf);
             // TODO: Cleanup
             raid_bdev_io_complete(raid_io, SPDK_BDEV_IO_STATUS_FAILED);
             return;
        }
        temp_iov.iov_base = write_buf;
        temp_iov.iov_len = len_this_write_bytes;

        raid5f_init_ext_io_opts(&io_opts, raid_io);
        if (stripe_req->rmw_original_md_buf) {
            uint64_t user_logical_start_block_abs = raid_io->offset_blocks - stripe_req->rmw_original_stripe_offset_blocks;
            uint64_t current_write_abs_start_block = user_logical_start_block_abs + (user_data_submitted_bytes / block_size_bytes);
             io_opts.metadata = (char*)stripe_req->rmw_original_md_buf +
                               (current_write_abs_start_block - raid_io->offset_blocks) * raid_bdev->bdev.md_len;
        } else {
            io_opts.metadata = NULL;
        }

        if (base_ch == NULL) {
            SPDK_ERRLOG("Stripe %lu: Data chunk device %u offline during RMW new data write. Aborting.\n",
                        stripe_req->stripe_index, target_chunk_phys_idx);
            spdk_dma_free(write_buf); // Free the temp buffer
            raid_bdev_io_complete(raid_io, SPDK_BDEV_IO_STATUS_FAILED);
            // TODO: Cleanup
            return;
        }

        struct raid5f_rmw_write_cb_ctx *write_ctx = malloc(sizeof(struct raid5f_rmw_write_cb_ctx));
        if (!write_ctx) {
            spdk_dma_free(write_buf);
            SPDK_ERRLOG("Stripe %lu: Failed to alloc write_ctx. Failing RMW.\n", stripe_req->stripe_index);
            raid_bdev_io_complete(raid_io, SPDK_BDEV_IO_STATUS_NOMEM);
            return;
        }
        write_ctx->stripe_req = stripe_req;
        write_ctx->temp_buf_to_free = write_buf;

        ret = raid_bdev_writev_blocks_ext(base_info, base_ch, &temp_iov, 1, /* iovcnt */
                                         base_write_offset_blocks, num_blocks_this_write,
                                         raid5f_rmw_write_data_chunk_done, write_ctx, &io_opts);

        if (spdk_likely(ret == 0)) {
            submitted_io_count++;
        } else {
            SPDK_ERRLOG("Stripe %lu: Error %d submitting RMW new data write for chunk %u. Aborting.\n",
                        stripe_req->stripe_index, ret, target_chunk_phys_idx);
            free(write_ctx);
            spdk_dma_free(write_buf);
            raid_bdev_io_complete(raid_io, SPDK_BDEV_IO_STATUS_FAILED);
            // TODO: Cleanup
            return;
        }
        user_data_submitted_bytes += len_this_write_bytes;
        current_logical_block_in_stripe += num_blocks_this_write;
    }

    if (submitted_io_count > 0) {
        raid_io->base_bdev_io_remaining = submitted_io_count;
        stripe_req->rmw_data_chunks_to_write_total = submitted_io_count;
        stripe_req->rmw_data_chunks_written_count = 0;
    } else if (user_req_len_bytes == 0) {
        raid5f_initiate_rmw_write_new_parity(stripe_req);
    } else {
         SPDK_ERRLOG("Stripe %lu: No data write I/Os submitted for RMW. user_req_len_bytes: %lu\n",
                    stripe_req->stripe_index, user_req_len_bytes);
        raid_bdev_io_complete(raid_io, SPDK_BDEV_IO_STATUS_FAILED);
        // TODO: Cleanup
    }
}

static void raid5f_rmw_write_parity_chunk_done(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg);

static void
raid5f_initiate_rmw_write_new_parity(struct stripe_request *stripe_req)
{
    struct raid_bdev_io *raid_io = stripe_req->raid_io;
    struct raid_bdev *raid_bdev = raid_io->raid_bdev;
    struct raid_base_bdev_info *base_info;
    struct spdk_io_channel *base_ch;
    uint64_t base_offset_blocks;
    struct spdk_bdev_ext_io_opts io_opts;
    struct iovec write_iov;
    int ret;

    SPDK_DEBUGLOG(bdev_raid5f, "Stripe %lu: Initiating RMW: Writing new parity chunk.\n", stripe_req->stripe_index);

    struct chunk *parity_chunk = stripe_req->parity_chunk;
    base_info = &raid_bdev->base_bdev_info[parity_chunk->index];
    base_ch = raid_bdev_channel_get_base_channel(raid_io->raid_ch, parity_chunk->index);
    base_offset_blocks = stripe_req->stripe_index << raid_bdev->strip_size_shift;

    write_iov.iov_base = stripe_req->rmw_new_parity_buf;
    write_iov.iov_len = raid_bdev->strip_size * raid_bdev->bdev.blocklen;

    raid5f_init_ext_io_opts(&io_opts, raid_io);
    io_opts.metadata = NULL; /* No metadata for internal parity write */

    if (base_ch == NULL) {
        SPDK_ERRLOG("Stripe %lu: Parity chunk device %u offline during RMW new parity write. Aborting.\n",
                    stripe_req->stripe_index, parity_chunk->index);
        raid5f_rmw_write_parity_chunk_done(NULL, false, stripe_req);
        return;
    }

    stripe_req->rmw_state = RMW_WRITING_NEW_PARITY;
    raid_io->base_bdev_io_submitted = 0;
    raid_io->base_bdev_io_remaining = 1; /* Only one parity write */

    ret = raid_bdev_writev_blocks_ext(base_info, base_ch, &write_iov, 1,
                                      base_offset_blocks, raid_bdev->strip_size,
                                      raid5f_rmw_write_parity_chunk_done, stripe_req, &io_opts);

    if (spdk_likely(ret == 0)) {
        raid_io->base_bdev_io_submitted++;
    } else {
        SPDK_ERRLOG("Stripe %lu: Error %d submitting RMW new parity write. Aborting.\n",
                    stripe_req->stripe_index, ret);
        raid5f_rmw_write_parity_chunk_done(NULL, false, stripe_req);
    }
}

static void
raid5f_rmw_write_parity_chunk_done(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
    struct stripe_request *stripe_req = cb_arg;
    struct raid_bdev_io *raid_io = stripe_req->raid_io;

    if (bdev_io) {
        spdk_bdev_free_io(bdev_io);
    }

    /* Clean up new parity buffer */
    if (stripe_req->rmw_new_parity_buf) {
        spdk_dma_free(stripe_req->rmw_new_parity_buf);
        stripe_req->rmw_new_parity_buf = NULL;
    }

    if (raid_bdev_io_complete_part(raid_io, 1, success ? SPDK_BDEV_IO_STATUS_SUCCESS : SPDK_BDEV_IO_STATUS_FAILED)) {
        SPDK_DEBUGLOG(bdev_raid5f, "Stripe %lu: RMW completed with status %d\n",
                      stripe_req->stripe_index, raid_io->status);
        raid5f_stripe_request_release(stripe_req);
    }
}

static void
raid5f_initiate_rmw_old_parity_read(struct stripe_request *stripe_req)
{
    struct raid_bdev_io *raid_io = stripe_req->raid_io;
    struct raid_bdev *raid_bdev = raid_io->raid_bdev;
    struct raid_base_bdev_info *base_info;
    struct spdk_io_channel *base_ch;
    uint64_t base_offset_blocks;
    struct spdk_bdev_ext_io_opts io_opts;
    int ret;

    stripe_req->rmw_state = RMW_READING_OLD_PARITY;
    raid_io->base_bdev_io_submitted = 0;
    raid_io->base_bdev_io_remaining = 1; /* Only one parity read */

    SPDK_DEBUGLOG(bdev_raid5f, "Stripe %lu: Initiating RMW: Reading old parity chunk.\n", stripe_req->stripe_index);

    struct chunk *parity_chunk_ptr = stripe_req->parity_chunk;
    base_info = &raid_bdev->base_bdev_info[parity_chunk_ptr->index];
    base_ch = raid_bdev_channel_get_base_channel(raid_io->raid_ch, parity_chunk_ptr->index);
    base_offset_blocks = stripe_req->stripe_index << raid_bdev->strip_size_shift;

    struct iovec read_iov;
    read_iov.iov_base = stripe_req->rmw_old_parity_buf;
    read_iov.iov_len = raid_bdev->strip_size * raid_bdev->bdev.blocklen;

    raid5f_init_ext_io_opts(&io_opts, raid_io);
    io_opts.metadata = NULL; /* Ensure no user metadata for this internal read */

    if (base_ch == NULL) {
        SPDK_ERRLOG("Stripe %lu: Parity chunk device %u offline during RMW old parity read. Aborting.\n",
                    stripe_req->stripe_index, parity_chunk_ptr->index);
        raid5f_rmw_read_old_parity_done(NULL, false, stripe_req);
        return;
    }

    ret = raid_bdev_readv_blocks_ext(base_info, base_ch, &read_iov, 1,
                                     base_offset_blocks, raid_bdev->strip_size,
                                     raid5f_rmw_read_old_parity_done, stripe_req, &io_opts);

    if (spdk_likely(ret == 0)) {
        raid_io->base_bdev_io_submitted++;
    } else {
        SPDK_ERRLOG("Stripe %lu: Error %d submitting RMW old parity read. Aborting RMW.\n",
                    stripe_req->stripe_index, ret);
        raid5f_rmw_read_old_parity_done(NULL, false, stripe_req);
    }
}

static void
raid5f_rmw_read_old_data_chunk_done(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
    struct stripe_request *stripe_req = cb_arg;
    struct raid_bdev_io *raid_io = stripe_req->raid_io;

    if (bdev_io) {
        spdk_bdev_free_io(bdev_io);
    }

    if (raid_bdev_io_complete_part(raid_io, 1, success ? SPDK_BDEV_IO_STATUS_SUCCESS : SPDK_BDEV_IO_STATUS_FAILED)) {
        if (raid_io->status == SPDK_BDEV_IO_STATUS_SUCCESS) {
            SPDK_DEBUGLOG(bdev_raid5f, "Stripe %lu: All old data chunks read successfully. Proceeding to read old parity.\n", stripe_req->stripe_index);
            raid5f_initiate_rmw_old_parity_read(stripe_req);
        } else {
            SPDK_ERRLOG("Stripe %lu: RMW failed during old data read stage. Overall status %d. Cleaning up.\n",
                        stripe_req->stripe_index, raid_io->status);
            if (stripe_req->rmw_old_data_bufs) {
                for (int i = 0; i < stripe_req->rmw_data_chunks_to_read_total; ++i) {
                    if (stripe_req->rmw_old_data_bufs[i]) spdk_dma_free(stripe_req->rmw_old_data_bufs[i]);
                }
                free(stripe_req->rmw_old_data_bufs);
                stripe_req->rmw_old_data_bufs = NULL;
            }
            if (stripe_req->rmw_old_parity_buf) {
                spdk_dma_free(stripe_req->rmw_old_parity_buf);
                stripe_req->rmw_old_parity_buf = NULL;
            }
            raid5f_stripe_request_release(stripe_req);
        }
    }
}

static int
raid5f_submit_write_request(struct raid_bdev_io *raid_io, uint64_t stripe_index)
{
	struct raid_bdev *raid_bdev = raid_io->raid_bdev;
	struct raid5f_io_channel *r5ch = raid_bdev_channel_get_module_ctx(raid_io->raid_ch);
	struct stripe_request *stripe_req;
	int ret;

	stripe_req = TAILQ_FIRST(&r5ch->free_stripe_requests.write);
	if (!stripe_req) {
		return -ENOMEM;
	}

	raid5f_stripe_request_init(stripe_req, raid_io, stripe_index);

	ret = raid5f_stripe_request_map_iovecs(stripe_req);
	if (spdk_unlikely(ret)) {
		return ret;
	}

	TAILQ_REMOVE(&r5ch->free_stripe_requests.write, stripe_req, link);

	raid_io->module_private = stripe_req;
	raid_io->base_bdev_io_remaining = raid_bdev->num_base_bdevs;

	if (raid_bdev_channel_get_base_channel(raid_io->raid_ch, stripe_req->parity_chunk->index) != NULL) {
		raid5f_xor_stripe(stripe_req, raid5f_stripe_write_request_xor_done);
	} else {
		raid5f_stripe_write_request_xor_done(stripe_req, 0);
	}

	return 0;
}

static void
raid5f_chunk_read_complete(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct raid_bdev_io *raid_io = cb_arg;

	spdk_bdev_free_io(bdev_io);

	raid_bdev_io_complete(raid_io, success ? SPDK_BDEV_IO_STATUS_SUCCESS :
			      SPDK_BDEV_IO_STATUS_FAILED);
}

static void raid5f_submit_rw_request(struct raid_bdev_io *raid_io);

static void
_raid5f_submit_rw_request(void *_raid_io)
{
	struct raid_bdev_io *raid_io = _raid_io;

	raid5f_submit_rw_request(raid_io);
}

static void
raid5f_stripe_request_reconstruct_xor_done(struct stripe_request *stripe_req, int status)
{
	struct raid_bdev_io *raid_io = stripe_req->raid_io;

	raid5f_stripe_request_release(stripe_req);

	raid_bdev_io_complete(raid_io,
			      status == 0 ? SPDK_BDEV_IO_STATUS_SUCCESS : SPDK_BDEV_IO_STATUS_FAILED);
}

static void
raid5f_reconstruct_reads_completed_cb(struct raid_bdev_io *raid_io, enum spdk_bdev_io_status status)
{
	struct stripe_request *stripe_req = raid_io->module_private;

	raid_io->completion_cb = NULL;

	if (status != SPDK_BDEV_IO_STATUS_SUCCESS) {
		stripe_req->xor.cb(stripe_req, -EIO);
		return;
	}

	raid5f_xor_stripe(stripe_req, stripe_req->xor.cb);
}

static int
raid5f_submit_reconstruct_read(struct raid_bdev_io *raid_io, uint64_t stripe_index,
			       uint8_t chunk_idx, uint64_t chunk_offset, stripe_req_xor_cb cb)
{
	struct raid_bdev *raid_bdev = raid_io->raid_bdev;
	struct raid5f_io_channel *r5ch = raid_bdev_channel_get_module_ctx(raid_io->raid_ch);
	void *raid_io_md = raid_io->md_buf;
	struct stripe_request *stripe_req;
	struct chunk *chunk;
	int buf_idx;

	assert(cb != NULL);

	stripe_req = TAILQ_FIRST(&r5ch->free_stripe_requests.reconstruct);
	if (!stripe_req) {
		return -ENOMEM;
	}

	raid5f_stripe_request_init(stripe_req, raid_io, stripe_index);

	stripe_req->reconstruct.chunk = &stripe_req->chunks[chunk_idx];
	stripe_req->reconstruct.chunk_offset = chunk_offset;
	stripe_req->xor.cb = cb;
	buf_idx = 0;

	FOR_EACH_CHUNK(stripe_req, chunk) {
		if (chunk == stripe_req->reconstruct.chunk) {
			int i;
			int ret;

			ret = raid5f_chunk_set_iovcnt(chunk, raid_io->iovcnt);
			if (ret) {
				return ret;
			}

			for (i = 0; i < raid_io->iovcnt; i++) {
				chunk->iovs[i] = raid_io->iovs[i];
			}

			chunk->md_buf = raid_io_md;
		} else {
			struct iovec *iov = &chunk->iovs[0];

			iov->iov_base = stripe_req->reconstruct.chunk_buffers[buf_idx];
			iov->iov_len = raid_io->num_blocks * raid_bdev->bdev.blocklen;
			chunk->iovcnt = 1;

			if (raid_io_md) {
				chunk->md_buf = stripe_req->reconstruct.chunk_md_buffers[buf_idx];
			}

			buf_idx++;
		}
	}

	raid_io->module_private = stripe_req;
	raid_io->base_bdev_io_remaining = raid_bdev->num_base_bdevs;
	raid_io->completion_cb = raid5f_reconstruct_reads_completed_cb;

	TAILQ_REMOVE(&r5ch->free_stripe_requests.reconstruct, stripe_req, link);

	raid5f_stripe_request_submit_chunks(stripe_req);

	return 0;
}

static int
raid5f_submit_read_request(struct raid_bdev_io *raid_io, uint64_t stripe_index,
			   uint64_t stripe_offset)
{
	struct raid_bdev *raid_bdev = raid_io->raid_bdev;
	uint8_t chunk_data_idx = stripe_offset >> raid_bdev->strip_size_shift;
	uint8_t p_idx = raid5f_stripe_parity_chunk_index(raid_bdev, stripe_index);
	uint8_t chunk_idx = chunk_data_idx < p_idx ? chunk_data_idx : chunk_data_idx + 1;
	struct raid_base_bdev_info *base_info = &raid_bdev->base_bdev_info[chunk_idx];
	struct spdk_io_channel *base_ch = raid_bdev_channel_get_base_channel(raid_io->raid_ch, chunk_idx);
	uint64_t chunk_offset = stripe_offset - (chunk_data_idx << raid_bdev->strip_size_shift);
	uint64_t base_offset_blocks = (stripe_index << raid_bdev->strip_size_shift) + chunk_offset;
	struct spdk_bdev_ext_io_opts io_opts;
	int ret;

	raid5f_init_ext_io_opts(&io_opts, raid_io);
	if (base_ch == NULL) {
		return raid5f_submit_reconstruct_read(raid_io, stripe_index, chunk_idx, chunk_offset,
						      raid5f_stripe_request_reconstruct_xor_done);
	}

	ret = raid_bdev_readv_blocks_ext(base_info, base_ch, raid_io->iovs, raid_io->iovcnt,
					 base_offset_blocks, raid_io->num_blocks,
					 raid5f_chunk_read_complete, raid_io, &io_opts);
	if (spdk_unlikely(ret == -ENOMEM)) {
		raid_bdev_queue_io_wait(raid_io, spdk_bdev_desc_get_bdev(base_info->desc),
					base_ch, _raid5f_submit_rw_request);
		return 0;
	}

	return ret;
}

static void
raid5f_submit_rw_request(struct raid_bdev_io *raid_io)
{
	struct raid_bdev *raid_bdev = raid_io->raid_bdev;
	struct raid5f_info *r5f_info = raid_bdev->module_private;
	uint64_t stripe_index = raid_io->offset_blocks / r5f_info->stripe_blocks;
	uint64_t stripe_offset = raid_io->offset_blocks % r5f_info->stripe_blocks;
	int ret;

	switch (raid_io->type) {
	case SPDK_BDEV_IO_TYPE_READ:
		assert(raid_io->num_blocks <= raid_bdev->strip_size);
		ret = raid5f_submit_read_request(raid_io, stripe_index, stripe_offset);
		break;
	case SPDK_BDEV_IO_TYPE_WRITE: {
		bool is_full_stripe_write = (stripe_offset == 0 && raid_io->num_blocks == r5f_info->stripe_blocks);

		if (is_full_stripe_write) {
			ret = raid5f_submit_write_request(raid_io, stripe_index);
		} else {
			SPDK_INFOLOG(bdev_raid5f, "Partial write request received. Stripe index: %lu, stripe_offset_blocks: %lu, num_blocks: %lu. Initiating RMW.\n",
				     stripe_index, stripe_offset, raid_io->num_blocks);
			ret = raid5f_submit_partial_write_request(raid_io, stripe_index, stripe_offset);
		}
		break;
	}
	default:
		ret = -EINVAL;
		break;
	}

	if (spdk_unlikely(ret)) {
		raid_bdev_io_complete(raid_io, ret == -ENOMEM ? SPDK_BDEV_IO_STATUS_NOMEM :
				      SPDK_BDEV_IO_STATUS_FAILED);
	}
}

static void
raid5f_stripe_request_free(struct stripe_request *stripe_req)
{
	struct chunk *chunk;

	FOR_EACH_CHUNK(stripe_req, chunk) {
		free(chunk->iovs);
	}

	if (stripe_req->type == STRIPE_REQ_WRITE) {
		spdk_dma_free(stripe_req->write.parity_buf);
		spdk_dma_free(stripe_req->write.parity_md_buf);
	} else if (stripe_req->type == STRIPE_REQ_RECONSTRUCT) {
		struct raid5f_info *r5f_info = raid5f_ch_to_r5f_info(stripe_req->r5ch);
		struct raid_bdev *raid_bdev = r5f_info->raid_bdev;
		uint8_t i;

		if (stripe_req->reconstruct.chunk_buffers) {
			for (i = 0; i < raid5f_stripe_data_chunks_num(raid_bdev); i++) {
				spdk_dma_free(stripe_req->reconstruct.chunk_buffers[i]);
			}
			free(stripe_req->reconstruct.chunk_buffers);
		}

		if (stripe_req->reconstruct.chunk_md_buffers) {
			for (i = 0; i < raid5f_stripe_data_chunks_num(raid_bdev); i++) {
				spdk_dma_free(stripe_req->reconstruct.chunk_md_buffers[i]);
			}
			free(stripe_req->reconstruct.chunk_md_buffers);
		}
	} else {
		assert(false);
	}

	free(stripe_req->chunk_xor_buffers);
	free(stripe_req->chunk_xor_md_buffers);
	free(stripe_req->chunk_iov_iters);

	free(stripe_req);
}

static struct stripe_request *
raid5f_stripe_request_alloc(struct raid5f_io_channel *r5ch, enum stripe_request_type type)
{
	struct raid5f_info *r5f_info = raid5f_ch_to_r5f_info(r5ch);
	struct raid_bdev *raid_bdev = r5f_info->raid_bdev;
	uint32_t raid_io_md_size = raid_bdev->bdev.md_interleave ? 0 : raid_bdev->bdev.md_len;
	struct stripe_request *stripe_req;
	struct chunk *chunk;
	size_t chunk_len;

	stripe_req = calloc(1, sizeof(*stripe_req) + sizeof(*chunk) * raid_bdev->num_base_bdevs);
	if (!stripe_req) {
		return NULL;
	}

	stripe_req->r5ch = r5ch;
	stripe_req->type = type;

	FOR_EACH_CHUNK(stripe_req, chunk) {
		chunk->index = chunk - stripe_req->chunks;
		chunk->iovcnt_max = 4;
		chunk->iovs = calloc(chunk->iovcnt_max, sizeof(chunk->iovs[0]));
		if (!chunk->iovs) {
			goto err;
		}
	}

	chunk_len = raid_bdev->strip_size * raid_bdev->bdev.blocklen;

	if (type == STRIPE_REQ_WRITE) {
		stripe_req->write.parity_buf = spdk_dma_malloc(chunk_len, r5f_info->buf_alignment, NULL);
		if (!stripe_req->write.parity_buf) {
			goto err;
		}

		if (raid_io_md_size != 0) {
			stripe_req->write.parity_md_buf = spdk_dma_malloc(raid_bdev->strip_size * raid_io_md_size,
							  r5f_info->buf_alignment, NULL);
			if (!stripe_req->write.parity_md_buf) {
				goto err;
			}
		}
	} else if (type == STRIPE_REQ_RECONSTRUCT) {
		uint8_t n = raid5f_stripe_data_chunks_num(raid_bdev);
		void *buf;
		uint8_t i;

		stripe_req->reconstruct.chunk_buffers = calloc(n, sizeof(void *));
		if (!stripe_req->reconstruct.chunk_buffers) {
			goto err;
		}

		for (i = 0; i < n; i++) {
			buf = spdk_dma_malloc(chunk_len, r5f_info->buf_alignment, NULL);
			if (!buf) {
				goto err;
			}
			stripe_req->reconstruct.chunk_buffers[i] = buf;
		}

		if (raid_io_md_size != 0) {
			stripe_req->reconstruct.chunk_md_buffers = calloc(n, sizeof(void *));
			if (!stripe_req->reconstruct.chunk_md_buffers) {
				goto err;
			}

			for (i = 0; i < n; i++) {
				buf = spdk_dma_malloc(raid_bdev->strip_size * raid_io_md_size, r5f_info->buf_alignment, NULL);
				if (!buf) {
					goto err;
				}
				stripe_req->reconstruct.chunk_md_buffers[i] = buf;
			}
		}
	} else {
		assert(false);
		return NULL;
	}

	stripe_req->chunk_iov_iters = malloc(SPDK_IOVITER_SIZE(raid_bdev->num_base_bdevs));
	if (!stripe_req->chunk_iov_iters) {
		goto err;
	}

	stripe_req->chunk_xor_buffers = calloc(raid5f_stripe_data_chunks_num(raid_bdev),
					       sizeof(stripe_req->chunk_xor_buffers[0]));
	if (!stripe_req->chunk_xor_buffers) {
		goto err;
	}

	stripe_req->chunk_xor_md_buffers = calloc(raid5f_stripe_data_chunks_num(raid_bdev),
					   sizeof(stripe_req->chunk_xor_md_buffers[0]));
	if (!stripe_req->chunk_xor_md_buffers) {
		goto err;
	}

	return stripe_req;
err:
	raid5f_stripe_request_free(stripe_req);
	return NULL;
}

static void
raid5f_ioch_destroy(void *io_device, void *ctx_buf)
{
	struct raid5f_io_channel *r5ch = ctx_buf;
	struct stripe_request *stripe_req;

	assert(TAILQ_EMPTY(&r5ch->xor_retry_queue));

	while ((stripe_req = TAILQ_FIRST(&r5ch->free_stripe_requests.write))) {
		TAILQ_REMOVE(&r5ch->free_stripe_requests.write, stripe_req, link);
		raid5f_stripe_request_free(stripe_req);
	}

	while ((stripe_req = TAILQ_FIRST(&r5ch->free_stripe_requests.reconstruct))) {
		TAILQ_REMOVE(&r5ch->free_stripe_requests.reconstruct, stripe_req, link);
		raid5f_stripe_request_free(stripe_req);
	}

	if (r5ch->accel_ch) {
		spdk_put_io_channel(r5ch->accel_ch);
	}

	free(r5ch->chunk_xor_buffers);
	free(r5ch->chunk_xor_iovs);
	free(r5ch->chunk_xor_iovcnt);
}

static int
raid5f_ioch_create(void *io_device, void *ctx_buf)
{
	struct raid5f_io_channel *r5ch = ctx_buf;
	struct raid5f_info *r5f_info = io_device;
	struct raid_bdev *raid_bdev = r5f_info->raid_bdev;
	struct stripe_request *stripe_req;
	int i;

	TAILQ_INIT(&r5ch->free_stripe_requests.write);
	TAILQ_INIT(&r5ch->free_stripe_requests.reconstruct);
	TAILQ_INIT(&r5ch->xor_retry_queue);

	for (i = 0; i < RAID5F_MAX_STRIPES; i++) {
		stripe_req = raid5f_stripe_request_alloc(r5ch, STRIPE_REQ_WRITE);
		if (!stripe_req) {
			goto err;
		}

		TAILQ_INSERT_HEAD(&r5ch->free_stripe_requests.write, stripe_req, link);
	}

	for (i = 0; i < RAID5F_MAX_STRIPES; i++) {
		stripe_req = raid5f_stripe_request_alloc(r5ch, STRIPE_REQ_RECONSTRUCT);
		if (!stripe_req) {
			goto err;
		}

		TAILQ_INSERT_HEAD(&r5ch->free_stripe_requests.reconstruct, stripe_req, link);
	}

	r5ch->accel_ch = spdk_accel_get_io_channel();
	if (!r5ch->accel_ch) {
		SPDK_ERRLOG("Failed to get accel framework's IO channel\n");
		goto err;
	}

	r5ch->chunk_xor_buffers = calloc(raid_bdev->num_base_bdevs, sizeof(*r5ch->chunk_xor_buffers));
	if (!r5ch->chunk_xor_buffers) {
		goto err;
	}

	r5ch->chunk_xor_iovs = calloc(raid_bdev->num_base_bdevs, sizeof(*r5ch->chunk_xor_iovs));
	if (!r5ch->chunk_xor_iovs) {
		goto err;
	}

	r5ch->chunk_xor_iovcnt = calloc(raid_bdev->num_base_bdevs, sizeof(*r5ch->chunk_xor_iovcnt));
	if (!r5ch->chunk_xor_iovcnt) {
		goto err;
	}

	return 0;
err:
	SPDK_ERRLOG("Failed to initialize io channel\n");
	raid5f_ioch_destroy(r5f_info, r5ch);
	return -ENOMEM;
}

static int
raid5f_start(struct raid_bdev *raid_bdev)
{
	uint64_t min_blockcnt = UINT64_MAX;
	uint64_t base_bdev_data_size;
	struct raid_base_bdev_info *base_info;
	struct spdk_bdev *base_bdev;
	struct raid5f_info *r5f_info;
	size_t alignment = 0;

	r5f_info = calloc(1, sizeof(*r5f_info));
	if (!r5f_info) {
		SPDK_ERRLOG("Failed to allocate r5f_info\n");
		return -ENOMEM;
	}
	r5f_info->raid_bdev = raid_bdev;

	RAID_FOR_EACH_BASE_BDEV(raid_bdev, base_info) {
		min_blockcnt = spdk_min(min_blockcnt, base_info->data_size);
		if (base_info->desc) {
			base_bdev = spdk_bdev_desc_get_bdev(base_info->desc);
			alignment = spdk_max(alignment, spdk_bdev_get_buf_align(base_bdev));
		}
	}

	base_bdev_data_size = (min_blockcnt / raid_bdev->strip_size) * raid_bdev->strip_size;

	RAID_FOR_EACH_BASE_BDEV(raid_bdev, base_info) {
		base_info->data_size = base_bdev_data_size;
	}

	r5f_info->total_stripes = min_blockcnt / raid_bdev->strip_size;
	r5f_info->stripe_blocks = raid_bdev->strip_size * raid5f_stripe_data_chunks_num(raid_bdev);
	r5f_info->buf_alignment = alignment;
	if (!raid_bdev->bdev.md_interleave) {
		r5f_info->blocklen_shift = spdk_u32log2(raid_bdev->bdev.blocklen);
	}

	raid_bdev->bdev.blockcnt = r5f_info->stripe_blocks * r5f_info->total_stripes;
	raid_bdev->bdev.optimal_io_boundary = raid_bdev->strip_size;
	raid_bdev->bdev.split_on_optimal_io_boundary = true;
	raid_bdev->bdev.write_unit_size = r5f_info->stripe_blocks;
	raid_bdev->bdev.split_on_write_unit = true;

	raid_bdev->module_private = r5f_info;

	spdk_io_device_register(r5f_info, raid5f_ioch_create, raid5f_ioch_destroy,
				sizeof(struct raid5f_io_channel), NULL);

	return 0;
}

static void
raid5f_io_device_unregister_done(void *io_device)
{
	struct raid5f_info *r5f_info = io_device;

	raid_bdev_module_stop_done(r5f_info->raid_bdev);

	free(r5f_info);
}

static bool
raid5f_stop(struct raid_bdev *raid_bdev)
{
	struct raid5f_info *r5f_info = raid_bdev->module_private;

	spdk_io_device_unregister(r5f_info, raid5f_io_device_unregister_done);

	return false;
}

static struct spdk_io_channel *
raid5f_get_io_channel(struct raid_bdev *raid_bdev)
{
	struct raid5f_info *r5f_info = raid_bdev->module_private;

	return spdk_get_io_channel(r5f_info);
}

static void
raid5f_process_write_completed(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct raid_bdev_process_request *process_req = cb_arg;

	spdk_bdev_free_io(bdev_io);

	raid_bdev_process_request_complete(process_req, success ? 0 : -EIO);
}

static void raid5f_process_submit_write(struct raid_bdev_process_request *process_req);

static void
_raid5f_process_submit_write(void *ctx)
{
	struct raid_bdev_process_request *process_req = ctx;

	raid5f_process_submit_write(process_req);
}

static void
raid5f_process_submit_write(struct raid_bdev_process_request *process_req)
{
	struct raid_bdev_io *raid_io = &process_req->raid_io;
	struct raid_bdev *raid_bdev = raid_io->raid_bdev;
	struct raid5f_info *r5f_info = raid_bdev->module_private;
	uint64_t stripe_index = process_req->offset_blocks / r5f_info->stripe_blocks;
	struct spdk_bdev_ext_io_opts io_opts;
	int ret;

	raid5f_init_ext_io_opts(&io_opts, raid_io);
	ret = raid_bdev_writev_blocks_ext(process_req->target, process_req->target_ch,
					  raid_io->iovs, raid_io->iovcnt,
					  stripe_index << raid_bdev->strip_size_shift, raid_bdev->strip_size,
					  raid5f_process_write_completed, process_req, &io_opts);
	if (spdk_unlikely(ret != 0)) {
		if (ret == -ENOMEM) {
			raid_bdev_queue_io_wait(raid_io, spdk_bdev_desc_get_bdev(process_req->target->desc),
						process_req->target_ch, _raid5f_process_submit_write);
		} else {
			raid_bdev_process_request_complete(process_req, ret);
		}
	}
}

static void
raid5f_process_stripe_request_reconstruct_xor_done(struct stripe_request *stripe_req, int status)
{
	struct raid_bdev_io *raid_io = stripe_req->raid_io;
	struct raid_bdev_process_request *process_req = SPDK_CONTAINEROF(raid_io,
			struct raid_bdev_process_request, raid_io);

	raid5f_stripe_request_release(stripe_req);

	if (status != 0) {
		raid_bdev_process_request_complete(process_req, status);
		return;
	}

	raid5f_process_submit_write(process_req);
}

static int
raid5f_submit_process_request(struct raid_bdev_process_request *process_req,
			      struct raid_bdev_io_channel *raid_ch)
{
	struct spdk_io_channel *ch = spdk_io_channel_from_ctx(raid_ch);
	struct raid_bdev *raid_bdev = spdk_io_channel_get_io_device(ch);
	struct raid5f_info *r5f_info = raid_bdev->module_private;
	struct raid_bdev_io *raid_io = &process_req->raid_io;
	uint8_t chunk_idx = raid_bdev_base_bdev_slot(process_req->target);
	uint64_t stripe_index = process_req->offset_blocks / r5f_info->stripe_blocks;
	struct iovec *iov;
	int ret;

	assert((process_req->offset_blocks % r5f_info->stripe_blocks) == 0);

	if (process_req->num_blocks < r5f_info->stripe_blocks) {
		return 0;
	}

	iov = &process_req->iov;
	iov->iov_len = raid_bdev->strip_size * raid_bdev->bdev.blocklen;
	raid_bdev_io_init(raid_io, raid_ch, SPDK_BDEV_IO_TYPE_READ,
			  process_req->offset_blocks, raid_bdev->strip_size,
			  iov, 1, process_req->md_buf, NULL, NULL);

	ret = raid5f_submit_reconstruct_read(raid_io, stripe_index, chunk_idx, 0,
					     raid5f_process_stripe_request_reconstruct_xor_done);
	if (spdk_likely(ret == 0)) {
		return r5f_info->stripe_blocks;
	} else if (ret < 0) {
		return ret;
	} else {
		return -EINVAL;
	}
}

static struct raid_bdev_module g_raid5f_module = {
	.level = RAID5F,
	.base_bdevs_min = 3,
	.base_bdevs_constraint = {CONSTRAINT_MAX_BASE_BDEVS_REMOVED, 1},
	.start = raid5f_start,
	.stop = raid5f_stop,
	.submit_rw_request = raid5f_submit_rw_request,
	.get_io_channel = raid5f_get_io_channel,
	.submit_process_request = raid5f_submit_process_request,
};
RAID_MODULE_REGISTER(&g_raid5f_module)

SPDK_LOG_REGISTER_COMPONENT(bdev_raid5f)
