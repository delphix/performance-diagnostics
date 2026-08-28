/*
 * Copyright 2019 Delphix. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <uapi/linux/ptrace.h>
#include <linux/bpf_common.h>
#include <uapi/linux/bpf.h>

/*
 * Avoid block-layer kernel headers: <linux/blkdev.h>, <linux/blk-mq.h>, and
 * <linux/blk_types.h> all chain to <linux/fs.h>, which has a Clang-fatal
 * static_assert on sizeof(struct filename).  <linux/bpf_common.h> above is
 * safe — it does not reach fs.h.  cmd/estat.py skips the ZFS SPL preamble
 * for this program since it accesses no ZFS kernel symbols.
 *
 * Forward-declare only the structs and constants this program accesses.
 */

typedef unsigned char       blk_status_t;
#define BLK_STS_OK          ((blk_status_t)0)

typedef unsigned int        blk_opf_t;
#define REQ_OP_BITS         8
#define REQ_OP_MASK         ((blk_opf_t)((1 << REQ_OP_BITS) - 1))
#define REQ_OP_WRITE        ((blk_opf_t)1)

typedef unsigned long long  sector_t;   /* u64 on x86-64 */
typedef unsigned int        req_flags_t;

#define DISK_NAME_LEN       32

struct blk_mq_ctx;
struct blk_mq_hw_ctx;

/*
 * Minimal struct bio — only bi_status is accessed.
 * Verified layout (blk_types.h:210, kernel 7.0.0-1011-dx2026082023):
 *   bi_next       +0  8B (struct bio *)
 *   bi_bdev       +8  8B (struct block_device *)
 *   bi_opf        +16 4B (blk_opf_t)
 *   bi_flags      +20 2B (unsigned short)
 *   bi_ioprio     +22 2B (unsigned short)
 *   bi_write_hint +24 1B (enum rw_hint; sizeof==1 per rw_hint.h static_assert)
 *   bi_write_stream +25 1B (u8)
 *   bi_status     +26 1B (blk_status_t)
 */
struct block_device;
struct bio {
	struct bio		*bi_next;
	struct block_device	*bi_bdev;
	blk_opf_t		bi_opf;
	unsigned short		bi_flags;
	unsigned short		bi_ioprio;
	unsigned char		bi_write_hint;	/* enum rw_hint, sizeof == 1 */
	unsigned char		bi_write_stream;
	blk_status_t		bi_status;
};

/*
 * Minimal struct gendisk — only disk_name is accessed.
 * Verified layout (blkdev.h:145, kernel 7.0.0-1011-dx2026082023):
 *   major         +0  4B
 *   first_minor   +4  4B
 *   minors        +8  4B
 *   disk_name     +12 32B
 */
struct gendisk {
	int	major;
	int	first_minor;
	int	minors;
	char	disk_name[DISK_NAME_LEN];
};

/*
 * Minimal struct block_device — only bd_disk is accessed.
 * Verified layout (blk_types.h:41, kernel 7.0.0-1011-dx2026082023):
 *   bd_start_sect +0  8B (sector_t)
 *   bd_nr_sectors +8  8B (sector_t)
 *   bd_disk       +16 8B (struct gendisk *)
 */
struct block_device {
	sector_t	bd_start_sect;
	sector_t	bd_nr_sectors;
	struct gendisk	*bd_disk;
};

/*
 * Minimal struct request — fields accessed: cmd_flags(+24), __data_len(+44),
 * bio(+56), part(+88).  q(+0) is void* — not dereferenced; disk name is
 * retrieved via part->bd_disk to avoid needing the full request_queue layout.
 * Verified layout (blk-mq.h:105, kernel 7.0.0-1011-dx2026082023):
 *   q             +0  8B  (request_queue *, opaque)
 *   mq_ctx        +8  8B
 *   mq_hctx       +16 8B
 *   cmd_flags     +24 4B  (blk_opf_t)
 *   rq_flags      +28 4B  (req_flags_t)
 *   tag           +32 4B
 *   internal_tag  +36 4B
 *   timeout       +40 4B
 *   __data_len    +44 4B
 *   __sector      +48 8B  (sector_t)
 *   bio           +56 8B
 *   biotail       +64 8B
 *   union{list_head(16B)/rq_next(8B)} +72 16B
 *   part          +88 8B  (struct block_device *)
 */
struct request {
	void			*q;		/* request_queue — opaque, not dereferenced */
	struct blk_mq_ctx	*mq_ctx;
	struct blk_mq_hw_ctx	*mq_hctx;
	blk_opf_t		cmd_flags;
	req_flags_t		rq_flags;
	int			tag;
	int			internal_tag;
	unsigned int		timeout;
	unsigned int		__data_len;
	sector_t		__sector;
	struct bio		*bio;
	struct bio		*biotail;
	union {
		struct {
			void	*next;
			void	*prev;
		} queuelist;		/* struct list_head = 2 pointers = 16 bytes */
		void		*rq_next;
	};
	struct block_device	*part;
};


// Definitions for this script
#define	READ_STR "read "
#define	WRITE_STR "write "
#define	OP_NAME_LEN 7
#define	NAME_LENGTH (OP_NAME_LEN + 1)
#define	AXIS_LENGTH (DISK_NAME_LEN + 1)

// Structure to hold thread local data
typedef struct {
	u64 ts;
	unsigned int size;
	unsigned int cmd_flags;
	u32 err;
	char device[DISK_NAME_LEN];
} io_data_t;

BPF_HASH(io_base_data, u64, io_data_t);

// @@ raw_tracepoint|block_io_start|disk_io_start
int
disk_io_start(struct bpf_raw_tracepoint_args *ctx)
{
	struct request *reqp = (struct request *)ctx->args[0];

	io_data_t data = {};
	struct gendisk *diskp = reqp->part->bd_disk;
	data.ts = bpf_ktime_get_ns();
	data.cmd_flags = reqp->cmd_flags;
	data.size = reqp->__data_len;
	bpf_probe_read_str(&data.device, DISK_NAME_LEN, diskp->disk_name);
	io_base_data.update((u64 *) &reqp, &data);
	return (0);
}

// @@ raw_tracepoint|block_io_done|disk_io_done
int
disk_io_done(struct bpf_raw_tracepoint_args *ctx)
{
	struct request *reqp = (struct request *)ctx->args[0];

	u64 ts = bpf_ktime_get_ns();
	io_data_t *data = io_base_data.lookup((u64 *) &reqp);
	struct bio *bp = reqp->bio;

	if (data == 0) {
		return (0);   // missed issue
	}

	u64 delta = ts - data->ts;
	char name[NAME_LENGTH] = "";
	char axis[AXIS_LENGTH] = "";

	data->err = (bp->bi_status == BLK_STS_OK) ? 0 : 1;

	if ((data->cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE) {
		__builtin_memcpy(&name, WRITE_STR, OP_NAME_LEN);
	} else {
		__builtin_memcpy(&name, READ_STR, OP_NAME_LEN);
	}

#ifdef OPTARG
	if ((sizeof (OPTARG) == 4) && (OPTARG[0] == 'l') &&
	    (OPTARG[1] == 'u') && (OPTARG[2] == 'n')) {
		__builtin_memcpy(&axis, data->device, AXIS_LENGTH);
	}
#endif

	// Perform aggregations
	AGGREGATE_DATA(name, axis, delta, data->size);
	io_base_data.delete((u64 *) &reqp);
	return (0);
}
