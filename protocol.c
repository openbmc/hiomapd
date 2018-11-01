// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2018 IBM Corp.
#include "config.h"

#include <errno.h>
#include <stdint.h>

#include "common.h"
#include "flash.h"
#include "mboxd.h"
#include "lpc.h"
#include "windows.h"

#define BLOCK_SIZE_SHIFT_V1		12 /* 4K */

static inline uint8_t protocol_get_bmc_event_mask(struct mbox_context *context)
{
	if (context->version == API_VERSION_1) {
		return BMC_EVENT_V1_MASK;
	}

	return BMC_EVENT_V2_MASK;
}

/*
 * protocol_events_set() - Set BMC events
 * @context:	The mbox context pointer
 * @bmc_event:	The bits to set
 *
 * Return:	0 on success otherwise negative error code
 */
int protocol_events_set(struct mbox_context *context, uint8_t bmc_event)
{
	const uint8_t mask = protocol_get_bmc_event_mask(context);

	/*
	 * Store the raw value, as we may up- or down- grade the protocol
	 * version and subsequently need to flush the appropriate set. Instead
	 * we pass the masked value through to the transport
	 */
	context->bmc_events |= bmc_event;

	return context->transport->set_events(context, bmc_event, mask);
}

/*
 * protocol_events_clear() - Clear BMC events
 * @context:	The mbox context pointer
 * @bmc_event:	The bits to clear
 *
 * Return:	0 on success otherwise negative error code
 */
int protocol_events_clear(struct mbox_context *context, uint8_t bmc_event)
{
	const uint8_t mask = protocol_get_bmc_event_mask(context);

	context->bmc_events &= ~bmc_event;

	return context->transport->clear_events(context, bmc_event, mask);
}

int protocol_v1_reset(struct mbox_context *context)
{
	/* Host requested it -> No BMC Event */
	windows_reset_all(context);
	return lpc_reset(context);
}

int protocol_v1_get_info(struct mbox_context *context,
			 struct protocol_get_info *io)
{
	uint8_t old_version = context->version;
	int rc;

	/* Bootstrap protocol version. This may involve {up,down}grading */
	rc = protocol_negotiate_version(context, io->req.api_version);
	if (rc < 0)
		return rc;

	/* Do the {up,down}grade if necessary*/
	if (rc != old_version) {
		/* Doing version negotiation, don't alert host to reset */
		windows_reset_all(context);
		return context->protocol->get_info(context, io);
	}

	/* Record the negotiated version for the response */
	io->resp.api_version = rc;

	/* Now do all required intialisation for v1 */
	context->block_size_shift = BLOCK_SIZE_SHIFT_V1;
	MSG_INFO("Block Size: 0x%.8x (shift: %u)\n",
		 1 << context->block_size_shift, context->block_size_shift);

	/* Knowing blocksize we can allocate the window dirty_bytemap */
	windows_alloc_dirty_bytemap(context);

	io->resp.v1.read_window_size =
		context->windows.default_size >> context->block_size_shift;
	io->resp.v1.write_window_size =
		context->windows.default_size >> context->block_size_shift;

	return lpc_map_memory(context);
}

int protocol_v1_get_flash_info(struct mbox_context *context,
			       struct protocol_get_flash_info *io)
{
	io->resp.v1.flash_size = context->flash_size;
	io->resp.v1.erase_size = context->mtd_info.erasesize;

	return 0;
}

/*
 * get_lpc_addr_shifted() - Get lpc address of the current window
 * @context:		The mbox context pointer
 *
 * Return:	The lpc address to access that offset shifted by block size
 */
static inline uint16_t get_lpc_addr_shifted(struct mbox_context *context)
{
	uint32_t lpc_addr, mem_offset;

	/* Offset of the current window in the reserved memory region */
	mem_offset = context->current->mem - context->mem;
	/* Total LPC Address */
	lpc_addr = context->lpc_base + mem_offset;

	MSG_DBG("LPC address of current window: 0x%.8x\n", lpc_addr);

	return lpc_addr >> context->block_size_shift;
}

int protocol_v1_create_window(struct mbox_context *context,
			      struct protocol_create_window *io)
{
	int rc;
	uint32_t offset = io->req.offset << context->block_size_shift;

	/* Close the current window if there is one */
	if (context->current) {
		/* There is an implicit flush if it was a write window
		 *
		 * protocol_v2_create_window() calls
		 * protocol_v1_create_window(), so use indirect call to
		 * write_flush() to make sure we pick the right one.
		 */
		if (context->current_is_write) {
			rc = context->protocol->flush(context, NULL);
			if (rc < 0) {
				MSG_ERR("Couldn't Flush Write Window\n");
				return rc;
			}
		}
		windows_close_current(context, FLAGS_NONE);
	}

	/* Offset the host has requested */
	MSG_INFO("Host requested flash @ 0x%.8x\n", offset);
	/* Check if we have an existing window */
	context->current = windows_search(context, offset,
					  context->version == API_VERSION_1);

	if (!context->current) { /* No existing window */
		MSG_DBG("No existing window which maps that flash offset\n");
		rc = windows_create_map(context, &context->current,
				       offset,
				       context->version == API_VERSION_1);
		if (rc < 0) { /* Unable to map offset */
			MSG_ERR("Couldn't create window mapping for offset 0x%.8x\n",
				offset);
			return rc;
		}
	}

	context->current_is_write = !io->req.ro;

	MSG_INFO("Window @ %p for size 0x%.8x maps flash offset 0x%.8x\n",
		 context->current->mem, context->current->size,
		 context->current->flash_offset);

	io->resp.lpc_address = get_lpc_addr_shifted(context);

	return 0;
}

int protocol_v1_mark_dirty(struct mbox_context *context,
			   struct protocol_mark_dirty *io)
{
	uint32_t offset = io->req.v1.offset;
	uint32_t size = io->req.v1.size;
	uint32_t off;

	if (!(context->current && context->current_is_write)) {
		MSG_ERR("Tried to call mark dirty without open write window\n");
		return -EPERM;
	}

	/* For V1 offset given relative to flash - we want the window */
	off = offset - ((context->current->flash_offset) >>
			context->block_size_shift);
	if (off > offset) { /* Underflow - before current window */
		MSG_ERR("Tried to mark dirty before start of window\n");
		MSG_ERR("requested offset: 0x%x window start: 0x%x\n",
				offset << context->block_size_shift,
				context->current->flash_offset);
		return -EINVAL;
	}
	offset = off;
	/*
	 * We only track dirty at the block level.
	 * For protocol V1 we can get away with just marking the whole
	 * block dirty.
	 */
	size = align_up(size, 1 << context->block_size_shift);
	size >>= context->block_size_shift;

	MSG_INFO("Dirty window @ 0x%.8x for 0x%.8x\n",
		 offset << context->block_size_shift,
		 size << context->block_size_shift);

	return window_set_bytemap(context, context->current, offset, size,
				  WINDOW_DIRTY);
}

static int generic_flush(struct mbox_context *context)
{
	int rc, i, offset, count;
	uint8_t prev;

	offset = 0;
	count = 0;
	prev = WINDOW_CLEAN;

	MSG_INFO("Flush window @ %p for size 0x%.8x which maps flash @ 0x%.8x\n",
		 context->current->mem, context->current->size,
		 context->current->flash_offset);

	/*
	 * We look for streaks of the same type and keep a count, when the type
	 * (dirty/erased) changes we perform the required action on the backing
	 * store and update the current streak-type
	 */
	for (i = 0; i < (context->current->size >> context->block_size_shift);
			i++) {
		uint8_t cur = context->current->dirty_bmap[i];
		if (cur != WINDOW_CLEAN) {
			if (cur == prev) { /* Same as previous block, incrmnt */
				count++;
			} else if (prev == WINDOW_CLEAN) { /* Start of run */
				offset = i;
				count++;
			} else { /* Change in streak type */
				rc = window_flush(context, offset, count,
						       prev);
				if (rc < 0) {
					return rc;
				}
				offset = i;
				count = 1;
			}
		} else {
			if (prev != WINDOW_CLEAN) { /* End of a streak */
				rc = window_flush(context, offset, count,
						       prev);
				if (rc < 0) {
					return rc;
				}
				offset = 0;
				count = 0;
			}
		}
		prev = cur;
	}

	if (prev != WINDOW_CLEAN) { /* Still the last streak to write */
		rc = window_flush(context, offset, count, prev);
		if (rc < 0) {
			return rc;
		}
	}

	/* Clear the dirty bytemap since we have written back all changes */
	return window_set_bytemap(context, context->current, 0,
				  context->current->size >>
				  context->block_size_shift,
				  WINDOW_CLEAN);
}

int protocol_v1_flush(struct mbox_context *context, struct protocol_flush *io)
{
	int rc;

	if (!(context->current && context->current_is_write)) {
		MSG_ERR("Tried to call flush without open write window\n");
		return -EPERM;
	}

	/*
	 * For V1 the Flush command acts much the same as the dirty command
	 * except with a flush as well. Only do this on an actual flush
	 * command not when we call flush because we've implicitly closed a
	 * window because we might not have the required args in req.
	 */
	if (io) {
		struct protocol_mark_dirty *mdio = (void *)io;
		rc = protocol_v1_mark_dirty(context, mdio);
		if (rc < 0) {
			return rc;
		}
	}

	return generic_flush(context);
}

int protocol_v1_close(struct mbox_context *context, struct protocol_close *io)
{
	int rc;

	/* Close the current window if there is one */
	if (!context->current) {
		return 0;
	}

	/* There is an implicit flush if it was a write window */
	if (context->current_is_write) {
		rc = protocol_v1_flush(context, NULL);
		if (rc < 0) {
			MSG_ERR("Couldn't Flush Write Window\n");
			return rc;
		}
	}

	/* Host asked for it -> Don't set the BMC Event */
	windows_close_current(context, io->req.flags);

	return 0;
}

int protocol_v1_ack(struct mbox_context *context, struct protocol_ack *io)
{
	return protocol_events_clear(context,
				     (io->req.flags & BMC_EVENT_ACK_MASK));
}

/*
 * get_suggested_timeout() - get the suggested timeout value in seconds
 * @context:	The mbox context pointer
 *
 * Return:	Suggested timeout in seconds
 */
static uint16_t get_suggested_timeout(struct mbox_context *context)
{
	struct window_context *window = windows_find_largest(context);
	uint32_t max_size_mb = window ? (window->size >> 20) : 0;
	uint16_t ret;

	ret = align_up(max_size_mb * FLASH_ACCESS_MS_PER_MB, 1000) / 1000;

	MSG_DBG("Suggested Timeout: %us, max window size: %uMB, for %dms/MB\n",
		ret, max_size_mb, FLASH_ACCESS_MS_PER_MB);
	return ret;
}

int protocol_v2_get_info(struct mbox_context *context,
			 struct protocol_get_info *io)
{
	uint8_t old_version = context->version;
	int rc;

	/* Bootstrap protocol version. This may involve {up,down}grading */
	rc = protocol_negotiate_version(context, io->req.api_version);
	if (rc < 0)
		return rc;

	/* Do the {up,down}grade if necessary*/
	if (rc != old_version) {
		/* Doing version negotiation, don't alert host to reset */
		windows_reset_all(context);
		return context->protocol->get_info(context, io);
	}

	/* Record the negotiated version for the response */
	io->resp.api_version = rc;

	/* Now do all required intialisation for v2 */
	context->block_size_shift = log_2(context->mtd_info.erasesize);
	MSG_INFO("Block Size: 0x%.8x (shift: %u)\n",
		 1 << context->block_size_shift, context->block_size_shift);

	/* Knowing blocksize we can allocate the window dirty_bytemap */
	windows_alloc_dirty_bytemap(context);

	io->resp.v2.block_size_shift = context->block_size_shift;
	io->resp.v2.timeout = get_suggested_timeout(context);

	return lpc_map_memory(context);
}

int protocol_v2_get_flash_info(struct mbox_context *context,
			       struct protocol_get_flash_info *io)
{
	io->resp.v2.flash_size =
		context->flash_size >> context->block_size_shift;
	io->resp.v2.erase_size =
		context->mtd_info.erasesize >> context->block_size_shift;

	return 0;
}

int protocol_v2_create_window(struct mbox_context *context,
			      struct protocol_create_window *io)
{
	int rc;

	rc = protocol_v1_create_window(context, io);
	if (rc < 0)
		return rc;

	io->resp.size = context->current->size >> context->block_size_shift;
	io->resp.offset = context->current->flash_offset >>
					context->block_size_shift;

	return 0;
}

int protocol_v2_mark_dirty(struct mbox_context *context,
			   struct protocol_mark_dirty *io)
{
	if (!(context->current && context->current_is_write)) {
		MSG_ERR("Tried to call mark dirty without open write window\n");
		return -EPERM;
	}

	MSG_INFO("Dirty window @ 0x%.8x for 0x%.8x\n",
		 io->req.v2.offset << context->block_size_shift,
		 io->req.v2.size << context->block_size_shift);

	return window_set_bytemap(context, context->current, io->req.v2.offset,
				  io->req.v2.size, WINDOW_DIRTY);
}

int protocol_v2_erase(struct mbox_context *context,
		      struct protocol_erase *io)
{
	size_t start, len;
	int rc;

	if (!(context->current && context->current_is_write)) {
		MSG_ERR("Tried to call erase without open write window\n");
		return -EPERM;
	}

	MSG_INFO("Erase window @ 0x%.8x for 0x%.8x\n",
		 io->req.offset << context->block_size_shift,
		 io->req.size << context->block_size_shift);

	rc = window_set_bytemap(context, context->current, io->req.offset,
				io->req.size, WINDOW_ERASED);
	if (rc < 0) {
		return rc;
	}

	/* Write 0xFF to mem -> This ensures consistency between flash & ram */
	start = io->req.offset << context->block_size_shift;
	len = io->req.size << context->block_size_shift;
	memset(context->current->mem + start, 0xFF, len);

	return 0;
}

int protocol_v2_flush(struct mbox_context *context, struct protocol_flush *io)
{
	if (!(context->current && context->current_is_write)) {
		MSG_ERR("Tried to call flush without open write window\n");
		return -EPERM;
	}

	return generic_flush(context);
}

int protocol_v2_close(struct mbox_context *context, struct protocol_close *io)
{
	int rc;

	/* Close the current window if there is one */
	if (!context->current) {
		return 0;
	}

	/* There is an implicit flush if it was a write window */
	if (context->current_is_write) {
		rc = protocol_v2_flush(context, NULL);
		if (rc < 0) {
			MSG_ERR("Couldn't Flush Write Window\n");
			return rc;
		}
	}

	/* Host asked for it -> Don't set the BMC Event */
	windows_close_current(context, io->req.flags);

	return 0;
}

int protocol_init(struct mbox_context *context)
{
	protocol_negotiate_version(context, API_MAX_VERSION);

	return 0;
}

void protocol_free(struct mbox_context *context)
{
	return;
}
