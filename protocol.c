// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2018 IBM Corp.
#include "config.h"

#include <errno.h>
#include <stdint.h>

#include "mbox.h"
#include "lpc.h"
#include "transport_mbox.h" /* TODO: Remove dependency on transport_mbox.h */
#include "windows.h"

int protocol_v1_reset(struct mbox_context *context)
{
	/* Host requested it -> No BMC Event */
	windows_reset_all(context, NO_BMC_EVENT);
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
		windows_reset_all(context, SET_BMC_EVENT);
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

int protocol_v1_create_read_window(struct mbox_context *context,
				   struct protocol_create_window *io)
{
	int rc;
	uint32_t offset = io->req.offset << context->block_size_shift;

	/* Close the current window if there is one */
	if (context->current) {
		/* There is an implicit flush if it was a write window */
		if (context->current_is_write) {
			rc = mbox_handle_flush_window(context, NULL, NULL);
			if (rc < 0) {
				MSG_ERR("Couldn't Flush Write Window\n");
				return rc;
			}
		}
		windows_close_current(context, NO_BMC_EVENT, FLAGS_NONE);
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
				io->req.offset);
			return rc;
		}
	}

	MSG_INFO("Window @ %p for size 0x%.8x maps flash offset 0x%.8x\n",
		 context->current->mem, context->current->size,
		 context->current->flash_offset);

	io->resp.lpc_address = get_lpc_addr_shifted(context);

	return 0;
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
		windows_reset_all(context, SET_BMC_EVENT);
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

int protocol_v2_create_read_window(struct mbox_context *context,
				   struct protocol_create_window *io)
{
	int rc;

	rc = protocol_v1_create_read_window(context, io);
	if (rc < 0)
		return rc;

	io->resp.size = context->current->size >> context->block_size_shift;
	io->resp.offset = context->current->flash_offset >>
					context->block_size_shift;

	return 0;
}

static const struct protocol_ops protocol_ops_v1 = {
	.reset = protocol_v1_reset,
	.get_info = protocol_v1_get_info,
	.get_flash_info = protocol_v1_get_flash_info,
	.create_read_window = protocol_v1_create_read_window,
};

static const struct protocol_ops protocol_ops_v2 = {
	.reset = protocol_v1_reset,
	.get_info = protocol_v2_get_info,
	.get_flash_info = protocol_v2_get_flash_info,
	.create_read_window = protocol_v2_create_read_window,

};

static const struct protocol_ops *protocol_ops_map[] = {
	[0] = NULL,
	[1] = &protocol_ops_v1,
	[2] = &protocol_ops_v2,
};

int protocol_negotiate_version(struct mbox_context *context,
				   uint8_t requested)
{
	/* Check we support the version requested */
	if (requested < API_MIN_VERSION)
		return -EINVAL;

	context->version = (requested > API_MAX_VERSION) ?
				API_MAX_VERSION : requested;

	context->protocol = protocol_ops_map[context->version];

	return context->version;
}

int protocol_init(struct mbox_context *context)
{
	context->version = API_MAX_VERSION;
	context->protocol = protocol_ops_map[context->version];

	return 0;
}

void protocol_free(struct mbox_context *context)
{
	return;
}
