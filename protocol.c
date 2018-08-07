// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2018 IBM Corp.
#include "config.h"

#include <errno.h>
#include <stdint.h>

#include "mbox.h"
#include "lpc.h"
#include "transport_mbox.h" /* TODO: Remove dependency on transport_mbox.h */
#include "windows.h"

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

static const struct protocol_ops protocol_ops_v1 = {
	.get_info = protocol_v1_get_info,
};

static const struct protocol_ops protocol_ops_v2 = {
	.get_info = protocol_v2_get_info,
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
