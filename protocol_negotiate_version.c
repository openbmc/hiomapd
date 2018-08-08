// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2018 IBM Corp.
#include "config.h"

#include <errno.h>

#include "mbox.h"
#include "protocol.h"

static const struct protocol_ops protocol_ops_v1 = {
	.reset = protocol_v1_reset,
	.get_info = protocol_v1_get_info,
	.get_flash_info = protocol_v1_get_flash_info,
	.create_window = protocol_v1_create_window,
	.mark_dirty = protocol_v1_mark_dirty,
	.erase = NULL,
	.flush = protocol_v1_flush,
	.close = protocol_v1_close,
	.ack = protocol_v1_ack,
};

static const struct protocol_ops protocol_ops_v2 = {
	.reset = protocol_v1_reset,
	.get_info = protocol_v2_get_info,
	.get_flash_info = protocol_v2_get_flash_info,
	.create_window = protocol_v2_create_window,
	.mark_dirty = protocol_v2_mark_dirty,
	.erase = protocol_v2_erase,
	.flush = protocol_v2_flush,
	.close = protocol_v2_close,
	.ack = protocol_v1_ack,
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
