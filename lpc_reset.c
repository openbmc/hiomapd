// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2018 IBM Corp.

#define _GNU_SOURCE

#include "mbox.h"
#include "lpc.h"

/*
 * reset_lpc() - Reset the lpc bus mapping
 * @context:	The mbox context pointer
 *
 * Return:	0 on success otherwise negative error code
 */
int reset_lpc(struct mbox_context *context)
{
	return point_to_flash(context);
}
