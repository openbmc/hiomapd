// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2018 IBM Corp.

#define _GNU_SOURCE

#include "lpc.h"

struct mbox_context;

/*
 * lpc_reset() - Reset the lpc bus mapping
 * @context:	The mbox context pointer
 *
 * Return:	0 on success otherwise negative error code
 */
int lpc_reset(struct mbox_context *context)
{
	if(context->filename)
	{
		/*
		 * We are running from a file instead of /dev/mtd/pnor
		 * During init, we preloaded the file contents to the
		 *   memory mapped window, so it's safe to point to mem.
		*/
		return lpc_map_memory(context);
	}
	else
	{
		/*
		 * We are pointing directly to the flash device,
		 */
		return lpc_map_flash(context);
        }
}
