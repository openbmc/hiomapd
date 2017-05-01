/*
 * Mailbox Daemon Window Helpers
 *
 * Copyright 2017 IBM
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdint.h>
#include <stdlib.h>
#include <syslog.h>

extern "C" {
#include "common.h"
}

#include "mboxd_flash.h"
#include "mboxd_pnor_partition_table.h"

/*
 * copy_flash() - Copy data from the virtual pnor into a provided buffer
 * @context:    The mbox context pointer
 * @offset:     The pnor offset to copy from (bytes)
 * @mem:        The buffer to copy into (must be of atleast 'size' bytes)
 * @size:       The number of bytes to copy
 *
 * Return:      0 on success otherwise negative error code
 */
int copy_flash(struct mbox_context *context, uint32_t offset, void *mem,
	       uint32_t size)
{
	int rc = 0;

	MSG_DBG("Copy virtual pnor to %p for size 0x%.8x from offset 0x%.8x\n",
		mem, size, offset);

	/* The virtual PNOR partition table starts at offset 0 in the virtual
	 * pnor image. Check if host asked for an offset that lies within the
	 * partition table.
	 */
	size_t sz =
	vpnor_get_partition_table_size(context) << context->block_size_shift;
	if (offset < sz) {
		struct pnor_partition_table* table =
			vpnor_get_partition_table(context);
		memcpy(mem,
		       ((uint8_t *)table) + offset,
		       min_u32(sz - offset, size));
		free(table);
	}

	return rc;
}
