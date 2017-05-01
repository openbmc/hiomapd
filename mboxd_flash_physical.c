/*
 * Mailbox Daemon Flash Helpers
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

#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <mtd/mtd-abi.h>

#include "mbox.h"
#include "common.h"
#include "mboxd_flash.h"

#define CHUNKSIZE (64 * 1024)

/*
 * copy_flash() - Copy data from the flash device into a provided buffer
 * @context:	The mbox context pointer
 * @offset:	The flash offset to copy from (bytes)
 * @mem:	The buffer to copy into (must be of atleast 'size' bytes)
 * @size:	The number of bytes to copy
 *
 * Return:	0 on success otherwise negative error code
 */
int copy_flash(struct mbox_context *context, uint32_t offset, void *mem,
	       uint32_t size)
{
	int32_t size_read;

	MSG_DBG("Copy flash to %p for size 0x%.8x from offset 0x%.8x\n",
		mem, size, offset);
	if (lseek(context->fds[MTD_FD].fd, offset, SEEK_SET) != offset) {
		MSG_ERR("Couldn't seek flash at pos: %u %s\n", offset,
			strerror(errno));
		return -MBOX_R_SYSTEM_ERROR;
	}

	do {
		size_read = read(context->fds[MTD_FD].fd, mem,
					  min_u32(CHUNKSIZE, size));
		if (size_read < 0) {
			MSG_ERR("Couldn't copy mtd into ram: %s\n",
				strerror(errno));
			return -MBOX_R_SYSTEM_ERROR;
		}

		size -= size_read;
		mem += size_read;
	} while (size && size_read);

	return size ? -MBOX_R_SYSTEM_ERROR : 0;
}
