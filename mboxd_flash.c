/*
 * Mailbox Daemon Flash Helpers
 *
 * Copyright 2016 IBM
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
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>
#include <mtd/mtd-abi.h>

#include "mbox.h"
#include "common.h"
#include "mboxd_flash.h"

#define MSG_OUT(f_, ...)	do { if (verbosity >= MBOX_LOG_DEBUG) { \
				    mbox_log(LOG_INFO, f_, ##__VA_ARGS__); } \
				} while (0)
#define MSG_ERR(f_, ...)	do { if (verbosity >= MBOX_LOG_VERBOSE) { \
				    mbox_log(LOG_ERR, f_, ##__VA_ARGS__); } \
				} while (0)

int init_flash_dev(struct mbox_context *context)
{
	char *filename = get_dev_mtd();
	int fd, rc = 0;

	if (!filename) {
		MSG_ERR("Couldn't find the PNOR /dev/mtd partition\n");
		return -1;
	}

	MSG_OUT("Opening %s\n", filename);

	/* Open Flash Device */
	fd = open(filename, O_RDWR);
	if (fd < 0) {
		MSG_ERR("Couldn't open %s with flags O_RDWR: %s\n",
			filename, strerror(errno));
		rc = -errno;
		goto out;
	}
	context->fds[MTD_FD].fd = fd;

	/* Read the Flash Info */
	if (ioctl(fd, MEMGETINFO, &context->mtd_info) == -1) {
		MSG_ERR("Couldn't get information about MTD: %s\n",
			strerror(errno));
		rc = -1;
		goto out;
	}

	/* We know the erase size so we can allocate the flash_erased bytemap */
	context->erase_size_shift = log_2(context->mtd_info.erasesize);
	context->flash_bmap = calloc(context->flash_size >>
				     context->erase_size_shift,
				     sizeof(*context->flash_bmap));

out:
	free(filename);
	return rc;
}

/* Flash Functions */

#define CHUNKSIZE (64 * 1024)

/*
 * copy_flash() - Copy data from the flash device into a provided buffer
 * @context:	The mbox context pointer
 * @offset:	The flash offset to copy from (bytes)
 * @mem:	The buffer to copy into (must be of atleast size)
 * @size:	The number of bytes to copy
 *
 * Return:	0 on success otherwise negative error code
 */
int copy_flash(struct mbox_context *context, uint32_t offset, void *mem,
	       uint32_t size)
{
	MSG_OUT("Loading flash at %p for 0x%08x bytes from offset 0x%.8x\n",
							mem, size, offset);
	if (lseek(context->fds[MTD_FD].fd, offset, SEEK_SET) != offset) {
		MSG_ERR("Couldn't seek flash at pos: %u %s\n", offset,
			strerror(errno));
		return -MBOX_R_SYSTEM_ERROR;
	}

	while (size) {
		uint32_t size_read = read(context->fds[MTD_FD].fd, mem,
					  min_u32(CHUNKSIZE, size));
		if (size_read < 0) {
			MSG_ERR("Couldn't copy mtd into ram: %d. %s\n",
				size_read, strerror(size_read));
			return -MBOX_R_SYSTEM_ERROR;
		}

		size -= size_read;
		mem += size_read;
	}

	return 0;
}

/*
 * flash_is_erased() - Check if an offset into flash is erased
 * @context:	The mbox context pointer
 * @offset:	The flash offset to check (bytes)
 *
 * Return:	true if erased otherwise false
 */
static inline bool flash_is_erased(struct mbox_context *context,
				   uint32_t offset)
{
	return context->flash_bmap[offset >> context->erase_size_shift]
			== FLASH_ERASED;
}

/*
 * set_flash_bytemap() - Set the flash erased bytemap
 * @context:	The mbox context pointer
 * @offset:	The flash offset to set (bytes)
 * @count:	Number of bytes to set
 * @val:	Value to set the bytemap to
 *
 * The flash bytemap only tracks the erased status at the erase block level so
 * this will update the erased state for an (or many) erase blocks
 *
 * Return:	0 if success otherwise negative error code
 */
int set_flash_bytemap(struct mbox_context *context, uint32_t offset,
		      uint32_t count, uint8_t val)
{
	if ((offset + count) > context->flash_size) {
		return -MBOX_R_PARAM_ERROR;
	}

	memset(context->flash_bmap + (offset >> context->erase_size_shift),
	       val,
	       ALIGN_UP(count, 1 << context->erase_size_shift) >>
	       context->erase_size_shift);

	return 0;
}

/*
 * erase_flash() - Erase the flash
 * @context:	The mbox context pointer
 * @offset:	The flash offset to erase (bytes)
 * @size:	The number of bytes to erase
 *
 * Return:	0 on success otherwise negative error code
 */
int erase_flash(struct mbox_context *context, uint32_t offset, uint32_t count)
{
	const uint32_t erase_size = 1 << context->erase_size_shift;
	struct erase_info_user erase_info = { 0 };
	int rc;

	MSG_OUT("Erasing 0x%.8x for 0x%.8x\n", offset, count);

	/*
	 * We have an erased_bytemap for the flash so we want to avoid erasing
	 * blocks which we already know to be erased. Look for runs of blocks
	 * which aren't erased and erase the entire run at once to avoid how
	 * often we have to call the erase ioctl. If the block is already
	 * erased then there's nothing we need to do.
	 */
	while (count) {
		if (!flash_is_erased(context, offset)) { /* Need to erase */
			if (!erase_info.length) { /* Start of not-erased run */
				erase_info.start = offset;
			}
			erase_info.length += erase_size;
		} else if (erase_info.length) { /* Already erased|end of run? */
			/* Erase the previous run which just ended */
			rc = ioctl(context->fds[MTD_FD].fd, MEMERASE,
				   &erase_info);
			if (rc < 0) {
				MSG_ERR("Couldn't erase flash at 0x%.8x\n",
						erase_info.start);
				return -MBOX_R_SYSTEM_ERROR;
			}
			/* Mark ERASED where we just erased */
			set_flash_bytemap(context, erase_info.start,
					  erase_info.length, FLASH_ERASED);
			erase_info.start = 0;
			erase_info.length = 0;
		}

		offset += erase_size;
		count -= erase_size;
	}

	if (erase_info.length) {
		rc = ioctl(context->fds[MTD_FD].fd, MEMERASE, &erase_info);
		if (rc < 0) {
			MSG_ERR("Couldn't erase flash at 0x%.8x\n",
					erase_info.start);
			return -MBOX_R_SYSTEM_ERROR;
		}
		/* Mark ERASED where we just erased */
		set_flash_bytemap(context, erase_info.start, erase_info.length,
				  FLASH_ERASED);
	}

	return 0;
}

/*
 * write_flash() - Write the flash from a provided buffer
 * @context:	The mbox context pointer
 * @offset:	The flash offset to write to (bytes)
 * @buf:	The buffer to write from (must be of atleast size)
 * @size:	The number of bytes to write
 *
 * Return:	0 on success otherwise negative error code
 */
int write_flash(struct mbox_context *context, uint32_t offset, void *buf,
		uint32_t count)
{
	uint32_t buf_offset = 0;
	int rc;

	MSG_OUT("Writing 0x%.8x for 0x%.8x from %p\n", offset, count, buf);

	if (lseek(context->fds[MTD_FD].fd, offset, SEEK_SET) != offset) {
		MSG_ERR("Couldn't seek flash at pos: %u %s\n", offset,
			strerror(errno));
		return -MBOX_R_SYSTEM_ERROR;
	}

	while (count) {
		rc = write(context->fds[MTD_FD].fd, buf + buf_offset, count);
		if (rc < 0) {
			MSG_ERR("Couldn't write to flash, write lost: %s\n",
				strerror(errno));
			return -MBOX_R_WRITE_ERROR;
		}
		/* Mark *NOT* erased where we just wrote */
		set_flash_bytemap(context, offset + buf_offset, rc,
				  FLASH_DIRTY);
		count -= rc;
		buf_offset += rc;
	}

	return 0;
}
