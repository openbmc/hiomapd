// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2018 IBM Corp.

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
#include <errno.h>
#include <mtd/mtd-abi.h>

#include "mboxd.h"
#include "common.h"
#include "flash.h"

int flash_dev_init(struct mbox_context *context)
{
	const char *filename = context->filename;
	int fd, rc = 0;
	int mtd = 0;

	if(!filename)
	{
		filename = get_dev_mtd();
		mtd = 1;
	}

	if (!filename) {
		MSG_ERR("Couldn't find the PNOR /dev/mtd partition\n");
		return -1;
	}

	MSG_DBG("Opening %s\n", filename);

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
	if (mtd)
	{
		if (ioctl(fd, MEMGETINFO, &context->mtd_info) == -1) {
			MSG_ERR("Couldn't get information about MTD: %s\n",
				strerror(errno));
			rc = -1;
			goto out;
		}
	}
	else
	{
		context->mtd_info.size = context->flash_size;
		/* Assume a 4K sector size. */
		context->mtd_info.erasesize = 4 * 1024;
	}

	if (context->flash_size == 0) {
		/*
		 * PNOR images for current OpenPOWER systems are at most 64MB
		 * despite the PNOR itself sometimes being as big as 128MB. To
		 * ensure the image read from the PNOR is exposed in the LPC
		 * address space at the location expected by the host firmware,
		 * it is required that the image size be used for
		 * context->flash_size, and not the size of the flash device.
		 *
		 * However, the test cases specify the flash size via special
		 * test APIs (controlling flash behaviour) which don't have
		 * access to the mbox context. Rather than requiring
		 * error-prone assignments in every test case, we instead rely
		 * on context->flash_size being set to the size reported by the
		 * MEMINFO ioctl().
		 *
		 * As this case should never be hit in production (i.e. outside
		 * the test environment), log an error. As a consequence, this
		 * error is expected in the test case output.
		 */
		MSG_ERR("Flash size MUST be supplied on the commandline. However, continuing by assuming flash is %u bytes\n",
				context->mtd_info.size);
		context->flash_size = context->mtd_info.size;
	}

	/* We know the erase size so we can allocate the flash_erased bytemap */
	context->erase_size_shift = log_2(context->mtd_info.erasesize);
	context->flash_bmap = calloc(context->flash_size >>
				     context->erase_size_shift,
				     sizeof(*context->flash_bmap));
	MSG_DBG("Flash erase size: 0x%.8x\n", context->mtd_info.erasesize);

out:
	if (mtd) {
		free((void*)filename);
	}
	else
	{
		/* We are booting from a file - preload it to the lpc memeory window */
		pread(context->fds[MTD_FD].fd, context->mem, MIN(context->flash_size, context->mem_size), 0);
	}
	return rc;
}

void flash_dev_free(struct mbox_context *context)
{
	free(context->flash_bmap);
	close(context->fds[MTD_FD].fd);
}

/* Flash Functions */

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
 * flash_set_bytemap() - Set the flash erased bytemap
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
int flash_set_bytemap(struct mbox_context *context, uint32_t offset,
		      uint32_t count, uint8_t val)
{
	if ((offset + count) > context->flash_size) {
		return -EINVAL;
	}

	MSG_DBG("Set flash bytemap @ 0x%.8x for 0x%.8x to %s\n",
		offset, count, val ? "ERASED" : "DIRTY");
	memset(context->flash_bmap + (offset >> context->erase_size_shift),
	       val,
	       align_up(count, 1 << context->erase_size_shift) >>
	       context->erase_size_shift);

	return 0;
}

/*
 * flash_erase() - Erase the flash
 * @context:	The mbox context pointer
 * @offset:	The flash offset to erase (bytes)
 * @size:	The number of bytes to erase
 *
 * Return:	0 on success otherwise negative error code
 */
int flash_erase(struct mbox_context *context, uint32_t offset, uint32_t count)
{
	const uint32_t erase_size = 1 << context->erase_size_shift;
	struct erase_info_user erase_info = { 0 };
	int rc;

	MSG_DBG("Erase flash @ 0x%.8x for 0x%.8x\n", offset, count);

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
			MSG_DBG("Erase flash @ 0x%.8x for 0x%.8x\n",
				erase_info.start, erase_info.length);


			if(!context->filename)
			{
				/* MTD Device */
				rc = ioctl(context->fds[MTD_FD].fd, MEMERASE,
					   &erase_info);
			}
			else
			{
				uint8_t* erase_buf = (uint8_t*)malloc(erase_size);
				if (!erase_buf) {
					MSG_ERR("Couldn't malloc erase buffer. %s\n", strerror(errno));
					return -MBOX_R_SYSTEM_ERROR;
				}

				memset(erase_buf, 0xFF, erase_size);
				rc = pwrite(context->fds[MTD_FD].fd, erase_buf, erase_info.length, erase_info.start);
				free(erase_buf);
			}

			if (rc < 0) {
				MSG_ERR("Couldn't erase flash at 0x%.8x\n",
						erase_info.start);
				return -errno;
			}
			/* Mark ERASED where we just erased */
			flash_set_bytemap(context, erase_info.start,
					  erase_info.length, FLASH_ERASED);
			erase_info.start = 0;
			erase_info.length = 0;
		}

		offset += erase_size;
		count -= erase_size;
	}

	if (erase_info.length) {
		MSG_DBG("Erase flash @ 0x%.8x for 0x%.8x\n",
			erase_info.start, erase_info.length);


		if(!context->filename)
		{
			/* MTD Device */
			rc = ioctl(context->fds[MTD_FD].fd, MEMERASE,
				   &erase_info);
		}
		else
		{
			uint8_t* erase_buf = (uint8_t*)malloc(erase_size);
			if (!erase_buf) {
				MSG_ERR("Couldn't malloc erase buffer. %s\n", strerror(errno));
				return -MBOX_R_SYSTEM_ERROR;
			}

			memset(erase_buf, 0xFF, erase_size);
			rc = pwrite(context->fds[MTD_FD].fd, erase_buf, erase_info.length, erase_info.start);
			free(erase_buf);
		}


		if (rc < 0) {
			MSG_ERR("Couldn't erase flash at 0x%.8x\n",
					erase_info.start);
			return -errno;
		}
		/* Mark ERASED where we just erased */
		flash_set_bytemap(context, erase_info.start, erase_info.length,
				  FLASH_ERASED);
	}

	return 0;
}

#define CHUNKSIZE (64 * 1024)

/*
 * flash_copy() - Copy data from the flash device into a provided buffer
 * @context:	The mbox context pointer
 * @offset:	The flash offset to copy from (bytes)
 * @mem:	The buffer to copy into (must be of atleast 'size' bytes)
 * @size:	The number of bytes to copy
 * Return:	Number of bytes copied on success, otherwise negative error
 *		code. flash_copy will copy at most 'size' bytes, but it may
 *		copy less.
 */
int64_t flash_copy(struct mbox_context *context, uint32_t offset, void *mem,
		   uint32_t size)
{
	int32_t size_read;
	void *start = mem;

	MSG_DBG("Copy flash to %p for size 0x%.8x from offset 0x%.8x\n",
		mem, size, offset);
	if (lseek(context->fds[MTD_FD].fd, offset, SEEK_SET) != offset) {
		MSG_ERR("Couldn't seek flash at pos: %u %s\n", offset,
			strerror(errno));
		return -errno;
	}

	do {
		size_read = read(context->fds[MTD_FD].fd, mem,
					  min_u32(CHUNKSIZE, size));
		if (size_read < 0) {
			MSG_ERR("Couldn't copy mtd into ram: %s\n",
				strerror(errno));
			return -errno;
		}

		size -= size_read;
		mem += size_read;
	} while (size && size_read);

	return size_read ? mem - start : -EIO;
}

/*
 * flash_write() - Write the flash from a provided buffer
 * @context:	The mbox context pointer
 * @offset:	The flash offset to write to (bytes)
 * @buf:	The buffer to write from (must be of atleast size)
 * @size:	The number of bytes to write
 *
 * Return:	0 on success otherwise negative error code
 */
int flash_write(struct mbox_context *context, uint32_t offset, void *buf,
		uint32_t count)
{
	uint32_t buf_offset = 0;
	int rc;

	MSG_DBG("Write flash @ 0x%.8x for 0x%.8x from %p\n", offset, count, buf);

	if (lseek(context->fds[MTD_FD].fd, offset, SEEK_SET) != offset) {
		MSG_ERR("Couldn't seek flash at pos: %u %s\n", offset,
			strerror(errno));
		return -errno;
	}

	while (count) {
		rc = write(context->fds[MTD_FD].fd, buf + buf_offset, count);
		if (rc < 0) {
			MSG_ERR("Couldn't write to flash, write lost: %s\n",
				strerror(errno));
			return -errno;
		}
		/* Mark *NOT* erased where we just wrote */
		flash_set_bytemap(context, offset + buf_offset, rc,
				  FLASH_DIRTY);
		count -= rc;
		buf_offset += rc;
	}

	return 0;
}
