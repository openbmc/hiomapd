// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2018 IBM Corp.
// Copyright (C) 2018 Evan Lojewski.

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <mtd/mtd-abi.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "backend.h"
#include "lpc.h"
#include "mboxd.h"

#define MIN(__x__, __y__)  (((__x__) < (__y__)) ? (__x__) : (__y__))

/* Internal routines */
static int flash_dev_init(struct mbox_context *context);
static void flash_dev_free(struct mbox_context *context);
static int flash_set_bytemap(struct mbox_context *context, uint32_t offset,
			     uint32_t count, uint8_t val);
static int flash_erase(struct mbox_context *context, uint32_t offset,
		       uint32_t count);
static int64_t flash_copy(struct mbox_context *context, uint32_t offset,
			  void *mem, uint32_t size);
static int flash_write(struct mbox_context *context, uint32_t offset, void *buf,
		       uint32_t count);
static int lpc_reset(struct mbox_context *context);

static struct backend flash_file_backend = {
	.init = flash_dev_init,
	.free = flash_dev_free,
	.copy = flash_copy,
	.set_bytemap = flash_set_bytemap,
	.erase = flash_erase,
	.write = flash_write,
	.lpc_reset = lpc_reset,
	.validate = NULL,
	.flash_bmap = NULL,
	.erase_size_shift = 0,
	.block_size_shift = 0,
	.mtd_info = {0},
};

int probe_file_backed_flash(struct mbox_context *context)
{
	int fd;
	char *filename = context->filename;

	if(context->force_backend) {
		/* setup data structure */
		context->backend = &flash_file_backend;
	}

	if (!filename) {
		return -1;
	}

	fd = open(filename, O_RDWR);
	if (fd < 0) {
		/* Unable to open file, not an mtd device */
		return -errno;
	} else if (ioctl(fd, MEMGETINFO, &flash_file_backend.mtd_info) != -1) {
                /* Don't attach to mtd devices. */
		close(fd);
		return -1;
	}

	/* setup data structure */
	context->backend = &flash_file_backend;
	close(fd);
	return 0;
}

static int flash_dev_init(struct mbox_context *context)
{
	char *filename = context->filename;
	int fd, rc = 0;

	if (!filename) {
		MSG_ERR("Couldn't find the PNOR file\n");
		return -1;
	}

	MSG_DBG("Opening %s\n", filename);

	/* Open Flash Device */
	fd = open(filename, O_RDWR);
	if (fd < 0) {
		MSG_ERR("Couldn't open %s with flags O_RDWR: %s\n", filename,
			strerror(errno));
		rc = -errno;
		goto out;
	}
	context->fds[MTD_FD].fd = fd;

	if (context->flash_size == 0) {
		MSG_ERR("Flash size MUST be supplied on the commandline.\n");
                return -1;
	}

	context->backend->mtd_info.size = context->flash_size;
	/* Assume a 4K sector size. */
	context->backend->mtd_info.erasesize = 4 * 1024;


	/* We know the erase size so we can allocate the flash_erased bytemap */
	context->backend->erase_size_shift =
	    log_2(context->backend->mtd_info.erasesize);
	MSG_DBG("Flash erase size: 0x%.8x\n",
		context->backend->mtd_info.erasesize);
out:
	return rc;
}

static void flash_dev_free(struct mbox_context *context)
{
	close(context->fds[MTD_FD].fd);
}

/* Flash Functions */

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
static int flash_set_bytemap(struct mbox_context *context, uint32_t offset,
			     uint32_t count, uint8_t val)
{
	if ((offset + count) > context->flash_size) {
		return -EINVAL;
	}

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
static int flash_erase(struct mbox_context *context, uint32_t offset,
		       uint32_t count)
{
	const uint32_t erase_size = 1 << context->backend->erase_size_shift;
	struct erase_info_user erase_info = {0};
	int rc;

	MSG_DBG("Erase flash @ 0x%.8x for 0x%.8x\n", offset, count);

	uint8_t* erase_buf = (uint8_t*)malloc(count);
	if (!erase_buf) {
		MSG_ERR("Couldn't malloc erase buffer. %s\n", strerror(errno));
		return -1;
	}
	memset(erase_buf, 0xFF, erase_size);
	rc = pwrite(context->fds[MTD_FD].fd, erase_buf, count, offset);
	free(erase_buf);

	if (rc < 0) {
		MSG_ERR("Couldn't erase flash at 0x%.8x\n",
			erase_info.start);
		return -errno;
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
static int64_t flash_copy(struct mbox_context *context, uint32_t offset,
			  void *mem, uint32_t size)
{
	int32_t size_read;
	void *start = mem;

	MSG_DBG("Copy flash to %p for size 0x%.8x from offset 0x%.8x\n", mem,
		size, offset);
	if (lseek(context->fds[MTD_FD].fd, offset, SEEK_SET) != offset) {
		MSG_ERR("Couldn't seek flash at pos: %u %s\n", offset,
			strerror(errno));
		return -errno;
	}

	do {
		size_read = read(context->fds[MTD_FD].fd, mem,
				 min_u32(CHUNKSIZE, size));
		if (size_read < 0) {
			MSG_ERR("Couldn't copy file into ram: %s\n",
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
static int flash_write(struct mbox_context *context, uint32_t offset, void *buf,
		       uint32_t count)
{
	uint32_t buf_offset = 0;
	int rc;

	MSG_DBG("Write flash @ 0x%.8x for 0x%.8x from %p\n", offset, count,
		buf);

	if (lseek(context->fds[MTD_FD].fd, offset, SEEK_SET) != offset) {
		MSG_ERR("Couldn't seek flash at pos: %u %s\n", offset,
			strerror(errno));
		return -errno;
	}

	while (count) {
		rc = write(context->fds[MTD_FD].fd, buf + buf_offset, count);
		if (rc < 0) {
			MSG_ERR("Couldn't write to file, write lost: %s\n",
				strerror(errno));
			return -errno;
		}
		count -= rc;
		buf_offset += rc;
	}

	return 0;
}

/*
 * lpc_reset() - Reset the lpc bus mapping
 * @context:    The mbox context pointer
 *
 * Return:      0 on success otherwise negative error code
 */
static int lpc_reset(struct mbox_context *context)
{
	/* Preload Flash contents into memory window */
	pread(context->fds[MTD_FD].fd, context->mem, MIN(context->flash_size, context->mem_size), 0);

	return lpc_map_memory(context);
}
