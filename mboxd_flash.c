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

static void __set_flash_bytemap(struct mbox_context *context, uint32_t offset,
				uint32_t count, uint8_t val);

int init_flash_dev(struct mbox_context *context)
{
	char *filename = get_dev_mtd();
	int fd, rc = 0;

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
	if (ioctl(fd, MEMGETINFO, &context->mtd_info) == -1) {
		MSG_ERR("Couldn't get information about MTD: %s\n",
			strerror(errno));
		rc = -1;
		goto out;
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

	context->erase_size_shift = log_2(context->mtd_info.erasesize);
	/* Hard code to the minimum for ease if block size changes */
	context->flash_size_shift = 12;
	context->flash_bmap = calloc(context->flash_size >>
				     context->flash_size_shift,
				     sizeof(*context->flash_bmap));
	MSG_DBG("Flash erase size: 0x%.8x (shift: %d)\n",
		context->mtd_info.erasesize, context->erase_size_shift);

out:
	free(filename);
	return rc;
}

void free_flash_dev(struct mbox_context *context)
{
	free(context->flash_bmap);
	close(context->fds[MTD_FD].fd);
}

int __init_flash_lock_file(struct mbox_context *context, const char *path)
{
	uint32_t buf[2];
	int fd, rc;

	MSG_DBG("Opening %s\n", path);

	/* Open the flash locked file which is used to store the locked bmap */
	fd = open(path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		MSG_ERR("Couldn't open %s with flags O_RDWR: %s\n", path,
			strerror(errno));
		return -errno;
	}
	context->fds[LOCK_FD].fd = fd;

	MSG_DBG("Parsing lock file\n");
	/* Lock file is in the format [32-bit offset][32-bit count] */
	while ((rc = read(fd, buf, 8)) > 0) {
		MSG_DBG("Lock flash @ 0x%.8x for 0x%.8x\n", buf[0], buf[1]);
		__set_flash_bytemap(context, buf[0], buf[1], FLASH_LOCKED);
	}
	if (rc < 0) {
		MSG_ERR("Failed to read lock file: %s\n", strerror(errno));
		return -errno;
	}

	return 0;
}

int init_flash_lock_file(struct mbox_context *context)
{
	return __init_flash_lock_file(context, FLASH_LOCKED_FILE);
}

void close_flash_lock_file(struct mbox_context *context)
{
	close(context->fds[LOCK_FD].fd);
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

/*
 * flash_is_erased() - Check if a flash region is erased
 * @context:	The mbox context pointer
 * @offset:	The flash offset to check (bytes)
 * @size:	Size to check (bytes)
 *
 * Return:	true if erased from offset -> offset + size, otherwise false
 */
static inline bool flash_is_erased(struct mbox_context *context,
				   uint32_t offset, uint32_t size)
{
	uint8_t val = FLASH_ERASED;
	offset >>= context->flash_size_shift;
	size >>= context->flash_size_shift;

	for (; size; offset++, size--) {
		val &= context->flash_bmap[offset];
	}

	return !!(val & FLASH_ERASED);
}

/*
 * search_flash_bytemap() - Find the first occurance of a value in the bytemap
 * @context:    The mbox context pointer
 * @offset:     Offset to search from (bytes)
 * @size:       Size of range to search (bytes)
 * @val:        The value to search for
 * @loc:	Pointer to variable to store location of the first occurance of
 * 		val in the range from offset -> offset + size
 *
 * Return:	If there is an occurance of val in the range
 */
bool search_flash_bytemap(struct mbox_context *context, uint32_t offset,
			  uint32_t size, uint8_t val, uint32_t *loc)
{
	uint8_t *found = NULL;

	if (!size || (offset >= context->flash_size)) {
		return false;
	}

	if ((offset + size) > context->flash_size) {
		/* Trucate search to the size of flash */
		size = context->flash_size - offset;
	}

	if (context->flash_bmap) { /* Might not have been allocated */
		uint8_t *search = context->flash_bmap +
				  (offset >> context->flash_size_shift);
		found = memchr(search, val, size >>
					    context->flash_size_shift);
	}

	if (found) {
		if (loc) {
			*loc = (found - context->flash_bmap)
				<< context->flash_size_shift;
		}
		return true;
	}
	return false;
}

static void __set_flash_bytemap(struct mbox_context *context, uint32_t offset,
				uint32_t count, uint8_t val)
{
	memset(context->flash_bmap + (offset >> context->flash_size_shift),
	       val, align_up(count, 1 << context->flash_size_shift) >>
		    context->flash_size_shift);
}

/*
 * set_flash_bytemap() - Set the flash erased bytemap
 * @context:		The mbox context pointer
 * @offset:		The flash offset to set (bytes)
 * @count:		Number to set (bytes)
 * @val:		Value to set the bytemap to
 *
 * Return:	0 if success otherwise negative error code
 */
int set_flash_bytemap(struct mbox_context *context, uint32_t offset,
		      uint32_t count, uint8_t val)
{
	uint32_t locked;

	if ((offset + count) > context->flash_size) {
		return -MBOX_R_PARAM_ERROR;
	}

	MSG_DBG("Set flash bytemap @ 0x%.8x for 0x%.8x to %s\n",
		offset, count, val ? (val & FLASH_LOCKED ? "LOCKED" : "ERASED")
				   : "DIRTY");

	if (val != FLASH_LOCKED) {
		while (search_flash_bytemap(context, offset, count,
					    FLASH_LOCKED, &locked)) {
			/* Set up to the locked bit and then skip over it */
			__set_flash_bytemap(context, offset, (locked - offset),
					    val);
			locked += 1 << context->flash_size_shift;
			count -= (locked - offset);
			offset = locked;
		}
	}

	__set_flash_bytemap(context, offset, count, val);
	return 0;
}

/*
 * save_flash_lock() - Update the flash bytemap and save to storage
 * @context:            The mbox context pointer
 * @offset:             The flash offset to set (bytes)
 * @count:              Number to set (bytes)
 *
 * Return:      0 if success otherwise negative error code
 */
int save_flash_lock(struct mbox_context *context, uint32_t offset,
		    uint32_t count)
{
	uint32_t buf[2] = { offset, count };
	int rc;

	MSG_DBG("Writing lock file @ 0x%.8x for 0x%.8x\n", offset, count);

	rc = lseek(context->fds[LOCK_FD].fd, 0, SEEK_END);
	if (rc < 0) {
		MSG_ERR("Failed to seek lock file: %s\n", strerror(errno));
		return -MBOX_R_SYSTEM_ERROR;
	}

	rc = ftruncate(context->fds[LOCK_FD].fd, rc + 8);
	if (rc < 0) {
		MSG_ERR("Failed to increase size of lock file: %s\n",
			strerror(errno));
		return -MBOX_R_SYSTEM_ERROR;
	}

	rc = write(context->fds[LOCK_FD].fd, buf, 8);
	if (rc != 8) {
		MSG_ERR("Failed to write lock file: %s\n", strerror(errno));
		return -MBOX_R_SYSTEM_ERROR;
	}

	__set_flash_bytemap(context, offset, count, FLASH_LOCKED);
	return 0;
}

/*
 * clear_flash_lock() - Clear locked bits from flash bytemap and from storage
 * @context:            The mbox context pointer
 *
 * Return:      0 if success otherwise negative error code
 */
int clear_flash_lock(struct mbox_context *context)
{
	MSG_DBG("Erasing the flash lock file\n");

	/* Clear the lock file */
	if (ftruncate(context->fds[LOCK_FD].fd, 0)) {
		MSG_ERR("Failed to clear lock file: %s\n", strerror(errno));
		return -MBOX_R_SYSTEM_ERROR;
	}

	/* We don't know if the locked areas were dirty or erased, set dirty */
	__set_flash_bytemap(context, 0, context->flash_size, FLASH_DIRTY);
	return 0;
}

/*
 * erase_flash() - Erase the flash
 * @context:	The mbox context pointer
 * @offset:	The flash offset to erase (bytes) MUST BE ERASE SIZE ALIGNED
 * @size:	The number to erase (bytes) MUST BE ERASE SIZE ALIGNED
 *
 * Return:	0 on success otherwise negative error code
 */
static int erase_flash(struct mbox_context *context, uint32_t offset,
		       uint32_t count)
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
		if (!flash_is_erased(context, offset, erase_size)) {
			/* Need to erase */
			if (!erase_info.length) { /* Start of not-erased run */
				erase_info.start = offset;
			}
			erase_info.length += erase_size;
		} else if (erase_info.length) { /* Already erased|end of run? */
			/* Erase the previous run which just ended */
			MSG_DBG("Erase ioctl @ 0x%.8x for 0x%.8x\n",
				erase_info.start, erase_info.length);
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
		MSG_DBG("Erase ioctl @ 0x%.8x for 0x%.8x\n",
			erase_info.start, erase_info.length);
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
 * @count:	The number of bytes to write
 *
 * Return:	0 on success otherwise negative error code
 */
int write_flash(struct mbox_context *context, uint32_t offset, void *buf,
		uint32_t count)
{
	uint32_t buf_offset = 0;
	int rc;

	MSG_DBG("Write flash @ 0x%.8x for 0x%.8x from %p\n", offset, count, buf);

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

/*
 * smart_erase_flash() - Erase the flash without alignment constraints
 * @context:	The mbox context pointer
 * @offset:	The flash offset to erase (bytes)
 * @count:	The number to erase (bytes)
 *
 * Return:	0 on success otherwise negative error code
 */
int smart_erase_flash(struct mbox_context *context, uint32_t offset,
		      uint32_t count)
{
	const uint32_t erase_size = 1 << context->erase_size_shift;
	struct window_context low_mem = { 0 }, high_mem = { 0 };
	int rc;

	MSG_DBG("Smart erase flash @ 0x%.8x for 0x%.8x\n", offset, count);

	/* Better to check than trust the caller */
	if ((offset + count) > context->flash_size) {
		MSG_ERR("Erase past end of flash @ 0x%.8x for 0x%.8x\n",
			offset, count);
		return -MBOX_R_PARAM_ERROR;
	}

	/* Aligned Erase - Call the erase function directly */
	if (!((offset & (erase_size - 1)) || (count & (erase_size - 1)))) {
		return erase_flash(context, offset, count);
	}

	/* Read */
	/* Unaligned at base of erase */
	if (offset & (erase_size - 1)) {
		low_mem.flash_offset = align_down(offset, erase_size);
		low_mem.size = offset - low_mem.flash_offset;
		low_mem.mem = malloc(low_mem.size);
		if (!low_mem.mem) {
			MSG_ERR("Unable to allocate memory\n");
			return -MBOX_R_SYSTEM_ERROR;
		}
		rc = copy_flash(context, low_mem.flash_offset, low_mem.mem,
				low_mem.size);
		if (rc < 0) {
			goto out;
		}
		MSG_DBG("Aligning erase down: 0x%.8x\n", low_mem.flash_offset);
	}
	/* Unaligned at top of erase */
	if ((offset + count) & (erase_size - 1)) {
		high_mem.flash_offset = offset + count;
		high_mem.size = align_up(high_mem.flash_offset, erase_size) -
				high_mem.flash_offset;
		high_mem.mem = malloc(high_mem.size);
		if (!high_mem.mem) {
			MSG_ERR("Unable to allocate memory\n");
			rc = -MBOX_R_SYSTEM_ERROR;
			goto out;
		}
		rc = copy_flash(context, high_mem.flash_offset, high_mem.mem,
				high_mem.size);
		if (rc < 0) {
			goto out;
		}
		MSG_DBG("Aligning erase up: 0x%.8x\n", high_mem.flash_offset +
							high_mem.size);
	}

	/* Erase */
	rc = erase_flash(context, align_down(offset, erase_size),
			 align_up(offset + count, erase_size) -
			 align_down(offset, erase_size));
	if (rc < 0) {
		goto out;
	}

	/* Write */
	if (low_mem.mem) { /* Only required if we allocated the memory */
		rc = write_flash(context, low_mem.flash_offset, low_mem.mem,
				 low_mem.size);
		if (rc < 0) {
			goto out;
		}
	}
	if (high_mem.mem) { /* Only required if we allocated the memory */
		rc = write_flash(context, high_mem.flash_offset, high_mem.mem,
				 high_mem.size);
	}

out:
	free(low_mem.mem);
	free(high_mem.mem);
	return rc;
}
