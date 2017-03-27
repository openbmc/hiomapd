/*
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
#include <linux/aspeed-lpc-ctrl.h>
#include <systemd/sd-bus.h>

#include "mbox.h"
#include "common.h"
#include "mbox_dbus.h"

#define USAGE \
"\nUsage: %s [--version] [-h | --help] [-v[v] | --verbose] [-s | --syslog]\n" \
"\t\t-w | --window-size <size>M\n" \
"\t\t-n | --window-num <num>\n" \
"\t\t-f | --flash <size>[K|M]\n\n" \
"\t-v | --verbose\t\tBe [more] verbose\n" \
"\t-s | --syslog\t\tLog output to syslog (pointless without -v)\n" \
"\t-w | --window-size\tThe window size (power of 2) in MB\n" \
"\t-n | --window-num\tThe number of windows\n" \
"\t-f | --flash\t\tSize of flash in [K|M] bytes\n\n"

/* LPC Device Path */
#define LPC_CTRL_PATH		"/dev/aspeed-lpc-ctrl"

#define ALIGN_UP(val, size)	(((val) + (size) - 1) & ~((size) - 1))
#define ALIGN_DOWN(val, size)	((val) & ~(((size) - 1)))

#define MSG_OUT(f_, ...)	do { if (verbosity >= MBOX_LOG_DEBUG) { \
				    mbox_log(LOG_INFO, f_, ##__VA_ARGS__); } \
				} while (0)
#define MSG_ERR(f_, ...)	do { if (verbosity >= MBOX_LOG_VERBOSE) { \
				    mbox_log(LOG_ERR, f_, ##__VA_ARGS__); } \
				} while (0)

#define BOOT_HICR7		0x30000e00U
#define BOOT_HICR8		0xfe0001ffU

static sig_atomic_t sighup = 0;
static sig_atomic_t sigint = 0;
static bool dbus_terminate = 0;

/* We need to keep track of this because we may resize windows due to V1 bugs */
static uint32_t default_window_size = 0;

/*
 * Used to track the oldest window value for the LRU eviction scheme.
 *
 * Everytime a window is created/accessed it is given the max_age and max_age
 * is incremented. This means that more recently accessed windows will have a
 * higher age. Thus when selecting a window to evict, we simple choose the one
 * with the lowest age and this is the least recently used (LRU) window.
 *
 * We could try to look at windows which are used least often rather than least
 * recently, but an LRU scheme should suffice for now.
 */
static uint32_t max_age = 0;

/*
 * We track the erased bitmap of the entire flash to avoid erasing blocks we
 * already know to be erased.
 */
static struct flash_erased_bitmap {
	uint8_t *bitmap;
	uint32_t erase_size_shift;
} flash_erased;

/* d-bus */
static sd_bus *bus;

static int handle_cmd_close_window(struct mbox_context *context,
				   union mbox_regs *req);
static int set_bmc_events(struct mbox_context *context, uint8_t bmc_event,
			  bool write_back);
static int clr_bmc_events(struct mbox_context *context, uint8_t bmc_event,
			    bool write_back);

/******************************************************************************/

/* Flash Functions */

static int point_to_flash(struct mbox_context *context)
{
	struct aspeed_lpc_ctrl_mapping map = {
		.window_type = ASPEED_LPC_CTRL_WINDOW_FLASH,
		.window_id = 0, /* Theres only one */
		.flags = 0,
		/*
		 * The mask is because the top nibble is the host LPC FW space,
		 * we want space 0.
		 */
		.addr = 0x0FFFFFFF & -context->flash_size,
		.offset = 0,
		.size = context->flash_size
	};

	MSG_OUT("Pointing HOST LPC bus at the actual flash\n");
	MSG_OUT("Assuming %dMB of flash: HOST LPC 0x%08x\n",
		context->flash_size >> 20, map.addr);

	if (ioctl(context->fds[LPC_CTRL_FD].fd, ASPEED_LPC_CTRL_IOCTL_MAP, &map)
			== -1) {
		MSG_ERR("Failed to point the LPC BUS at the actual flash: %s\n",
			strerror(errno));
		return -MBOX_R_SYSTEM_ERROR;
	}

	/*
	 * Since the host now has access to the flash it can change it out from
	 * under us
	 */
	memset(flash_erased.bitmap, 0,
	       context->flash_size >> flash_erased.erase_size_shift);

	return 0;
}

#define CHUNKSIZE (64 * 1024)

/*
 * Copy size bytes from flash with file descriptor fd at offset into buffer mem
 * which is of atleast size
 * Note: All in bytes
 */
static int copy_flash(int fd, uint32_t offset, void *mem, uint32_t size)
{
	MSG_OUT("Loading flash at %p for 0x%08x bytes from offset 0x%.8x\n",
							mem, size, offset);
	if (lseek(fd, offset, SEEK_SET) != offset) {
		MSG_ERR("Couldn't seek flash at pos: %u %s\n", offset,
			strerror(errno));
		return -MBOX_R_SYSTEM_ERROR;
	}

	while (size) {
		uint32_t size_read = read(fd, mem, min_u32(CHUNKSIZE, size));
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
 * Check if the section of flash containing offset (bytes) is currently erased
 *
 * Returns:
 * 	TRUE  - currently erased
 * 	FALSE - NOT currently erased
 */
static inline bool flash_is_erased(uint32_t offset)
{
	return flash_erased.bitmap[offset >> flash_erased.erase_size_shift];
}

/*
 * Mark the section of flash containing offset (bytes) as erased for count
 * (bytes)
 *
 * NOTE: marks 1 if erased == true or 0 if erased == false
 */
static void flash_mark_erased(uint32_t offset, uint32_t count, uint8_t erased)
{
	memset(flash_erased.bitmap + (offset >> flash_erased.erase_size_shift),
	       erased,
	       ALIGN_UP(count, 1 << flash_erased.erase_size_shift) >>
	       flash_erased.erase_size_shift);
}

/*
 * Erase the flash at offset (bytes) for count (bytes)
 * Note: The erase ioctl will fail for an offset and count not aligned to erase
 * size
 */
static int erase_flash(int fd, uint32_t offset, uint32_t count)
{
	const uint32_t erase_size = 1 << flash_erased.erase_size_shift;
	struct erase_info_user erase_info = { 0 };
	int rc;

	while (count) {
		if (!flash_is_erased(offset)) { /* Need to erase this block */
			if (!erase_info.length) { /* Start of not-erased run */
				erase_info.start = offset;
			}
			erase_info.length += erase_size;
		} else if (erase_info.length) { /* Already erased|end of run? */
			/* Erase the previous run which just ended */
			rc = ioctl(fd, MEMERASE, &erase_info);
			if (rc < 0) {
				MSG_ERR("Couldn't erase flash at 0x%.8x\n",
						erase_info.start);
				return -MBOX_R_SYSTEM_ERROR;
			}
			/* Mark ERASED where we just erased */
			flash_mark_erased(erase_info.start, erase_info.length,
					  1);
			erase_info.start = 0;
			erase_info.length = 0;
		}

		offset += erase_size;
		count -= erase_size;
	}

	if (erase_info.length) {
		rc = ioctl(fd, MEMERASE, &erase_info);
		if (rc < 0) {
			MSG_ERR("Couldn't erase flash at 0x%.8x\n",
					erase_info.start);
			return -MBOX_R_SYSTEM_ERROR;
		}
		/* Mark ERASED where we just erased */
		flash_mark_erased(erase_info.start, erase_info.length, 1);
	}

	return 0;
}

/*
 * Write the flash at offset (bytes) for count (bytes) from buf
 */
static int write_flash(int fd, uint32_t offset, void *buf, uint32_t count)
{
	uint32_t buf_offset = 0;
	int rc;

	MSG_OUT("Writing 0x%.8x for 0x%.8x from %p\n", offset, count, buf);

	if (lseek(fd, offset, SEEK_SET) != offset) {
		MSG_ERR("Couldn't seek flash at pos: %u %s\n", offset,
			strerror(errno));
		return -MBOX_R_SYSTEM_ERROR;
	}

	while (count) {
		rc = write(fd, buf + buf_offset, count);
		if (rc < 0) {
			MSG_ERR("Couldn't write to flash, write lost: %s\n",
				strerror(errno));
			return -MBOX_R_WRITE_ERROR;
		}
		/* Mark *NOT* erased where we just wrote */
		flash_mark_erased(offset + buf_offset, rc, 0);
		count -= rc;
		buf_offset += rc;
	}

	return 0;
}

/*
 * Handle a write_to_flash for dirty memory when block_size is less than the
 * flash erase size
 * This requires us to be a bit careful because we might have to erase more
 * than we want to write which could result in data loss if we don't have the
 * entire portion of flash to be erased already saved in memory (for us to
 * write back after the erase)
 *
 * offset and count are in number of bytes where offset is within the window
 */
static int write_to_flash_dirty_v1(struct mbox_context *context,
				   uint32_t offset_bytes, uint32_t count_bytes)
{
	int rc;
	uint32_t flash_offset;
	struct window_context low_mem = { 0 }, high_mem = { 0 };

	/* Find where in phys flash this is based on the window.flash_offset */
	flash_offset = context->current->flash_offset + offset_bytes;

	/*
	 * low_mem.flash_offset = erase boundary below where we're writing
	 * low_mem.size = size from low_mem.flash_offset to where we're writing
	 *
	 * high_mem.flash_offset = end of where we're writing
	 * high_mem.size = size from end of where we're writing to next erase
	 * 		   boundary
	 */
	low_mem.flash_offset = ALIGN_DOWN(flash_offset,
					  context->mtd_info.erasesize);
	low_mem.size = flash_offset - low_mem.flash_offset;
	high_mem.flash_offset = flash_offset + count_bytes;
	high_mem.size = ALIGN_UP(high_mem.flash_offset,
				 context->mtd_info.erasesize) -
			high_mem.flash_offset;

	/*
	 * Check if we already have a copy of the required flash areas in
	 * memory as part of the existing window
	 */
	if (low_mem.flash_offset < context->current->flash_offset) {
		/* Before the start of our current window */
		low_mem.mem = malloc(low_mem.size);
		if (!low_mem.mem) {
			MSG_ERR("Unable to allocate memory\n");
			return -MBOX_R_SYSTEM_ERROR;
		}
		rc = copy_flash(context->fds[MTD_FD].fd, low_mem.flash_offset,
				low_mem.mem, low_mem.size);
		if (rc < 0) {
			goto out;
		}
	}
	if ((high_mem.flash_offset + high_mem.size) >
	    (context->current->flash_offset + context->current->size)) {
		/* After the end of our current window */
		high_mem.mem = malloc(high_mem.size);
		if (!high_mem.mem) {
			MSG_ERR("Unable to allocate memory\n");
			rc = -MBOX_R_SYSTEM_ERROR;
			goto out;
		}
		rc = copy_flash(context->fds[MTD_FD].fd, high_mem.flash_offset,
				high_mem.mem, high_mem.size);
		if (rc < 0) {
			goto out;
		}
	}

	/*
	 * We need to erase the flash from low_mem.flash_offset->
	 * high_mem.flash_offset + high_mem.size
	 */
	rc = erase_flash(context->fds[MTD_FD].fd, low_mem.flash_offset,
			 (high_mem.flash_offset - low_mem.flash_offset) +
			 high_mem.size);
	if (rc < 0) {
		MSG_ERR("Couldn't erase flash\n");
		goto out;
	}

	/* Write back over the erased area */
	if (low_mem.mem) {
		/* Exceed window at the start */
		rc = write_flash(context->fds[MTD_FD].fd, low_mem.flash_offset,
				 low_mem.mem, low_mem.size);
		if (rc < 0) {
			goto out;
		}
	}
	rc = write_flash(context->fds[MTD_FD].fd, flash_offset,
			 context->current->mem + offset_bytes, count_bytes);
	if (rc < 0) {
		goto out;
	}
	/*
	 * We still need to write the last little bit that we erased - it's
	 * either in the current window or the high_mem window.
	 */
	if (high_mem.mem) {
		/* Exceed window at the end */
		rc = write_flash(context->fds[MTD_FD].fd, high_mem.flash_offset,
				 high_mem.mem, high_mem.size);
		if (rc < 0) {
			goto out;
		}
	} else {
		/* Write from the current window - it's atleast that big */
		rc = write_flash(context->fds[MTD_FD].fd, high_mem.flash_offset,
				 context->current->mem + offset_bytes +
				 count_bytes, high_mem.size);
		if (rc < 0) {
			goto out;
		}
	}

out:
	free(low_mem.mem);
	free(high_mem.mem);
	return rc;
}

/*
 * Write back to the flash from the current window at offset for count blocks
 * We either just erase or erase then write depending on type
 *
 * offset and count are in number of blocks where offset is within the window
 */
static int write_to_flash(struct mbox_context *context, uint32_t offset,
			  uint32_t count, uint8_t type)
{
	int rc;
	uint32_t flash_offset, count_bytes = count << context->block_size_shift;
	uint32_t offset_bytes = offset << context->block_size_shift;

	switch (type) {
	case BITMAP_ERASED: /* >= V2 ONLY -> block_size == erasesize */
		flash_offset = context->current->flash_offset + offset_bytes;
		rc = erase_flash(context->fds[MTD_FD].fd, flash_offset,
				 count_bytes);
		if (rc < 0) {
			MSG_ERR("Couldn't erase flash\n");
			return rc;
		}
		break;
	case BITMAP_DIRTY:
		/*
		 * For protocol V1, block_size may be smaller than erase size
		 * so we have a special function to make sure that we do this
		 * correctly without losing data.
		 */
		if (log_2(context->mtd_info.erasesize) !=
						context->block_size_shift) {
			return write_to_flash_dirty_v1(context, offset_bytes,
						       count_bytes);
		}
		flash_offset = context->current->flash_offset + offset_bytes;

		/* Erase the flash */
		rc = erase_flash(context->fds[MTD_FD].fd, flash_offset,
				 count_bytes);
		if (rc < 0) {
			return rc;
		}

		/* Write to the erased flash */
		rc = write_flash(context->fds[MTD_FD].fd, flash_offset,
				 context->current->mem + offset_bytes,
				 count_bytes);
		if (rc < 0) {
			return rc;
		}

		break;
	default:
		break;
	}

	return 0;
}

/******************************************************************************/

/* Window Functions */

/*
 * Point the LPC bus mapping to the reserved memory region
 */
static int point_to_memory(struct mbox_context *context)
{
	struct aspeed_lpc_ctrl_mapping map = {
		.window_type = ASPEED_LPC_CTRL_WINDOW_MEMORY,
		.window_id = 0, /* There's only one */
		.flags = 0,
		.addr = context->lpc_base,
		.offset = 0,
		.size = context->mem_size
	};

	MSG_OUT("Pointing HOST LPC bus at memory region %p of size 0x%.8x\n",
			context->mem, context->mem_size);
	MSG_OUT("LPC address 0x%.8x\n", map.addr);

	if (ioctl(context->fds[LPC_CTRL_FD].fd, ASPEED_LPC_CTRL_IOCTL_MAP,
		  &map)) {
		MSG_ERR("Failed to point the LPC BUS to memory: %s\n",
			strerror(errno));
		return -MBOX_R_SYSTEM_ERROR;
	}

	return 0;
}

/* Allocates (with inital free) dirty bitmaps for windows based on block size */
static void alloc_window_dirty_bitmap(struct mbox_context *context)
{
	struct window_context *window;
	int i;

	for (i = 0; i < context->windows.num; i++) {
		window = &context->windows.window[i];
		/* There may already be one allocated */
		free(window->dirty_bitmap);
		/* Allocate the new one */
		window->dirty_bitmap = calloc((window->size >>
					       context->block_size_shift),
					      sizeof(*window->dirty_bitmap));
	}
}

/* Reset all windows to a default state */
static void reset_windows(struct mbox_context *context, bool do_flush)
{
	int i;

	set_bmc_events(context, BMC_EVENT_WINDOW_RESET, 1);

	/* We might have an open window which needs closing/flushing */
	if (context->current) {
		if (!do_flush) {
			/* Stop the close command from flushing the window */
			context->is_write = false;
		}
		handle_cmd_close_window(context, NULL);
	}

	for (i = 0; i < context->windows.num; i++) {
		struct window_context *window = &context->windows.window[i];

		window->flash_offset = -1;
		window->size = default_window_size;
		if (window->dirty_bitmap) { /* Might not have been allocated */
			memset(window->dirty_bitmap, BITMAP_CLEAN,
			       window->size >> context->block_size_shift);
		}
		window->age = 0;
	}

	max_age = 0;
}

/* Finds and returns the oldest (LRU) window */
static struct window_context *find_oldest_window(struct mbox_context *context)
{
	struct window_context *oldest = NULL, *cur;
	uint32_t min_age = max_age + 1;
	int i;

	for (i = 0; i < context->windows.num; i++) {
		cur = &context->windows.window[i];

		if (cur->age < min_age) {
			min_age = cur->age;
			oldest = cur;
		}
	}

	return oldest;
}

/*
 * Search window list for one containing the given offset.
 * Returns the window that maps that offset
 * If exact == 1 then the window must exactly map the offset (required for
 * protocol V1)
 *
 * offset given as absolute flash offset in bytes
 */
static struct window_context *search_windows(struct mbox_context *context,
					     uint32_t offset, bool exact)
{
	int i = 0;
	struct window_context *cur = &context->windows.window[i];

	for (; i < context->windows.num; cur = &context->windows.window[++i]) {
		if (cur->flash_offset == (uint32_t) -1) {
			/* Uninitialised Window */
			continue;
		}
		if ((offset >= cur->flash_offset) &&
		    (offset < (cur->flash_offset + cur->size))) {
			if (exact && (cur->flash_offset != offset)) {
				continue;
			}
			/* This window contains the requested offset */
			cur->age = ++max_age;
			return cur;
		}
	}

	return NULL;
}

/*
 * Used when we don't have a window that already maps the required offset.
 * Chooses one to evict and sets up a window to contain that offset.
 * Returns negative on error, or zero if context->current set to window
 * If exact == 1 then the window must exactly map the offset (required for
 * protocol V1)
 *
 * offset given as absolute flash offset in bytes
 */
static struct window_context *create_map_window(struct mbox_context *context,
						uint32_t offset, bool exact,
						int *rc)
{
	struct window_context *cur = NULL;
	int i;

	/* Search for an uninitialised window, use this before evicting */
	for (i = 0; i < context->windows.num; i++) {
		cur = &context->windows.window[i];
		if (cur->flash_offset == (uint32_t) -1) {
			/* Uninitialised window -> use this one */
			break;
		}
	}

	/* No uninitialised window found, we need to choose one to "evict" */
	if (i == context->windows.num) {
		cur = find_oldest_window(context);
	}

	if (!exact) {
		/*
		 * It would be nice to align the offsets which we map to window
		 * size, this will help prevent overlap which would be an
		 * inefficient use of our reserved memory area (we would like
		 * to "cache" as much of the acutal flash as possible in
		 * memory). If we're protocol V1 however we must ensure the
		 * offset requested is exactly mapped.
		 */
		offset &= ~(cur->size - 1);
	}

	if ((offset + cur->size) > context->flash_size) {
		/*
		 * There is V1 skiboot implementations out there which don't
		 * mask offset with window size, meaning when we have
		 * window size == flash size we will never allow the host to
		 * open a window except at 0x0, which isn't alway where the host
		 * requests it. Thus we have to ignore this check and just
		 * hope the host doesn't access past the end of the window
		 * (which it shouldn't) for V1 implementations to get around
		 * this.
		 */
		if (exact) {
			cur->size = ALIGN_DOWN(context->flash_size - offset,
					       1 << context->block_size_shift);
		} else {
			/* Trying to read past the end of flash */
			MSG_ERR("Tried to open read window past flash limit\n");
			*rc = -MBOX_R_PARAM_ERROR;
			return NULL;
		}
	}

	/* Copy from flash into the window buffer */
	*rc = copy_flash(context->fds[MTD_FD].fd, offset, cur->mem, cur->size);
	if (*rc < 0) {
		return NULL;
	}

	/* Clear the Dirty/Erase Bitmap */
	memset(cur->dirty_bitmap, BITMAP_CLEAN,
	       cur->size >> context->block_size_shift);

	/* Update so we know what's in the window */
	cur->flash_offset = offset;
	cur->age = ++max_age;

	return cur;
}

/******************************************************************************/

/* Command Handlers */

/*
 * Command: RESET_STATE
 * Reset the LPC mapping to point back at the flash
 */
static int handle_cmd_reset(struct mbox_context *context)
{
	reset_windows(context, true);
	return point_to_flash(context);
}

/*
 * Command: GET_MBOX_INFO
 * Get the API version, default window size and block size
 * We also set the LPC mapping to point to the reserved memory region here so
 * this command must be called before any window manipulation
 *
 * V1:
 * ARGS[0]: API Version
 *
 * RESP[0]: API Version
 * RESP[1:2]: Default read window size (number of blocks)
 * RESP[3:4]: Default write window size (number of blocks)
 * RESP[5]: Block size (as shift)
 *
 * V2:
 * ARGS[0]: API Version
 *
 * RESP[0]: API Version
 * RESP[1:2]: Default read window size (number of blocks)
 * RESP[3:4]: Default write window size (number of blocks)
 * RESP[5]: Block size (as shift)
 */
static int handle_cmd_mbox_info(struct mbox_context *context,
				union mbox_regs *req, struct mbox_msg *resp)
{
	uint8_t mbox_api_version = req->msg.args[0];
	uint8_t old_api_version = context->version;
	int rc;

	/* Check we support the version requested */
	if (mbox_api_version < API_MIN_VERISON ||
	    mbox_api_version > API_MAX_VERSION) {
		return -MBOX_R_PARAM_ERROR;
	}
	context->version = mbox_api_version;

	switch (context->version) {
	case API_VERISON_2:
		context->block_size_shift = log_2(context->mtd_info.erasesize);
		break;
	default:
		context->block_size_shift = BLOCK_SIZE_SHIFT_V1;
		break;
	}

	/* Reset if we were V1 since this required exact window mapping */
	if (old_api_version == API_VERISON_1) {
		reset_windows(context, 0); /* NOTE: No flush */
	}
	/* Now we know the blocksize we can allocate the window dirty_bitmap */
	if (mbox_api_version != old_api_version) {
		alloc_window_dirty_bitmap(context);
	}

	/* Point the LPC bus mapping to the reserved memory region */
	rc = point_to_memory(context);
	if (rc < 0) {
		return rc;
	}

	resp->args[0] = mbox_api_version;
	put_u16(&resp->args[1], default_window_size >>
				context->block_size_shift);
	put_u16(&resp->args[3], default_window_size >>
				context->block_size_shift);
	resp->args[5] = context->block_size_shift;

	return 0;
}

/*
 * Command: GET_FLASH_INFO
 * Get the flash size and erase granularity
 *
 * V1:
 * RESP[0:3]: Flash Size (bytes)
 * RESP[4:7]: Eraze Size (bytes)
 * V2:
 * RESP[0:1]: Flash Size (number of blocks)
 * RESP[2:3]: Eraze Size (number of blocks)
 */
static int handle_cmd_flash_info(struct mbox_context *context,
				 struct mbox_msg *resp)
{
	switch (context->version) {
	case API_VERISON_1:
		/* Both Sizes in Bytes */
		put_u32(&resp->args[0], context->flash_size);
		put_u32(&resp->args[4], context->mtd_info.erasesize);
		break;
	case API_VERISON_2:
		/* Both Sizes in Block Size */
		put_u16(&resp->args[0],
			context->flash_size >> context->block_size_shift);
		put_u16(&resp->args[2],
			context->mtd_info.erasesize >>
					context->block_size_shift);
		break;
	default:
		break;
	}

	return 0;
}

/*
 * Command: CREATE_READ_WINDOW
 * Opens a read window
 * First checks if any current window with the requested data, if so we just
 * point the host to that. Otherwise we read the request data in from flash and
 * point the host there.
 *
 * V1:
 * ARGS[0:1]: Window Location as Offset into Flash (number of blocks)
 *
 * RESP[0:1]: LPC bus address for host to access this window (number of blocks)
 *
 * V2:
 * ARGS[0:1]: Window Location as Offset into Flash (number of blocks)
 * ARGS[2:3]: Requested window size (number of blocks)
 *
 * RESP[0:1]: LPC bus address for host to access this window (number of blocks)
 * RESP[2:3]: Actual window size that was mapped/host can access (n.o. blocks)
 */
static int handle_cmd_read_window(struct mbox_context *context,
				  union mbox_regs *req, struct mbox_msg *resp)
{
	uint32_t flash_offset;
	int rc;

	if (context->current) {
		/* Already window open -> close it */
		rc = handle_cmd_close_window(context, req);
		if (rc < 0) {
			return rc;
		}
	}

	/* Offset the host has requested */
	flash_offset = get_u16(&req->msg.args[0]) << context->block_size_shift;
	/* Check if we have an existing window */
	context->current = search_windows(context, flash_offset,
					  context->version == API_VERISON_1);

	if (!context->current) { /* No existing window */
		context->current = create_map_window(context, flash_offset,
						     context->version ==
						     API_VERISON_1, &rc);
		if (rc < 0) { /* Unable to map offset */
			MSG_ERR("Couldn't create window mapping for offset 0x%.8x\n"
				, flash_offset);
			return rc;
		}
	}

	/*
	 * Tell the host the lpc bus address of what they requested, this is
	 * the base lpc address + the offset of this window in the reserved
	 * memory region + the offset of the actual data they requested within
	 * this window
	 */
	put_u16(&resp->args[0],
		(context->lpc_base + (context->current->mem - context->mem) +
		 (flash_offset - context->current->flash_offset))
		>> context->block_size_shift);
	if (context->version >= API_VERISON_2) {
		/*
		 * Tell the host how much data they can actually access from
		 * that address, this is the window size - the offset of the
		 * actual data they requested within this window
		 */
		put_u16(&resp->args[2],
			(context->current->size - (flash_offset -
			 context->current->flash_offset))
			>> context->block_size_shift);
	}

	context->is_write = false;
	context->window_offset = (flash_offset - context->current->flash_offset)
				 >> context->block_size_shift;

	return 0;
}

/*
 * Command: CREATE_WRITE_WINDOW
 * Opens a write window
 * First checks if any current window with the requested data, if so we just
 * point the host to that. Otherwise we read the request data in from flash and
 * point the host there.
 *
 * V1:
 * ARGS[0:1]: Window Location as Offset into Flash (number of blocks)
 *
 * RESP[0:1]: LPC bus address for host to access this window (number of blocks)
 *
 * V2:
 * ARGS[0:1]: Window Location as Offset into Flash (number of blocks)
 * ARGS[2:3]: Requested window size (number of blocks)
 *
 * RESP[0:1]: LPC bus address for host to access this window (number of blocks)
 * RESP[2:3]: Actual window size that was mapped/host can access (n.o. blocks)
 */
static int handle_cmd_write_window(struct mbox_context *context,
				   union mbox_regs *req, struct mbox_msg *resp)
{
	int rc;
	/*
	 * This is very similar to opening a read window (exactly the same
	 * for now infact)
	 */
	rc = handle_cmd_read_window(context, req, resp);
	if (rc < 0) {
		return rc;
	}

	context->is_write = true;
	return rc;
}

/*
 * Commands: MARK_WRITE_DIRTY
 * Marks a portion of the current (write) window dirty, informing the daemon
 * that is has been written to and thus must be at some point written to the
 * backing store
 * These changes aren't written back to the backing store unless flush is then
 * called or the window closed
 *
 * V1:
 * ARGS[0:1]: Where within flash to start (number of blocks)
 * ARGS[2:5]: Number to mark dirty (number of bytes)
 *
 * V2:
 * ARGS[0:1]: Where within window to start (number of blocks)
 * ARGS[2:3]: Number to mark dirty (number of blocks)
 */
static int handle_cmd_dirty_window(struct mbox_context *context,
				   union mbox_regs *req)
{
	uint32_t offset, size;

	if (!context->current || !context->is_write) {
		MSG_ERR("Tried to call mark dirty without open write window\n");
		return -MBOX_R_WINDOW_ERROR;
	}

	offset = get_u16(&req->msg.args[0]);
	/* We need to offset based on where in the window we pointed the host */
	offset += context->window_offset;

	if (context->version >= API_VERISON_2) {
		size = get_u16(&req->msg.args[2]);
	} else {
		uint32_t off;
		/* For V1 offset is relative to flash not the current window */
		off = offset - ((context->current->flash_offset) >>
				context->block_size_shift);
		if (off > offset) { /* Underflow - before current window */
			MSG_ERR("Tried to mark dirty past window limits\n");
			return -MBOX_R_PARAM_ERROR;
		}
		offset = off;
		size = get_u32(&req->msg.args[2]);
		/*
		 * We only track dirty at the block level.
		 * For protocol V1 we can get away with just marking the whole
		 * block dirty.
		 */
		size = ALIGN_UP(size, 1 << context->block_size_shift);
		size >>= context->block_size_shift;
	}

	if ((size + offset) > (context->current->size >>
			       context->block_size_shift)) {
		/* Exceeds window limits */
		MSG_ERR("Tried to mark dirty past window limits\n");
		return -MBOX_R_PARAM_ERROR;
	}

	/*
	 * Mark the blocks dirty, even if they had been erased we have to erase
	 * before write anyway so it's sufficient to just mark them dirty
	 */
	memset(context->current->dirty_bitmap + offset, BITMAP_DIRTY, size);

	return 0;
}

/*
 * Commands: MARK_WRITE_ERASE
 * Erases a portion of the current window
 * These changes aren't written back to the backing store unless flush is then
 * called or the window closed
 *
 * V1:
 * Unimplemented
 *
 * V2:
 * ARGS[0:1]: Where within window to start (number of blocks)
 * ARGS[2:3]: Number to erase (number of blocks)
 */
static int handle_cmd_erase_window(struct mbox_context *context,
				   union mbox_regs *req)
{
	uint32_t offset, size;

	if (context->version < API_VERISON_2) {
		MSG_ERR("Erase command called in protocol version 1\n");
		return -MBOX_R_PARAM_ERROR;
	}

	if (!context->current || !context->is_write) {
		MSG_ERR("Tried to call erase without open write window\n");
		return -MBOX_R_WINDOW_ERROR;
	}

	offset = get_u16(&req->msg.args[0]);
	/* We need to offset based on where in the window we pointed the host */
	offset += context->window_offset;
	size = get_u16(&req->msg.args[2]);

	if ((size + offset) > (context->current->size >>
			       context->block_size_shift)) {
		/* Exceeds window limits */
		MSG_ERR("Tried to erase past window limits\n");
		return -MBOX_R_PARAM_ERROR;
	}

	/*
	 * Mark the blocks erased, even if they had been dirtied they've now
	 * been erased so there is no loss of information and it's sufficient
	 * to just mark them erased
	 */
	memset(context->current->dirty_bitmap + offset, BITMAP_ERASED, size);
	/* Write 0xFF to mem -> This ensures consistency between flash & ram */
	memset(context->current->mem + (offset << context->block_size_shift),
	       0xFF, size << context->block_size_shift);

	return 0;
}

/*
 * Command: WRITE_FLUSH
 * Flushes any dirty or erased blocks in the current window back to the backing
 * store
 * NOTE: For V1 this behaves much the same as the dirty command in that it
 * takes an offset and number of blocks to dirty, then also performs a flush as
 * part of the same command. For V2 this will only flush blocks already marked
 * dirty/erased with the appropriate commands and doesn't take any arguments
 * directly.
 *
 * V1:
 * ARGS[0:1]: Where within window to start (number of blocks)
 * ARGS[2:5]: Number to mark dirty (number of bytes)
 *
 * V2:
 * NONE
 */
static int handle_cmd_flush_window(struct mbox_context *context,
				   union mbox_regs *req)
{
	int rc, i, offset, count;
	uint8_t prev;

	if (!context->current || !context->is_write) {
		MSG_ERR("Tried to call flush without open write window\n");
		return -MBOX_R_WINDOW_ERROR;
	}

	/*
	 * For V1 the Flush command acts much the same as the dirty command
	 * except with a flush as well. Only do this on an actual flush
	 * command not when we call flush because we've implicitly closed a
	 * window because we might not have the required args in req.
	 */
	if (context->version == API_VERISON_1 && req &&
			req->msg.command == MBOX_C_WRITE_FLUSH) {
		rc = handle_cmd_dirty_window(context, req);
		if (rc < 0) {
			return rc;
		}
	}

	offset = 0;
	count = 0;
	prev = BITMAP_CLEAN;

	/*
	 * We look for streaks of the same type and keep a count, when the type
	 * (dirty/erased) changes we perform the required action on the backing
	 * store and update the current streak-type
	 */
	for (i = 0; i < (context->current->size >> context->block_size_shift);
			i++) {
		uint8_t cur = context->current->dirty_bitmap[i];
		if (cur != BITMAP_CLEAN) {
			if (cur == prev) { /* Same as previous block, incrmnt */
				count++;
			} else if (prev == BITMAP_CLEAN) { /* Start of run */
				offset = i;
				count++;
			} else { /* Change in streak type */
				rc = write_to_flash(context, offset, count,
						    prev);
				if (rc < 0) {
					return rc;
				}
				offset = i;
				count = 1;
			}
		} else {
			if (prev != BITMAP_CLEAN) { /* End of a streak */
				rc = write_to_flash(context, offset, count,
						    prev);
				if (rc < 0) {
					return rc;
				}
				offset = 0;
				count = 0;
			}
		}
		prev = cur;
	}

	if (prev != BITMAP_CLEAN) { /* Still the last streak to write */
		rc = write_to_flash(context, offset, count, prev);
		if (rc < 0) {
			return rc;
		}
	}

	/* Clear the dirty bitmap since we have written back all changes */
	memset(context->current->dirty_bitmap, BITMAP_CLEAN,
	       context->current->size >> context->block_size_shift);

	return 0;
}

/*
 * Command: CLOSE_WINDOW
 * Close the current window
 * NOTE: There is an implicit flush
 *
 * V1:
 * NONE
 *
 * V2:
 * ARGS[0]: FLAGS
 */
static int handle_cmd_close_window(struct mbox_context *context,
				   union mbox_regs *req)
{
	uint8_t flags = 0;
	int rc;

	if (context->is_write) { /* Perform implicit flush */
		rc = handle_cmd_flush_window(context, req);
		if (rc < 0) {
			MSG_ERR("Couldn't flush window on close\n");
			return rc;
		}
	}

	/* Check for flags -> only if this was an explicit close command */
	if (context->version >= API_VERISON_2 && req &&
	    req->msg.command == MBOX_C_CLOSE_WINDOW) {
		flags = req->msg.args[0];
		if (flags & FLAGS_SHORT_LIFETIME) {
			context->current->age = 0;
		}
	}

	/* We may have resized this - reset to the default */
	context->current->size = default_window_size;
	context->current = NULL;
	context->is_write = false;
	context->window_offset = 0;

	return 0;
}

/*
 * Command: BMC_EVENT_ACK
 * Sent by the host to acknowledge BMC events supplied in mailbox register 15
 *
 * ARGS[0]: Bitmap of bits to ack (by clearing)
 */
static int handle_cmd_ack(struct mbox_context *context, union mbox_regs *req)
{
	uint8_t bmc_events = req->msg.args[0];

	return clr_bmc_events(context, (bmc_events & BMC_EVENT_ACK_MASK), 1);
}

static int handle_mbox_req(struct mbox_context *context, union mbox_regs *req)
{
	struct mbox_msg resp = {
		.command = req->msg.command,
		.seq = req->msg.seq,
		.args = { 0 },
		.response = MBOX_R_SUCCESS
	};
	int rc = 0, len;

	MSG_OUT("Got data in with command %d\n", req->msg.command);
	/* Must have already called get_mbox_info for other commands */
	if (!context->block_size_shift &&
			!(req->msg.command == MBOX_C_RESET_STATE ||
			req->msg.command == MBOX_C_GET_MBOX_INFO ||
			req->msg.command == MBOX_C_ACK)) {
		MSG_ERR("Must call GET_MBOX_INFO before that command\n");
		rc = -MBOX_R_PARAM_ERROR;
		goto cmd_out;
	}
	/* Check if we're in a suspended state */
	if ((context->bmc_events & BMC_EVENT_FLASH_CTRL_LOST) &&
			!(req->msg.command == MBOX_C_GET_MBOX_INFO ||
			req->msg.command == MBOX_C_ACK)) {
		MSG_OUT("Daemon suspended - returning busy\n");
		rc = -MBOX_R_BUSY;
		goto cmd_out;
	}

	/* Handle the command */
	switch (req->msg.command) {
		case MBOX_C_RESET_STATE:
			rc = handle_cmd_reset(context);
			break;
		case MBOX_C_GET_MBOX_INFO:
			rc = handle_cmd_mbox_info(context, req, &resp);
			break;
		case MBOX_C_GET_FLASH_INFO:
			rc = handle_cmd_flash_info(context, &resp);
			break;
		case MBOX_C_READ_WINDOW:
			rc = handle_cmd_read_window(context, req, &resp);
			break;
		case MBOX_C_CLOSE_WINDOW:
			rc = handle_cmd_close_window(context, req);
			break;
		case MBOX_C_WRITE_WINDOW:
			rc = handle_cmd_write_window(context, req, &resp);
			break;
		case MBOX_C_WRITE_DIRTY:
			rc = handle_cmd_dirty_window(context, req);
			break;
		case MBOX_C_WRITE_FLUSH:
			rc = handle_cmd_flush_window(context, req);
			break;
		case MBOX_C_ACK:
			rc = handle_cmd_ack(context, req);
			break;
		case MBOX_C_WRITE_ERASE:
			rc = handle_cmd_erase_window(context, req);
			break;
		default:
			MSG_ERR("UNKNOWN MBOX COMMAND\n");
			rc = -MBOX_R_PARAM_ERROR;
	}

cmd_out:
	if (rc < 0) {
		MSG_ERR("Error handling mbox cmd: %d\n", req->msg.command);
		resp.response = -rc;
	}

	MSG_OUT("Writing response to MBOX regs\n");
	len = write(context->fds[MBOX_FD].fd, &resp, sizeof(resp));
	if (len < sizeof(resp)) {
		MSG_ERR("Didn't write the full response\n");
		rc = -errno;
	}

	return rc;
}

/******************************************************************************/

/* DBUS Functions */

/*
 * Command: DBUS Ping
 * Ping the daemon
 *
 * Args: NONE
 * Resp: NONE
 */
static int dbus_handle_ping(void)
{
	return 0;
}

/*
 * Command: DBUS Status
 * Get the status of the daemon
 *
 * Args: NONE
 * Resp[0]: Status Code
 */
static int dbus_handle_status(struct mbox_context *context,
			      struct mbox_dbus_msg *resp)
{
	resp->args[0] = (context->bmc_events & BMC_EVENT_FLASH_CTRL_LOST) ?
			STATUS_SUSPENDED : STATUS_ACTIVE;

	return 0;
}

/*
 * Command: DBUS Reset
 * Reset the daemon state, final operation TBA.
 * For now we just point the lpc mapping back at the flash.
 *
 * Args: NONE
 * Resp: NONE
 */
static int dbus_handle_reset(struct mbox_context *context,
			     struct mbox_dbus_msg *resp)
{
	int rc;

	/* We don't let the host access flash if the daemon is suspened */
	if (context->bmc_events & BMC_EVENT_FLASH_CTRL_LOST) {
		resp->cmd = E_DBUS_REJECTED;
		return -MBOX_R_PARAM_ERROR;
	}

	/*
	 * This will close (and flush) the current window and point the lpc bus
	 * mapping back to flash.
	 */
	rc = handle_cmd_reset(context);

	if (rc < 0) {
		resp->cmd = E_DBUS_HARDWARE;
	}

	return rc;
}

/*
 * Command: DBUS Kill
 * Stop the daemon
 *
 * Args: NONE
 * Resp: NONE
 */
static int dbus_handle_kill(void)
{
	dbus_terminate = 1;

	return 0;
}

/*
 * Command: DBUS Flash Modified
 * Used to notify the daemon that the flash has been modified out from under
 * it - We need to reset all out windows to ensure flash will be reloaded
 * when a new window is opened.
 * Note: We don't flush any previously opened windowsa
 *
 * Args: NONE
 * Resp: NONE
 */
static int dbus_handle_modified(struct mbox_context *context,
				struct mbox_dbus_msg *resp)
{
	/* The flash modified - can no longer trust our erased bitmap */
	memset(flash_erased.bitmap, 0,
	       context->flash_size >> flash_erased.erase_size_shift);
	/*
	 * This will close the current window and invalidate all windows.
	 * NOTE: we don't flush the current window since there may be
	 * inconsistencies between the flash and data in memory
	 */
	reset_windows(context, false);

	return 0;
}

/*
 * Command: DBUS Suspend
 * Suspend the daemon to inhibit it from performing flash accesses.
 * This is used to synchronise access to the flash between the daemon and
 * directly from the BMC.
 *
 * Args: NONE
 * Resp: NONE
 */
static int dbus_handle_suspend(struct mbox_context *context,
			       struct mbox_dbus_msg *resp)
{
	int rc;

	if (context->bmc_events & BMC_EVENT_FLASH_CTRL_LOST) {
		/* Already Suspended */
		resp->cmd = E_DBUS_NOOP;
		return -MBOX_R_PARAM_ERROR;
	}

	/* Nothing to check - Just set the bit to notify the host */
	rc = set_bmc_events(context, BMC_EVENT_FLASH_CTRL_LOST, 1);
	if (rc < 0) {
		resp->cmd = E_DBUS_HARDWARE;
	}

	return rc;
}

/*
 * Command: DBUS Resume
 * Resume the daemon to let it perform flash accesses again.
 *
 * Args[0]: Flash Modified (0 - no | 1 - yes)
 * Resp: NONE
 */
static int dbus_handle_resume(struct mbox_context *context,
			      struct mbox_dbus_msg *req,
			      struct mbox_dbus_msg *resp)
{
	int rc;

	if (req->num_args != 1) {
		resp->cmd = E_DBUS_INVAL;
		return -MBOX_R_PARAM_ERROR;
	}

	if (!(context->bmc_events & BMC_EVENT_FLASH_CTRL_LOST)) {
		/* We weren't suspended... */
		resp->cmd = E_DBUS_NOOP;
		return -MBOX_R_PARAM_ERROR;
	}

	if (req->args[0] == RESUME_FLASH_MODIFIED) {
		/* Clear the bit and call the flash modified handler */
		clr_bmc_events(context, BMC_EVENT_FLASH_CTRL_LOST, 0);
		return dbus_handle_modified(context, resp);
	}

	/* Flash wasn't modified - just clear the bit with writeback */
	rc = clr_bmc_events(context, BMC_EVENT_FLASH_CTRL_LOST, 1);
	if (rc < 0) {
		resp->cmd = E_DBUS_HARDWARE;
	}

	return rc;
}

static int method_cmd(sd_bus_message *m, void *userdata,
		      sd_bus_error *ret_error)
{
	struct mbox_dbus_msg req = { 0 }, resp = { 0 };
	struct mbox_context *context;
	sd_bus_message *n;
	int rc;

	context = (struct mbox_context *) userdata;
	if (!context) {
		MSG_ERR("DBUS Internal Error\n");
		resp.cmd = E_DBUS_INTERNAL;
		goto out;
	}

	/* Read the command */
	rc = sd_bus_message_read(m, "y", &req.cmd);
	if (rc < 0) {
		MSG_ERR("DBUS error reading message: %s\n", strerror(-rc));
		resp.cmd = E_DBUS_INTERNAL;
		goto out;
	}

	/* Read the args */
	rc = sd_bus_message_read_array(m, 'y', (const void **) &req.args,
				       &req.num_args);
	if (rc < 0) {
		MSG_ERR("DBUS error reading message: %s\n", strerror(-rc));
		resp.cmd = E_DBUS_INTERNAL;
		goto out;
	}

	/* Handle the command */
	switch (req.cmd) {
	case DBUS_C_PING:
		dbus_handle_ping();
		break;
	case DBUS_C_STATUS:
		resp.num_args = 1;
		resp.args = calloc(resp.num_args, sizeof(*resp.args));
		dbus_handle_status(context, &resp);
		break;
	case DBUS_C_KILL:
		dbus_handle_kill();
		break;
	case DBUS_C_RESET:
		dbus_handle_reset(context, &resp);
		break;
	case DBUS_C_SUSPEND:
		dbus_handle_suspend(context, &resp);
		break;
	case DBUS_C_RESUME:
		dbus_handle_resume(context, &req, &resp);
		break;
	case DBUS_C_MODIFIED:
		dbus_handle_modified(context, &resp);
		break;
	default:
		resp.cmd = E_DBUS_INVAL;
		MSG_ERR("Received unknown dbus cmd: %d\n", req.cmd);
		break;
	}

out:
	sd_bus_message_new_method_return(m, &n); /* Generate response */
	sd_bus_message_append(n, "y", resp.cmd); /* Set return code */
	sd_bus_message_append_array(n, 'y', resp.args, resp.num_args);
	sd_bus_send(bus, n, NULL); /* Send response */
	free(resp.args);
	return 0;
}

static const sd_bus_vtable mboxd_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_METHOD("cmd", "yay", "yay", &method_cmd,
		      SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_VTABLE_END
};

/******************************************************************************/

/* MBOX Register Access Functions */

static int write_bmc_event_reg(struct mbox_context *context)
{
	int rc;

	/* Seek mbox registers */
	rc = lseek(context->fds[MBOX_FD].fd, MBOX_BMC_EVENT, SEEK_SET);
	if (rc != MBOX_BMC_EVENT) {
		MSG_ERR("Couldn't lseek mbox to byte %d: %s\n", MBOX_BMC_EVENT,
				strerror(errno));
		return -MBOX_R_SYSTEM_ERROR;
	}

	/* Write to mbox status register */
	rc = write(context->fds[MBOX_FD].fd, &context->bmc_events, 1);
	if (rc != 1) {
		MSG_ERR("Couldn't write to BMC status reg: %s\n",
				strerror(errno));
		return -MBOX_R_SYSTEM_ERROR;
	}

	/* Reset to start */
	rc = lseek(context->fds[MBOX_FD].fd, 0, SEEK_SET);
	if (rc) {
		MSG_ERR("Couldn't reset MBOX offset to zero: %s\n",
				strerror(errno));
		return -MBOX_R_SYSTEM_ERROR;
	}

	return 0;
}

/*
 * Set the BMC Event Bits in MBOX register 15 - BMC controlled status reg
 */
static int set_bmc_events(struct mbox_context *context, uint8_t bmc_event,
			  bool write_back)
{
	context->bmc_events |= (bmc_event & BMC_EVENT_MASK);

	return write_back ? write_bmc_event_reg(context) : 0;
}

/*
 * Clear/ACK the BMC Event Bits in MBOX register 15 - BMC controlled status reg
 */
static int clr_bmc_events(struct mbox_context *context, uint8_t bmc_event,
			  bool write_back)
{
	context->bmc_events &= ~(bmc_event & BMC_EVENT_MASK);

	return write_back ? write_bmc_event_reg(context) : 0;
}

static int get_message(struct mbox_context *context, union mbox_regs *msg)
{
	int rc;

	rc = read(context->fds[MBOX_FD].fd, msg, sizeof(msg->raw));
	if (rc < 0) {
		MSG_ERR("Couldn't read: %s\n", strerror(errno));
		return -errno;
	} else if (rc < sizeof(msg->raw)) {
		MSG_ERR("Short read: %d expecting %zu\n", rc, sizeof(msg->raw));
		return -1;
	}

	return 0;
}

static int dispatch_mbox(struct mbox_context *context)
{
	int rc = 0;
	union mbox_regs req = { 0 };

	assert(context);

	MSG_OUT("Dispatched to mbox\n");
	rc = get_message(context, &req);
	if (rc) {
		return rc;
	}

	return handle_mbox_req(context, &req);
}

static int poll_loop(struct mbox_context *context)
{
	sigset_t set;
	int rc = 0, i;

	sigemptyset(&set);
	/* Set POLLIN on polling file descriptors */
	for (i = 0; i < POLL_FDS; i++) {
		context->fds[i].events = POLLIN;
	}

	while (1) {
		const struct timespec timeout = {
			.tv_sec = POLL_TIMEOUT_S,
			.tv_nsec = 0
		};
		/*
		 * Poll for events
		 * Note: we only want to recieve SIGHUPs' while we're polling,
		 * not while we're handling a request as otherwise we'll poll
		 * again without handling the signal, whereas if we only turn
		 * them on again before polling we'll immediately jump to the
		 * handler if one was pending without having to wait the entire
		 * poll interval.
		 *
		 * ppoll will replace the signal mask with set before beginning
		 * to poll and then reset it to the original mask before
		 * completing. By default we are blocking the SIGHUP signal, so
		 * give the empty set to ppoll. Thus we enable all signals ->
		 * poll -> disable SIGHUP again, meaning we can only take a
		 * SIGHUP while we're polling and not while handling a request.
		 */
		rc = ppoll(context->fds, POLL_FDS, &timeout, &set);

		if (!rc) { /* Timeout */
			continue;
		}
		if (rc < 0) { /* Error or Signal */
			if (errno == EINTR && sighup) {
				/*
				 * Something may be changing the flash behind
				 * our backs, better to reset all the windows
				 * to ensure we don't cache stale data.
				 * Note we flush the current window.
				 */
				rc = handle_cmd_reset(context);
				/* Not much we can do if this fails */
				if (rc < 0) {
					MSG_ERR("WARNING: Failed to point the "
						"LPC bus back to flash on "
						"SIGHUP\nIf the host requires "
						"this expect problems...\n");
				}
				sighup = 0;
				continue;
			}
			if (errno == EINTR && sigint) {
				MSG_OUT("Caught Signal - Exiting...\n");
				sigint = 0;
				break; /* This should mean we clean up nicely */
			}
			MSG_ERR("Error from poll(): %s\n", strerror(errno));
			rc = -errno;
			break; /* This should mean we clean up nicely */
		}

		/* Event on Polled File Descriptor - Handle It */
		if (context->fds[DBUS_FD].revents & POLLIN) {
			while ((rc = sd_bus_process(bus, NULL)) > 0);
			if (rc < 0) {
				MSG_ERR("Error handling DBUS event: %s\n",
						strerror(-rc));
			}
			if (dbus_terminate) {
				MSG_OUT("DBUS Kill - Exiting...\n");
				dbus_terminate = 0;
				break; /* This should mean we clean up nicely */
			}
		}
		if (context->fds[MBOX_FD].revents & POLLIN) {
			rc = dispatch_mbox(context);
			if (rc < 0) {
				MSG_ERR("Error handling MBOX event\n");
			}
		}
	}

	/* Best to do this for safety  - NOTE: No flush of current window */
	reset_windows(context, false);
	rc = point_to_flash(context);
	/* Not much we can do if this fails */
	if (rc < 0) {
		MSG_ERR("WARNING: Failed to point the LPC bus back to flash\n"
			"If the host requires this expect problems...\n");
	}

	return rc;
}

/******************************************************************************/

/* Init Functions */

static int init_mbox_dev(struct mbox_context *context)
{
	int fd;

	/* Open MBOX Device */
	fd = open(MBOX_HOST_PATH, O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		MSG_ERR("Couldn't open %s with flags O_RDWR: %s\n",
			MBOX_HOST_PATH, strerror(errno));
		return -errno;
	}

	context->fds[MBOX_FD].fd = fd;
	return 0;
}

static int init_lpc_dev(struct mbox_context *context)
{
	struct aspeed_lpc_ctrl_mapping map = {
		.window_type = ASPEED_LPC_CTRL_WINDOW_MEMORY,
		.window_id = 0, /* There's only one */
		.flags = 0,
		.addr = 0,
		.offset = 0,
		.size = 0
	};
	int fd;

	/* Open LPC Device */
	MSG_OUT("Opening %s\n", LPC_CTRL_PATH);
	fd = open(LPC_CTRL_PATH, O_RDWR | O_SYNC);
	if (fd < 0) {
		MSG_ERR("Couldn't open %s with flags O_RDWR: %s\n",
			LPC_CTRL_PATH, strerror(errno));
		return -errno;
	}

	context->fds[LPC_CTRL_FD].fd = fd;

	/* Find Size of Reserved Memory Region */
	MSG_OUT("Getting buffer size...\n");
	if (ioctl(fd, ASPEED_LPC_CTRL_IOCTL_GET_SIZE, &map) < 0) {
		MSG_ERR("Couldn't get lpc control buffer size: %s\n",
			strerror(errno));
		return -errno;
	}

	context->mem_size = map.size;
	/* Map at the top of the 28-bit LPC firmware address space-0 */
	context->lpc_base = 0x0FFFFFFF & -context->mem_size;
	
	/* mmap the Reserved Memory Region */
	MSG_OUT("Mapping %s for %u\n", LPC_CTRL_PATH, context->mem_size);
	context->mem = mmap(NULL, context->mem_size, PROT_READ | PROT_WRITE,
				MAP_SHARED, fd, 0);
	if (context->mem == MAP_FAILED) {
		MSG_ERR("Didn't manage to mmap %s: %s\n", LPC_CTRL_PATH,
			strerror(errno));
		return -errno;
	}

	return 0;
}

static int init_flash_dev(struct mbox_context *context)
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

	/* Since we know the erase sz we can allocate the flash_erased_bitmap */
	flash_erased.erase_size_shift = log_2(context->mtd_info.erasesize);
	flash_erased.bitmap = calloc(context->flash_size >>
				     flash_erased.erase_size_shift,
				     sizeof(*flash_erased.bitmap));

out:
	free(filename);
	return rc;
}

static int init_dbus_dev(struct mbox_context *context)
{
	int rc;

	rc = sd_bus_default_system(&bus);
	if (rc < 0) {
		MSG_ERR("Failed to connect to the system bus: %s\n",
			strerror(-rc));
		return rc;
	}

	rc = sd_bus_add_object_vtable(bus, NULL, DOBJ_NAME, DBUS_NAME,
				      mboxd_vtable, context);
	if (rc < 0) {
		MSG_ERR("Failed to register vtable: %s\n", strerror(-rc));
		return rc;
	}

	rc = sd_bus_request_name(bus, DBUS_NAME, SD_BUS_NAME_ALLOW_REPLACEMENT |
						 SD_BUS_NAME_REPLACE_EXISTING);
	if (rc < 0) {
		MSG_ERR("Failed to acquire service name: %s\n", strerror(-rc));
		return rc;
	}

	rc = sd_bus_get_fd(bus);
	if (rc < 0) {
		MSG_ERR("Failed to get bus fd: %s\n", strerror(-rc));
		return rc;
	}

	context->fds[DBUS_FD].fd = rc;
	return 0;
}

static void usage(const char *name)
{
	printf(USAGE, name);
}

static int init_window_mem(struct mbox_context *context)
{
	void *mem_location = context->mem;
	int i;

	/*
	 * Carve up the reserved memory region and allocate it to each of the
	 * windows. The windows are placed one after the other in ascending
	 * order, so window 1 will be first in memory and so on. We shouldn't
	 * have allocated more windows than we have memory, but if we did we
	 * will error out here
	 */
	for (i = 0; i < context->windows.num; i++) {
		context->windows.window[i].mem = mem_location;
		mem_location += context->windows.window[i].size;
		if (mem_location > (context->mem + context->mem_size)) {
			/* Tried to allocate window past the end of memory */
			MSG_ERR("Total size of windows exceeds reserved mem\n");
			MSG_ERR("Try smaller or fewer windows\n");
			MSG_ERR("Mem size: 0x%.8x\n", context->mem_size);
			return -1;
		}
	}

	return 0;
}

static void init_window(struct window_context *window, uint32_t size)
{
	window->mem = NULL;
	window->flash_offset = -1;
	window->size = size;
	window->dirty_bitmap = NULL;
	window->age = 0;
}

static bool parse_cmdline(int argc, char **argv,
			  struct mbox_context *context)
{
	char *endptr;
	int opt, i;

	static const struct option long_options[] = {
		{ "flash",		required_argument,	0, 'f' },
		{ "window-size",	required_argument,	0, 'w' },
		{ "window-num",		required_argument,	0, 'n' },
		{ "verbose",		no_argument,		0, 'v' },
		{ "syslog",		no_argument,		0, 's' },
		{ "version",		no_argument,		0, 'z' },
		{ "help",		no_argument,		0, 'h' },
		{ 0,			0,			0, 0   }
	};

	verbosity = MBOX_LOG_NONE;
	mbox_vlog = &mbox_log_console;

	default_window_size = 0;
	context->windows.num = 0;
	context->current = NULL; /* No current window */

	while ((opt = getopt_long(argc, argv, "f:w:n:vsh", long_options, NULL))
			!= -1) {
		switch (opt) {
		case 0:
			break;
		case 'f':
			context->flash_size = strtol(optarg, &endptr, 10);
			if (optarg == endptr) {
				fprintf(stderr, "Unparseable flash size\n");
				return false;
			}
			switch (*endptr) {
			case '\0':
				break;
			case 'M':
				context->flash_size <<= 10;
			case 'K':
				context->flash_size <<= 10;
				break;
			default:
				fprintf(stderr, "Unknown units '%c'\n",
					*endptr);
				return false;
			}
			break;
		case 'n':
			context->windows.num = strtol(optarg, &endptr, 10);
			if (optarg == endptr || *endptr != '\0') {
				fprintf(stderr, "Unparseable window num\n");
				return false;
			}
			break;
		case 'w':
			default_window_size = strtol(optarg, &endptr, 10);
			default_window_size <<= 20; /* Given in MB */
			if (optarg == endptr || *endptr != '\0') {
				fprintf(stderr, "Unparseable window size\n");
				return false;
			}
			break;
		case 'v':
			verbosity++;
			break;
		case 's':
			/* Avoid a double openlog() */
			if (mbox_vlog != &vsyslog) {
				openlog(PREFIX, LOG_ODELAY, LOG_DAEMON);
				mbox_vlog = &vsyslog;
			}
			break;
		case 'z':
			printf("%s v%d.%.2d\n", THIS_NAME, API_MAX_VERSION,
						SUB_VERSION);
			exit(0);
		case 'h':
			return false; /* This will print the usage message */
		default:
			return false;
		}
	}

	if (!context->flash_size) {
		fprintf(stderr, "Must specify a non-zero flash size\n");
		return false;
	}

	if (!default_window_size) {
		fprintf(stderr, "Must specify a non-zero window size\n");
		return false;
	}

	if (!context->windows.num) {
		fprintf(stderr, "Must specify a non-zero number of windows\n");
		return false;
	}

	MSG_OUT("Flash size: 0x%.8x\n", context->flash_size);
	MSG_OUT("Number of Windows: %d\n", context->windows.num);
	MSG_OUT("Window size: 0x%.8x\n", default_window_size);

	context->windows.window = calloc(context->windows.num,
					 sizeof(*context->windows.window));

	for (i = 0; i < context->windows.num; i++) {
		init_window(&context->windows.window[i], default_window_size);
	}

	if (verbosity) {
		MSG_OUT("%s logging\n", verbosity == MBOX_LOG_DEBUG ? "Debug" :
					"Verbose");
	}

	return true;
}

static int debug_test_mbox_regs(struct mbox_context *context)
{
	int i;

	/* Test the single write facility by setting all the regs to 0xFF */
	MSG_OUT("Setting all MBOX regs to 0xff individually...\n");
	for (i = 0; i < MBOX_REG_BYTES; i++) {
		uint8_t byte = 0x00;
		off_t pos;
		int len;

		pos = lseek(context->fds[MBOX_FD].fd, i, SEEK_SET);
		if (pos != i) {
			MSG_ERR("Couldn't lseek() to byte %d: %s\n", i,
				strerror(errno));
			break;
		}
		len = write(context->fds[MBOX_FD].fd, &byte, 1);
		if (len != 1) {
			MSG_ERR("Couldn't write MBOX reg %d: %s\n", i,
				strerror(errno));
			break;
		}
	}

	if (lseek(context->fds[MBOX_FD].fd, 0, SEEK_SET)) {
		MSG_ERR("Couldn't reset MBOX pos to zero\n");
		return -errno;
	}

	return 0;

}

/******************************************************************************/

/* Signal Handlers */

void signal_hup(int signum)
{
	sighup = 1;
}

void signal_int(int signum)
{
	sigint = 1;
}

/******************************************************************************/

int main(int argc, char **argv)
{
	struct sigaction act_sighup = { 0 }, act_sigint = { 0 };
	struct mbox_context *context;
	char *name = argv[0];
	sigset_t set;
	int rc, i;

	context = calloc(1, sizeof(*context));

	if (!parse_cmdline(argc, argv, context)) {
		usage(name);
		exit(0);
	}

	for (i = 0; i < TOTAL_FDS; i++) {
		context->fds[i].fd = -1;
	}

	/* Block SIGHUPs and SIGINTs */
	sigemptyset(&set);
	sigaddset(&set, SIGHUP | SIGINT | SIGTERM);
	sigprocmask(SIG_SETMASK, &set, NULL);
	/* Register Hang-Up Signal Handler */
	act_sighup.sa_handler = signal_hup;
	sigemptyset(&act_sighup.sa_mask);
	if (sigaction(SIGHUP, &act_sighup, NULL)) {
		perror("Registering SIGHUP");
		exit(1);
	}
	sighup = 0;
	/* Register Interrupt Signal Handler */
	act_sigint.sa_handler = signal_int;
	sigemptyset(&act_sigint.sa_mask);
	if (sigaction(SIGINT, &act_sigint, NULL)) {
		perror("Registering SIGINT");
		exit(1);
	}
	/* Register Terminate Signal Handler - Same as SIGINT */
	if (sigaction(SIGTERM, &act_sigint, NULL)) {
		perror("Registering SIGTERM");
		exit(1);
	}
	sigint = 0;

	MSG_OUT("Starting Daemon\n");

	rc = init_mbox_dev(context);
	if (rc) {
		goto finish;
	}

	if (rc) {
		goto finish;
	}

	rc = init_lpc_dev(context);
	if (rc) {
		goto finish;
	}

	/* We've found the reserved memory region -> we can assign to windows */
	rc = init_window_mem(context);
	if (rc) {
		goto finish;
	}

	rc = init_flash_dev(context);
	if (rc) {
		goto finish;
	}

	rc = init_dbus_dev(context);
	if (rc) {
		goto finish;
	}
	dbus_terminate = 0;

	/* Set the LPC bus mapping to point to the physical flash device */
	rc = point_to_flash(context);
	if (rc) {
		goto finish;
	}

	rc = set_bmc_events(context, BMC_EVENT_DAEMON_READY, 1);
	if (rc) {
		goto finish;
	}

	MSG_OUT("Entering Polling Loop\n");
	rc = poll_loop(context);

	MSG_OUT("Exiting Poll Loop: %d\n", rc);

finish:
	MSG_OUT("Daemon Exiting...\n");
	clr_bmc_events(context, BMC_EVENT_DAEMON_READY, 1);

	sd_bus_unref(bus);

	free(flash_erased.bitmap);
	if (context->mem) {
		munmap(context->mem, context->mem_size);
	}
	for (i = 0; i < TOTAL_FDS; i++) {
		close(context->fds[i].fd);
	}
	for (i = 0; i < context->windows.num; i++) {
		free(context->windows.window[i].dirty_bitmap);
	}
	free(context->windows.window);
	free(context);

	return rc;
}
