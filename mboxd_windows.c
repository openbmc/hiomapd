/*
 * Mailbox Daemon Window Helpers
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
#include "mboxd_msg.h"
#include "mboxd_windows.h"
#include "mboxd_flash.h"

/* Initialisation Functions */

/*
 * init_window_state() - Initialise a new window to a known state
 * @window:	The window to initialise
 * @size:	The size of the window
 */
static void init_window_state(struct window_context *window, uint32_t size)
{
	window->mem = NULL;
	window->flash_offset = FLASH_OFFSET_UNINIT;
	window->size = size;
	window->dirty_bmap = NULL;
	window->age = 0;
}

/*
 * init_window_mem() - Divide the reserved memory region among the windows
 * @context:	The mbox context pointer
 *
 * Return:	0 on success otherwise negative error code
 */
static int init_window_mem(struct mbox_context *context)
{
	void *mem_location = context->mem;
	int i;

	/*
	 * Carve up the reserved memory region and allocate it to each of the
	 * windows. The windows are placed one after the other in ascending
	 * order, so the first window will be first in memory and so on. We
	 * shouldn't have allocated more windows than we have memory, but if we
	 * did we will error out here
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
/*
 * init_windows() - Initalise the window cache
 * @context:    The mbox context pointer
 *
 * Return:      0 on success otherwise negative
 */
int init_windows(struct mbox_context *context)
{
	int i;

	/* Check if window size and number set - otherwise set to default */
	if (!context->windows.default_size) {
		/* Default to 1MB windows */
		context->windows.default_size = 1 << 20;
	}
	MSG_OUT("Window size: 0x%.8x\n", context->windows.default_size);
	if (!context->windows.num) {
		/* Use the entire reserved memory region by default */
		context->windows.num = context->mem_size /
				       context->windows.default_size;
	}
	MSG_OUT("Number of Windows: %d\n", context->windows.num);

	context->windows.window = calloc(context->windows.num,
					 sizeof(*context->windows.window));
	if (!context->windows.window) {
		MSG_ERR("Memory allocation failed\n");
		return -1;
	}

	for (i = 0; i < context->windows.num; i++) {
		init_window_state(&context->windows.window[i],
				  context->windows.default_size);
	}

	return init_window_mem(context);
}

/*
 * free_windows() - Free the window cache
 * @context:	The mbox context pointer
 */
void free_windows(struct mbox_context *context)
{
	int i;

	/* Check window cache has actually been allocated */
	if (context->windows.window) {
		for (i = 0; i < context->windows.num; i++) {
			free(context->windows.window[i].dirty_bmap);
		}
		free(context->windows.window);
	}
}

/* Write from Window Functions */

/*
 * write_from_window_v1() - Handle writing when erase and block size differ
 * @context:		The mbox context pointer
 * @offset_bytes:	The offset in the current window to write from (bytes)
 * @count_bytes:	Number of bytes to write
 *
 * Handle a write_from_window for dirty memory when block_size is less than the
 * flash erase size
 * This requires us to be a bit careful because we might have to erase more
 * than we want to write which could result in data loss if we don't have the
 * entire portion of flash to be erased already saved in memory (for us to
 * write back after the erase)
 *
 * Return:	0 on success otherwise negative error code
 */
int write_from_window_v1(struct mbox_context *context,
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
	low_mem.flash_offset = align_down(flash_offset,
					  context->mtd_info.erasesize);
	low_mem.size = flash_offset - low_mem.flash_offset;
	high_mem.flash_offset = flash_offset + count_bytes;
	high_mem.size = align_up(high_mem.flash_offset,
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
		rc = copy_flash(context, low_mem.flash_offset,
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
		rc = copy_flash(context, high_mem.flash_offset,
				high_mem.mem, high_mem.size);
		if (rc < 0) {
			goto out;
		}
	}

	/*
	 * We need to erase the flash from low_mem.flash_offset->
	 * high_mem.flash_offset + high_mem.size
	 */
	rc = erase_flash(context, low_mem.flash_offset,
			 (high_mem.flash_offset - low_mem.flash_offset) +
			 high_mem.size);
	if (rc < 0) {
		MSG_ERR("Couldn't erase flash\n");
		goto out;
	}

	/* Write back over the erased area */
	if (low_mem.mem) {
		/* Exceed window at the start */
		rc = write_flash(context, low_mem.flash_offset, low_mem.mem,
				 low_mem.size);
		if (rc < 0) {
			goto out;
		}
	}
	rc = write_flash(context, flash_offset,
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
		rc = write_flash(context, high_mem.flash_offset, high_mem.mem,
				 high_mem.size);
		if (rc < 0) {
			goto out;
		}
	} else {
		/* Write from the current window - it's atleast that big */
		rc = write_flash(context, high_mem.flash_offset,
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
 * write_from_window() - Write back to the flash from the current window
 * @context:		The mbox context pointer
 * @offset_bytes:	The offset in the current window to write from (blocks)
 * @count_bytes:	Number of blocks to write
 * @type:		Whether this is an erase & write or just an erase
 *
 * Return:	0 on success otherwise negative error code
 */
int write_from_window(struct mbox_context *context, uint32_t offset,
		      uint32_t count, uint8_t type)
{
	int rc;
	uint32_t flash_offset, count_bytes = count << context->block_size_shift;
	uint32_t offset_bytes = offset << context->block_size_shift;

	switch (type) {
	case WINDOW_ERASED: /* >= V2 ONLY -> block_size == erasesize */
		flash_offset = context->current->flash_offset + offset_bytes;
		rc = erase_flash(context, flash_offset, count_bytes);
		if (rc < 0) {
			MSG_ERR("Couldn't erase flash\n");
			return rc;
		}
		break;
	case WINDOW_DIRTY:
		/*
		 * For protocol V1, block_size may be smaller than erase size
		 * so we have a special function to make sure that we do this
		 * correctly without losing data.
		 */
		if (log_2(context->mtd_info.erasesize) !=
						context->block_size_shift) {
			return write_from_window_v1(context, offset_bytes,
						    count_bytes);
		}
		flash_offset = context->current->flash_offset + offset_bytes;

		/* Erase the flash */
		rc = erase_flash(context, flash_offset, count_bytes);
		if (rc < 0) {
			return rc;
		}

		/* Write to the erased flash */
		rc = write_flash(context, flash_offset,
				 context->current->mem + offset_bytes,
				 count_bytes);
		if (rc < 0) {
			return rc;
		}

		break;
	default:
		/* We shouldn't be able to get here */
		MSG_ERR("Write from window with invalid type: %d\n", type);
		return -MBOX_R_SYSTEM_ERROR;
	}

	return 0;
}

/* Window Management Functions */

/*
 * alloc_window_dirty_bytemap() - (re)allocate all the window dirty bytemaps
 * @context:		The mbox context pointer
 */
void alloc_window_dirty_bytemap(struct mbox_context *context)
{
	struct window_context *cur;
	int i;

	for (i = 0; i < context->windows.num; i++) {
		cur = &context->windows.window[i];
		/* There may already be one allocated */
		free(cur->dirty_bmap);
		/* Allocate the new one */
		cur->dirty_bmap = calloc((cur->size >>
					  context->block_size_shift),
					 sizeof(*cur->dirty_bmap));
	}
}

/*
 * set_window_bytemap() - Set the window bytemap
 * @context:	The mbox context pointer
 * @cur:	The window to set the bytemap of
 * @offset:	Where in the window to set the bytemap (blocks)
 * @size:	The number of blocks to set
 * @val:	The value to set the bytemap to
 *
 * Return:	0 on success otherwise negative error code
 */
int set_window_bytemap(struct mbox_context *context, struct window_context *cur,
		       uint32_t offset, uint32_t size, uint8_t val)
{
	if (offset + size > (cur->size >> context->block_size_shift)) {
		MSG_ERR("Tried to set window bytemap past end of window\n");
		MSG_ERR("Requested offset: 0x%x size: 0x%x window size: 0x%x\n",
			offset << context->block_size_shift,
			size << context->block_size_shift,
			cur->size << context->block_size_shift);
		return -MBOX_R_PARAM_ERROR;
	}

	memset(cur->dirty_bmap + offset, val, size);
	return 0;
}

/*
 * close_current_window() - Close the current (active) window
 * @context:   		The mbox context pointer
 * @set_bmc_event:	Whether to set the bmc event bit
 * @flags:		Flags as defined for a close command in the protocol
 *
 * This closes the current window. If the host has requested the current window
 * be closed then we don't need to set the bmc event bit
 * (set_bmc_event == false), otherwise if the current window has been closed
 * without the host requesting it the bmc event bit must be set to indicate this
 * to the host (set_bmc_event == true).
 */
void close_current_window(struct mbox_context *context, bool set_bmc_event,
			  uint8_t flags)
{
	if (set_bmc_event) {
		set_bmc_events(context, BMC_EVENT_WINDOW_RESET, SET_BMC_EVENT);
	}

	if (flags & FLAGS_SHORT_LIFETIME) {
		context->current->age = 0;
	}

	context->current->size = context->windows.default_size;
	context->current = NULL;
	context->current_is_write = false;
}

/*
 * reset_window() - Reset a window context to a well defined default state
 * @context:   	The mbox context pointer
 * @window:	The window to reset
 */
void reset_window(struct mbox_context *context, struct window_context *window)
{
	window->flash_offset = FLASH_OFFSET_UNINIT;
	window->size = context->windows.default_size;
	if (window->dirty_bmap) { /* Might not have been allocated */
		set_window_bytemap(context, window, 0,
				   window->size >> context->block_size_shift,
				   WINDOW_CLEAN);
	}
	window->age = 0;
}

/*
 * reset_all_windows() - Reset all windows to a well defined default state
 * @context:		The mbox context pointer
 * @set_bmc_event:	If any state change should be indicated to the host
 */
void reset_all_windows(struct mbox_context *context, bool set_bmc_event)
{
	int i;

	/* We might have an open window which needs closing */
	if (context->current) {
		close_current_window(context, set_bmc_event, FLAGS_NONE);
	}
	for (i = 0; i < context->windows.num; i++) {
		reset_window(context, &context->windows.window[i]);
	}

	context->windows.max_age = 0;
}

/*
 * find_oldest_window() - Find the oldest (Least Recently Used) window
 * @context:		The mbox context pointer
 *
 * Return:	Pointer to the least recently used window
 */
struct window_context *find_oldest_window(struct mbox_context *context)
{
	struct window_context *oldest = NULL, *cur;
	uint32_t min_age = context->windows.max_age + 1;
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
 * find_largest_window() - Find the largest window in the window cache
 * @context:	The mbox context pointer
 *
 * Return:	The largest window
 */
struct window_context *find_largest_window(struct mbox_context *context)
{
	struct window_context *largest = NULL, *cur;
	uint32_t max_size = 0;
	int i;

	for (i = 0; i < context->windows.num; i++) {
		cur = &context->windows.window[i];

		if (cur->size > max_size) {
			max_size = cur->size;
			largest = cur;
		}
	}

	return largest;
}

/*
 * search_windows() - Search the window cache for a window containing offset
 * @context:	The mbox context pointer
 * @offset:	Absolute flash offset to search for (bytes)
 * @exact:	If the window must exactly map the requested offset
 *
 * This will search the cache of windows for one containing the requested
 * offset. For V1 of the protocol windows must exactly map the offset since we
 * can't tell the host how much of its request we actually mapped and it will
 * thus assume it can access window->size from the offset we give it.
 *
 * Return:	Pointer to a window containing the requested offset otherwise
 *		NULL
 */
struct window_context *search_windows(struct mbox_context *context,
				      uint32_t offset, bool exact)
{
	struct window_context *cur;
	int i;

	for (i = 0; i < context->windows.num; i++) {
		cur = &context->windows.window[i];
		if (cur->flash_offset == FLASH_OFFSET_UNINIT) {
			/* Uninitialised Window */
			if (offset == FLASH_OFFSET_UNINIT) {
				return cur;
			}
			continue;
		}
		if ((offset >= cur->flash_offset) &&
		    (offset < (cur->flash_offset + cur->size))) {
			if (exact && (cur->flash_offset != offset)) {
				continue;
			}
			/* This window contains the requested offset */
			cur->age = ++(context->windows.max_age);
			return cur;
		}
	}

	return NULL;
}

/*
 * create_map_window() - Create a window mapping which maps the requested offset
 * @context:		The mbox context pointer
 * @this_window:	A pointer to update to the "new" window
 * @offset:		Absolute flash offset to create a mapping for (bytes)
 * @exact:		If the window must exactly map the requested offset
 *
 * This is used to create a window mapping for the requested offset when there
 * is no existing window in the cache which satisfies the offset. This involves
 * choosing an existing window from the window cache to evict so we can use it
 * to store the flash contents from the requested offset, we then point the
 * caller to that window since it now maps their request.
 *
 * Return:	0 on success otherwise negative error code
 */
int create_map_window(struct mbox_context *context,
		      struct window_context **this_window, uint32_t offset,
		      bool exact)
{
	struct window_context *cur = NULL;
	int rc;


	/* Search for an uninitialised window, use this before evicting */
	cur = search_windows(context, FLASH_OFFSET_UNINIT, true);

	/* No uninitialised window found, we need to choose one to "evict" */
	if (!cur) {
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
		 * open a window except at 0x0, which isn't always where the
		 * host requests it. Thus we have to ignore this check and just
		 * hope the host doesn't access past the end of the window
		 * (which it shouldn't) for V1 implementations to get around
		 * this.
		 */
		if (context->version == API_VERSION_1) {
			cur->size = align_down(context->flash_size - offset,
					       1 << context->block_size_shift);
		} else {
			/* Trying to read past the end of flash */
			MSG_ERR("Tried to open read window past flash limit\n");
			return -MBOX_R_PARAM_ERROR;
		}
	}

	/* Copy from flash into the window buffer */
	rc = copy_flash(context, offset, cur->mem, cur->size);
	if (rc < 0) {
		/* We don't know how much we've copied -> better reset window */
		reset_window(context, cur);
		return rc;
	}

	/*
	 * Since for V1 windows aren't constrained to start at multiples of
	 * window size it's possible that something already maps this offset.
	 * Reset any windows which map this offset to avoid coherency problems.
	 * We just have to check for anything which maps the start or the end
	 * of the window since all windows are the same size so another window
	 * cannot map just the middle of this window.
	 */
	if (context->version == API_VERSION_1) {
		uint32_t i;

		for (i = offset; i < (offset + cur->size); i += (cur->size - 1)) {
			struct window_context *tmp = NULL;
			do {
				tmp = search_windows(context, i, false);
				if (tmp) {
					reset_window(context, tmp);
				}
			} while (tmp);
		}
	}

	/* Clear the bytemap of the window just loaded -> we know it's clean */
	set_window_bytemap(context, cur, 0,
			   cur->size >> context->block_size_shift,
			   WINDOW_CLEAN);

	/* Update so we know what's in the window */
	cur->flash_offset = offset;
	cur->age = ++(context->windows.max_age);
	*this_window = cur;

	return 0;
}
