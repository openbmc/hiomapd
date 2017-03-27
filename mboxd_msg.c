/*
 * Mailbox Daemon MBOX Message Helpers
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

#include "mbox.h"
#include "common.h"
#include "mboxd_msg.h"
#include "mboxd_windows.h"
#include "mboxd_lpc.h"

#define MSG_OUT(f_, ...)	do { if (verbosity >= MBOX_LOG_DEBUG) { \
				    mbox_log(LOG_INFO, f_, ##__VA_ARGS__); } \
				} while (0)
#define MSG_ERR(f_, ...)	do { if (verbosity >= MBOX_LOG_VERBOSE) { \
				    mbox_log(LOG_ERR, f_, ##__VA_ARGS__); } \
				} while (0)

static int mbox_handle_flush_window(struct mbox_context *context, union mbox_regs *req,
			     struct mbox_msg *resp);

typedef int (*mboxd_mbox_handler)(struct mbox_context *, union mbox_regs *,
				  struct mbox_msg *);
static mboxd_mbox_handler mbox_handlers[NUM_MBOX_CMDS];

/*
 * write_bmc_event_reg() - Write to the BMC controlled status register (reg 15)
 * @context:	The mbox context pointer
 *
 * Return:	0 on success otherwise negative error code
 */
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
 * set_bmc_events() - Set BMC events
 * @context:	The mbox context pointer
 * @bmc_event:	The bits to set
 * @write_back:	Whether to write back to the register -> will interrupt host
 *
 * Return:	0 on success otherwise negative error code
 */
int set_bmc_events(struct mbox_context *context, uint8_t bmc_event,
		   bool write_back)
{
	uint8_t mask = 0x00;

	switch (context->version) {
	case API_VERSION_1:
		mask = BMC_EVENT_V1_MASK;
		break;
	default:
		mask = BMC_EVENT_V2_MASK;
		break;
	}

	context->bmc_events |= (bmc_event & mask);

	return write_back ? write_bmc_event_reg(context) : 0;
}

/*
 * clr_bmc_events() - Clear BMC events
 * @context:	The mbox context pointer
 * @bmc_event:	The bits to clear
 * @write_back:	Whether to write back to the register -> will interrupt host
 *
 * Return:	0 on success otherwise negative error code
 */
int clr_bmc_events(struct mbox_context *context, uint8_t bmc_event,
		   bool write_back)
{
	context->bmc_events &= ~bmc_event;

	return write_back ? write_bmc_event_reg(context) : 0;
}

/* Command Handlers */

/*
 * Command: RESET_STATE
 * Reset the LPC mapping to point back at the flash
 */
static int mbox_handle_reset(struct mbox_context *context,
			     union mbox_regs *req, struct mbox_msg *resp)
{
	/* Host requested it -> No BMC Event */
	reset_all_windows(context, NO_BMC_EVENT);
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
static int mbox_handle_mbox_info(struct mbox_context *context,
				 union mbox_regs *req, struct mbox_msg *resp)
{
	uint8_t mbox_api_version = req->msg.args[0];
	uint8_t old_api_version = context->version;
	int rc;

	/* Check we support the version requested */
	if (mbox_api_version < API_MIN_VERSION ||
	    mbox_api_version > API_MAX_VERSION) {
		return -MBOX_R_PARAM_ERROR;
	}
	context->version = mbox_api_version;
	MSG_OUT("Using Protocol Version: %d\n", context->version);

	/*
	 * The reset state is currently to have the LPC bus point directly to
	 * flash, since we got a mbox_info command we know the host can talk
	 * mbox so point the LPC bus mapping to the reserved memory region now
	 * so the host can access what we put in it.
	 */
	rc = point_to_memory(context);
	if (rc < 0) {
		return rc;
	}

	switch (context->version) {
	case API_VERSION_1:
		context->block_size_shift = BLOCK_SIZE_SHIFT_V1;
		break;
	default:
		context->block_size_shift = log_2(context->mtd_info.erasesize);
		break;
	}
	MSG_OUT("Block Size Shift: %d\n", context->block_size_shift);

	/* Now we know the blocksize we can allocate the window dirty_bytemap */
	if (mbox_api_version != old_api_version) {
		alloc_window_dirty_bytemap(context);
	}
	/* Reset if we were V1 since this required exact window mapping */
	if (old_api_version == API_VERSION_1) {
		/*
		 * This will only set the BMC event if there was a current
		 * window -> In which case we are better off notifying the
		 * host.
		 */
		reset_all_windows(context, SET_BMC_EVENT);
	}

	resp->args[0] = mbox_api_version;
	put_u16(&resp->args[1], context->windows.default_size >>
				context->block_size_shift);
	put_u16(&resp->args[3], context->windows.default_size >>
				context->block_size_shift);
	if (context->version >= API_VERSION_2) {
		resp->args[5] = context->block_size_shift;
	}

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
static int mbox_handle_flash_info(struct mbox_context *context,
				  union mbox_regs *req, struct mbox_msg *resp)
{
	switch (context->version) {
	case API_VERSION_1:
		/* Both Sizes in Bytes */
		put_u32(&resp->args[0], context->flash_size);
		put_u32(&resp->args[4], context->mtd_info.erasesize);
		break;
	case API_VERSION_2:
		/* Both Sizes in Block Size */
		put_u16(&resp->args[0],
			context->flash_size >> context->block_size_shift);
		put_u16(&resp->args[2],
			context->mtd_info.erasesize >>
					context->block_size_shift);
		break;
	default:
		MSG_ERR("API Version Not Valid - Invalid System State\n");
		return -MBOX_R_SYSTEM_ERROR;
		break;
	}

	return 0;
}

/*
 * get_lpc_addr_shifted() - Get lpc address of the offset in the current window
 * @context:		The mbox context pointer
 * @flash_offset:	The absolute flash offset (bytes)
 *
 * Flash offset is an absolute offset into flash. To get the lpc bus address of
 * this flash offset (given we know that the current window maps that flash
 * offset) we need to add the lpc base address, the offset of the current window
 * in the reserved memory region and the offset of the given flash offset into
 * the current window.
 *
 * Return:	The lpc address to access that offset shifted by block size
 */
static inline uint16_t get_lpc_addr_shifted(struct mbox_context *context,
					    uint32_t flash_offset)
{
	uint32_t lpc_addr, mem_offset, window_offset;

	/* Offset of the current window in the reserved memory region */
	mem_offset = context->current->mem - context->mem;
	/* Offset of the requested flash offset in the current window */
	window_offset = flash_offset - context->current->flash_offset;
	/* Total LPC Address */
	lpc_addr = context->lpc_base + mem_offset + window_offset;

	return lpc_addr >> context->block_size_shift;
}

/*
 * get_data_size_shifted() - Get the size of the data in the current window
 * @context:            The mbox context pointer
 * @flash_offset:       The absolute flash offset (bytes)
 *
 * Flash offset is an absolute offset into flash. To get the size of the data
 * in the current window which the host is allowed to access we need to
 * subtract from the current window size the offset into the window at which we
 * are pointing the host (which is the flash offset which the host has
 * requested minus the inital flash offset which the current window maps).
 *
 * Return:	The amount of data the host can access from the current window
 * 		(shifted by block size)
 */
static inline uint16_t get_data_size_shifted(struct mbox_context *context,
					     uint32_t flash_offset)
{
	uint32_t size, offset;

	offset = flash_offset - context->current->flash_offset;
	size = context->current->size - offset;

	return size >> context->block_size_shift;
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
 * RESP[2:3]: Actual window size that the host can access (number of blocks)
 */
static int mbox_handle_read_window(struct mbox_context *context,
				   union mbox_regs *req, struct mbox_msg *resp)
{
	uint32_t flash_offset;
	int rc;

	/* Close the current window if there is one */
	if (context->current) {
		/* There is an implicit flush if it was a write window */
		if (context->current_is_write) {
			rc = mbox_handle_flush_window(context, NULL, NULL);
			if (rc < 0) {
				MSG_ERR("Couldn't Flush Write Window\n");
				return rc;
			}
		}
		close_current_window(context, NO_BMC_EVENT, FLAGS_NONE);
	}

	/* Offset the host has requested */
	flash_offset = get_u16(&req->msg.args[0]) << context->block_size_shift;
	MSG_OUT("Host Requested Flash @ 0x%.8x\n", flash_offset);
	/* Check if we have an existing window */
	context->current = search_windows(context, flash_offset,
					  context->version == API_VERSION_1);

	if (!context->current) { /* No existing window */
		rc = create_map_window(context, &context->current, flash_offset,
				       context->version == API_VERSION_1);
		if (rc < 0) { /* Unable to map offset */
			MSG_ERR("Couldn't create window mapping for offset 0x%.8x\n"
				, flash_offset);
			return rc;
		}
	}

	put_u16(&resp->args[0], get_lpc_addr_shifted(context, flash_offset));
	if (context->version >= API_VERSION_2) {
		put_u16(&resp->args[2], get_data_size_shifted(context,
							      flash_offset));
	}

	context->current_is_write = false;
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
static int mbox_handle_write_window(struct mbox_context *context,
				    union mbox_regs *req, struct mbox_msg *resp)
{
	int rc;

	/*
	 * This is very similar to opening a read window (exactly the same
	 * for now infact)
	 */
	rc = mbox_handle_read_window(context, req, resp);
	if (rc < 0) {
		return rc;
	}

	context->current_is_write = true;
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
static int mbox_handle_dirty_window(struct mbox_context *context,
				    union mbox_regs *req, struct mbox_msg *resp)
{
	uint32_t offset, size;

	if (!(context->current && context->current_is_write)) {
		MSG_ERR("Tried to call mark dirty without open write window\n");
		return context->version >= API_VERSION_2 ? -MBOX_R_WINDOW_ERROR
							 : -MBOX_R_PARAM_ERROR;
	}

	offset = get_u16(&req->msg.args[0]);
	/* We need to offset based on where in the window we pointed the host */
	offset += context->window_offset;

	if (context->version >= API_VERSION_2) {
		size = get_u16(&req->msg.args[2]);
	} else {
		uint32_t off;
		/* For V1 offset given relative to flash - we want the window */
		off = offset - ((context->current->flash_offset) >>
				context->block_size_shift);
		if (off > offset) { /* Underflow - before current window */
			MSG_ERR("Tried to mark dirty before start of window\n");
			MSG_ERR("requested offset: 0x%x window start: 0x%x\n",
				offset << context->block_size_shift,
				context->current->flash_offset);
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

	return set_window_bytemap(context, context->current, offset, size,
				  WINDOW_DIRTY);
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
static int mbox_handle_erase_window(struct mbox_context *context,
				    union mbox_regs *req, struct mbox_msg *resp)
{
	uint32_t offset, size;
	int rc;

	if (context->version < API_VERSION_2) {
		MSG_ERR("Protocol Version invalid for Erase Command\n");
		return -MBOX_R_PARAM_ERROR;
	}

	if (!(context->current && context->current_is_write)) {
		MSG_ERR("Tried to call erase without open write window\n");
		return -MBOX_R_WINDOW_ERROR;
	}

	offset = get_u16(&req->msg.args[0]);
	/* We need to offset based on where in the window we pointed the host */
	offset += context->window_offset;
	size = get_u16(&req->msg.args[2]);

	rc = set_window_bytemap(context, context->current, offset, size,
				WINDOW_ERASED);
	if (rc < 0) {
		return rc;
	}

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
static int mbox_handle_flush_window(struct mbox_context *context,
				    union mbox_regs *req, struct mbox_msg *resp)
{
	int rc, i, offset, count;
	uint8_t prev;

	if (!(context->current && context->current_is_write)) {
		MSG_ERR("Tried to call flush without open write window\n");
		return context->version >= API_VERSION_2 ? -MBOX_R_WINDOW_ERROR
							 : -MBOX_R_PARAM_ERROR;
	}

	/*
	 * For V1 the Flush command acts much the same as the dirty command
	 * except with a flush as well. Only do this on an actual flush
	 * command not when we call flush because we've implicitly closed a
	 * window because we might not have the required args in req.
	 */
	if (context->version == API_VERSION_1 && req &&
			req->msg.command == MBOX_C_WRITE_FLUSH) {
		rc = mbox_handle_dirty_window(context, req, NULL);
		if (rc < 0) {
			return rc;
		}
	}

	offset = 0;
	count = 0;
	prev = WINDOW_CLEAN;

	/*
	 * We look for streaks of the same type and keep a count, when the type
	 * (dirty/erased) changes we perform the required action on the backing
	 * store and update the current streak-type
	 */
	for (i = 0; i < (context->current->size >> context->block_size_shift);
			i++) {
		uint8_t cur = context->current->dirty_bmap[i];
		if (cur != WINDOW_CLEAN) {
			if (cur == prev) { /* Same as previous block, incrmnt */
				count++;
			} else if (prev == WINDOW_CLEAN) { /* Start of run */
				offset = i;
				count++;
			} else { /* Change in streak type */
				rc = write_from_window(context, offset, count,
						       prev);
				if (rc < 0) {
					return rc;
				}
				offset = i;
				count = 1;
			}
		} else {
			if (prev != WINDOW_CLEAN) { /* End of a streak */
				rc = write_from_window(context, offset, count,
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

	if (prev != WINDOW_CLEAN) { /* Still the last streak to write */
		rc = write_from_window(context, offset, count, prev);
		if (rc < 0) {
			return rc;
		}
	}

	/* Clear the dirty bytemap since we have written back all changes */
	return set_window_bytemap(context, context->current, 0,
				  context->current->size >>
				  context->block_size_shift,
				  WINDOW_CLEAN);
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
static int mbox_handle_close_window(struct mbox_context *context,
				    union mbox_regs *req, struct mbox_msg *resp)
{
	uint8_t flags = 0;
	int rc;

	/* Close the current window if there is one */
	if (context->current) {
		/* There is an implicit flush if it was a write window */
		if (context->current_is_write) {
			rc = mbox_handle_flush_window(context, NULL, NULL);
			if (rc < 0) {
				MSG_ERR("Couldn't Flush Write Window\n");
				return rc;
			}
		}

		if (context->version >= API_VERSION_2) {
			flags = req->msg.args[0];
		}

		/* Host asked for it -> Don't set the BMC Event */
		close_current_window(context, NO_BMC_EVENT, flags);
	}

	return 0;
}

/*
 * Command: BMC_EVENT_ACK
 * Sent by the host to acknowledge BMC events supplied in mailbox register 15
 *
 * ARGS[0]: Bitmap of bits to ack (by clearing)
 */
static int mbox_handle_ack(struct mbox_context *context, union mbox_regs *req,
			   struct mbox_msg *resp)
{
	uint8_t bmc_events = req->msg.args[0];

	return clr_bmc_events(context, (bmc_events & BMC_EVENT_ACK_MASK),
			      SET_BMC_EVENT);
}

/*
 * check_cmd_valid() - Check if the given command is a valid mbox command code
 * @context:	The mbox context pointer
 * @cmd:	The command code
 *
 * Return:	0 if command is valid otherwise negative error code
 */
static int check_cmd_valid(struct mbox_context *context, int cmd)
{
	if (cmd <= 0 || cmd > NUM_MBOX_CMDS) {
		MSG_ERR("UNKNOWN MBOX COMMAND: %d\n", cmd);
		return -MBOX_R_PARAM_ERROR;
	}
	if (context->state & STATE_SUSPENDED) {
		if (cmd != MBOX_C_GET_MBOX_INFO && cmd != MBOX_C_ACK) {
			MSG_ERR("Cannot use that cmd while suspended: %d\n",
				cmd);
			return context->version >= API_VERSION_2 ? -MBOX_R_BUSY
						: -MBOX_R_PARAM_ERROR;
		}
	}
	if (!(context->state & MAPS_MEM)) {
		if (cmd != MBOX_C_RESET_STATE && cmd != MBOX_C_GET_MBOX_INFO
					      && cmd != MBOX_C_ACK) {
			MSG_ERR("Must call GET_MBOX_INFO before that cmd: %d\n",
				cmd);
			return -MBOX_R_PARAM_ERROR;
		}
	}

	return 0;
}

/*
 * handle_mbox_req() - Handle an incoming mbox command request
 * @context:	The mbox context pointer
 * @req:	The mbox request message
 *
 * Return:	0 if handled successfully otherwise negative error code
 */
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
	rc = check_cmd_valid(context, req->msg.command);
	if (rc < 0) {
		resp.response = -rc;
	} else {
		rc = mbox_handlers[req->msg.command - 1](context, req, &resp);
		if (rc < 0) {
			MSG_ERR("Error handling mbox cmd: %d\n",
				req->msg.command);
			resp.response = -rc;
		}
	}

	MSG_OUT("Writing response to MBOX regs: %d\n", resp.response);
	len = write(context->fds[MBOX_FD].fd, &resp, sizeof(resp));
	if (len < sizeof(resp)) {
		MSG_ERR("Didn't write the full response\n");
		rc = -errno;
	}

	return rc;
}

/*
 * get_message() - Read an mbox request message from the mbox registers
 * @context:	The mbox context pointer
 * @msg:	Where to put the received message
 *
 * Return:	0 if read successfully otherwise negative error code
 */
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

/*
 * dispatch_mbox() - handle an mbox interrupt
 * @context:	The mbox context pointer
 *
 * Return:	0 if handled successfully otherwise negative error code
 */
int dispatch_mbox(struct mbox_context *context)
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

int init_mbox_dev(struct mbox_context *context)
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

	/* Commands start from 1 so we have to subtract 1 */
	mbox_handlers[MBOX_C_RESET_STATE - 1] = mbox_handle_reset;
	mbox_handlers[MBOX_C_GET_MBOX_INFO - 1] = mbox_handle_mbox_info;
	mbox_handlers[MBOX_C_GET_FLASH_INFO - 1] = mbox_handle_flash_info;
	mbox_handlers[MBOX_C_READ_WINDOW - 1] = mbox_handle_read_window;
	mbox_handlers[MBOX_C_CLOSE_WINDOW - 1] = mbox_handle_close_window;
	mbox_handlers[MBOX_C_WRITE_WINDOW - 1] = mbox_handle_write_window;
	mbox_handlers[MBOX_C_WRITE_DIRTY - 1] = mbox_handle_dirty_window;
	mbox_handlers[MBOX_C_WRITE_FLUSH - 1] = mbox_handle_flush_window;
	mbox_handlers[MBOX_C_ACK - 1] = mbox_handle_ack;
	mbox_handlers[MBOX_C_WRITE_ERASE - 1] = mbox_handle_erase_window;

	return 0;
}
