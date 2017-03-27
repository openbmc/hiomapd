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

#ifndef MBOX_H
#define MBOX_H

#include <mtd/mtd-abi.h>

enum api_version {
	API_VERISON_INVAL	= 0,
	API_VERISON_1		= 1,
	API_VERISON_2		= 2
};

#define API_MIN_VERISON			API_VERISON_1
#define API_MAX_VERSION			API_VERISON_2

#define THIS_NAME			"Mailbox Daemon"
#define SUB_VERSION			0

/* Command Values */
#define MBOX_C_RESET_STATE		0x01
#define MBOX_C_GET_MBOX_INFO		0x02
#define MBOX_C_GET_FLASH_INFO		0x03
#define MBOX_C_READ_WINDOW		0x04
#define MBOX_C_CLOSE_WINDOW		0x05
#define MBOX_C_WRITE_WINDOW		0x06
#define MBOX_C_WRITE_DIRTY		0x07
#define MBOX_C_WRITE_FLUSH		0x08
#define MBOX_C_ACK			0x09
#define MBOX_C_WRITE_ERASE		0x0a

/* Response Values */
#define MBOX_R_SUCCESS			0x01
#define MBOX_R_PARAM_ERROR		0x02
#define MBOX_R_WRITE_ERROR		0x03
#define MBOX_R_SYSTEM_ERROR		0x04
#define MBOX_R_TIMEOUT			0x05
#define MBOX_R_BUSY			0x06
#define MBOX_R_WINDOW_ERROR		0x07
#define MBOX_R_WINDOW_CLOSED		0x08

/* Argument Flags */
#define FLAGS_SHORT_LIFETIME		0x01

/* BMC Event Notification */
#define BMC_EVENT_REBOOT		0x01
#define BMC_EVENT_WINDOW_RESET		0x02
#define BMC_EVENT_ACK_MASK		(BMC_EVENT_REBOOT | \
					BMC_EVENT_WINDOW_RESET)
#define BMC_EVENT_FLASH_CTRL_LOST	0x40
#define BMC_EVENT_DAEMON_READY		0x80
#define BMC_EVENT_MASK			(BMC_EVENT_REBOOT | \
					BMC_EVENT_WINDOW_RESET | \
					BMC_EVENT_FLASH_CTRL_LOST | \
					BMC_EVENT_DAEMON_READY)

#define MBOX_HOST_PATH			"/dev/aspeed-mbox"
#define MBOX_HOST_TIMEOUT_SEC		1
#define MBOX_ARGS_BYTES			11
#define MBOX_REG_BYTES			16
#define MBOX_HOST_EVENT			14
#define MBOX_BMC_EVENT			15

#define BLOCK_SIZE_SHIFT_V1		12 /* 4K */
#define POLL_TIMEOUT_S			1

/* Dirty/Erase bitmap masks */
#define BITMAP_CLEAN			0x00
#define BITMAP_DIRTY			0x01
#define BITMAP_ERASED			0x02

struct mbox_msg {
	uint8_t command;
	uint8_t seq;
	uint8_t args[MBOX_ARGS_BYTES];
	uint8_t response;
};

union mbox_regs {
	char raw[MBOX_REG_BYTES];
	struct mbox_msg msg;
};

/* Put polled file descriptors first */
#define DBUS_FD			0
#define MBOX_FD			1
#define POLL_FDS		2
#define LPC_CTRL_FD		2
#define MTD_FD			3
#define TOTAL_FDS		4

struct window_context {
	void *mem;			/* Portion of Reserved Memory Region */
	uint32_t flash_offset;		/* Flash area the window maps (bytes) */
	uint32_t size;			/* Size of the Window (bytes) POWER2 */
	uint8_t *dirty_bitmap;		/* Bitmap of the dirty/erased state */
	uint32_t age;			/* Used for LRU eviction scheme */
};

struct window_list {
	int num;
	struct window_context *window;
};

struct mbox_context {
/* System State */
	enum api_version version;
	struct pollfd fds[TOTAL_FDS];
	uint8_t bmc_events;

/* Window State */
	/* The window list struct containing all current "windows" */
	struct window_list windows;
	/* The window the host is currently pointed at */
	struct window_context *current;
	/* Where in the current window I have pointed the host (blocks) */
	uint32_t window_offset;
	/* Is the current window a write one */
	bool is_write;

/* Memory & Flash State */
	/* Reserved Memory Region */
	void *mem;
	/* Reserved Mem Size (bytes) */
	uint32_t mem_size;
	/* LPC Bus Base Address (bytes) */
	uint32_t lpc_base;
	/* Flash size from command line (bytes) */
	uint32_t flash_size;
	/* Block size (as a shift) */
	uint32_t block_size_shift;
	/* Actual Flash Info */
	struct mtd_info_user mtd_info;
};

#endif /* MBOX_H */
