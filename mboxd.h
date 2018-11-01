/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2018 IBM Corp. */

#ifndef MBOX_H
#define MBOX_H

#include <mtd/mtd-abi.h>
#include <systemd/sd-bus.h>
#include <poll.h>
#include <stdbool.h>

#include "protocol.h"
#include "transport.h"
#include "vpnor/mboxd_pnor_partition_table.h"
#include "windows.h"

enum api_version {
	API_VERSION_INVAL	= 0,
	API_VERSION_1		= 1,
	API_VERSION_2		= 2
};

#define API_MIN_VERSION			API_VERSION_1
#define API_MAX_VERSION			API_VERSION_2

#define THIS_NAME			"Mailbox Daemon"

/* Argument Flags */
#define FLAGS_NONE			0x00
#define FLAGS_SHORT_LIFETIME		0x01

/* BMC Event Notification */
#define BMC_EVENT_PROTOCOL_RESET	0x01
#define BMC_EVENT_WINDOW_RESET		0x02
#define BMC_EVENT_ACK_MASK		(BMC_EVENT_PROTOCOL_RESET | \
					BMC_EVENT_WINDOW_RESET)
#define BMC_EVENT_FLASH_CTRL_LOST	0x40
#define BMC_EVENT_DAEMON_READY		0x80
#define BMC_EVENT_V1_MASK		BMC_EVENT_PROTOCOL_RESET
#define BMC_EVENT_V2_MASK		(BMC_EVENT_PROTOCOL_RESET | \
					BMC_EVENT_WINDOW_RESET | \
					BMC_EVENT_FLASH_CTRL_LOST | \
					BMC_EVENT_DAEMON_READY)

/* Put polled file descriptors first */
#define DBUS_FD			0
#define MBOX_FD			1
#define SIG_FD			2
#define POLL_FDS		3 /* Number of FDs we poll on */
#define LPC_CTRL_FD		3
#define MTD_FD			4
#define TOTAL_FDS		5

#define MAPS_FLASH		(1 << 0)
#define MAPS_MEM		(1 << 1)
#define STATE_SUSPENDED		(1 << 7)

enum mbox_state {
	/* Still Initing */
	UNINITIALISED = 0,
	/* Active and LPC Maps Flash */
	ACTIVE_MAPS_FLASH = MAPS_FLASH,
	/* Suspended and LPC Maps Flash */
	SUSPEND_MAPS_FLASH = STATE_SUSPENDED | MAPS_FLASH,
	/* Active and LPC Maps Memory */
	ACTIVE_MAPS_MEM = MAPS_MEM,
	/* Suspended and LPC Maps Memory */
	SUSPEND_MAPS_MEM = STATE_SUSPENDED | MAPS_MEM
};

struct mbox_context {
	enum api_version version;
	const struct protocol_ops *protocol;
	const struct transport_ops *transport;

/* System State */
	enum mbox_state state;
	struct pollfd fds[TOTAL_FDS];
	sd_bus *bus;
	bool terminate;
	uint8_t bmc_events;
	uint8_t prev_seq;

/* Window State */
	/* The window list struct containing all current "windows" */
	struct window_list windows;
	/* The window the host is currently pointed at */
	struct window_context *current;
	/* Is the current window a write one */
	bool current_is_write;

/* Memory & Flash State */
	/* Reserved Memory Region */
	void *mem;
	/* Reserved Mem Size (bytes) */
	uint32_t mem_size;
	/* LPC Bus Base Address (bytes) */
	uint32_t lpc_base;
	/* Flash size from command line (bytes) */
	uint32_t flash_size;
	/* Bytemap of the erased state of the entire flash */
	uint8_t *flash_bmap;
	/* Erase size (as a shift) */
	uint32_t erase_size_shift;
	/* Block size (as a shift) */
	uint32_t block_size_shift;
	/* Actual Flash Info */
	struct mtd_info_user mtd_info;
#ifdef VIRTUAL_PNOR_ENABLED
	/* Virtual PNOR partition table */
	struct vpnor_partition_table *vpnor;
	struct vpnor_partition_paths paths;
#endif
};

#endif /* MBOX_H */
