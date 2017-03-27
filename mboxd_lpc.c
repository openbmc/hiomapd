/*
 * Mailbox Daemon LPC Helpers
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
#include "mboxd_lpc.h"
#include "mboxd_flash.h"
#include <linux/aspeed-lpc-ctrl.h>

#define LPC_CTRL_PATH		"/dev/aspeed-lpc-ctrl"

#define MSG_OUT(f_, ...)	do { if (verbosity >= MBOX_LOG_DEBUG) { \
				    mbox_log(LOG_INFO, f_, ##__VA_ARGS__); } \
				} while (0)
#define MSG_ERR(f_, ...)	do { if (verbosity >= MBOX_LOG_VERBOSE) { \
				    mbox_log(LOG_ERR, f_, ##__VA_ARGS__); } \
				} while (0)

int init_lpc_dev(struct mbox_context *context)
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

/*
 * point_to_flash() - Point the lpc bus mapping to the actual flash device
 * @context:	The mbox context pointer
 *
 * Return:	0 on success otherwise negative error code
 */
int point_to_flash(struct mbox_context *context)
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

	if (context->state & MAPS_FLASH) {
		return 0; /* LPC Bus already points to flash */
	}
	/* Don't let the host access flash while we're suspended */
	if (context->state & STATE_SUSPENDED) {
		MSG_ERR("Can't point lpc mapping to flash while suspended\n");
		return -MBOX_R_PARAM_ERROR;
	}

	MSG_OUT("Pointing HOST LPC bus at the actual flash\n");
	MSG_OUT("Assuming %dMB of flash: HOST LPC 0x%08x\n",
		context->flash_size >> 20, map.addr);

	if (ioctl(context->fds[LPC_CTRL_FD].fd, ASPEED_LPC_CTRL_IOCTL_MAP, &map)
			== -1) {
		MSG_ERR("Failed to point the LPC BUS at the actual flash: %s\n",
			strerror(errno));
		return -MBOX_R_SYSTEM_ERROR;
	}

	context->state = ACTIVE_MAPS_FLASH;
	/*
	 * Since the host now has access to the flash it can change it out from
	 * under us
	 */
	return set_flash_bytemap(context, 0, context->flash_size, FLASH_DIRTY);
}

/*
 * point_to_memory() - Point the lpc bus mapping to the reserved memory region
 * @context:	The mbox context pointer
 *
 * Return:	0 on success otherwise negative error code
 */
int point_to_memory(struct mbox_context *context)
{
	struct aspeed_lpc_ctrl_mapping map = {
		.window_type = ASPEED_LPC_CTRL_WINDOW_MEMORY,
		.window_id = 0, /* There's only one */
		.flags = 0,
		.addr = context->lpc_base,
		.offset = 0,
		.size = context->mem_size
	};

	if (context->state & MAPS_MEM) {
		return 0; /* LPC Bus already points to reserved memory area */
	}

	MSG_OUT("Pointing HOST LPC bus at memory region %p of size 0x%.8x\n",
			context->mem, context->mem_size);
	MSG_OUT("LPC address 0x%.8x\n", map.addr);

	if (ioctl(context->fds[LPC_CTRL_FD].fd, ASPEED_LPC_CTRL_IOCTL_MAP,
		  &map)) {
		MSG_ERR("Failed to point the LPC BUS to memory: %s\n",
			strerror(errno));
		return -MBOX_R_SYSTEM_ERROR;
	}

	/* LPC now maps memory (keep suspended state) */
	context->state = MAPS_MEM | (context->state & STATE_SUSPENDED);

	return 0;
}
