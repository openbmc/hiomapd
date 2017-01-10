/* Copyright 2016 IBM
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *
 */

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
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <mtd/mtd-abi.h>

#include <linux/aspeed-lpc-ctrl.h>

#include "mbox.h"
#include "common.h"

#define LPC_CTRL_PATH "/dev/aspeed-lpc-ctrl"

#define MBOX_FD 0
#define LPC_CTRL_FD 1
#define MTD_FD 2
#define TOTAL_FDS 3

#define ALIGN_UP(_v, _a)    (((_v) + (_a) - 1) & ~((_a) - 1))

#define MSG_OUT(f_, ...) do { if (verbosity != MBOX_LOG_NONE) { mbox_log(LOG_INFO, f_, ##__VA_ARGS__); } } while(0)
#define MSG_ERR(f_, ...) do { if (verbosity != MBOX_LOG_NONE) { mbox_log(LOG_ERR, f_, ##__VA_ARGS__); } } while(0)

#define BOOT_HICR7 0x30000e00U
#define BOOT_HICR8 0xfe0001ffU

struct mbox_context {
	struct pollfd fds[TOTAL_FDS];
	void *lpc_mem;
	uint32_t base;
	uint32_t size;
	uint32_t pgsize;
	bool dirty;
	uint32_t dirtybase;
	uint32_t dirtysize;
	struct mtd_info_user mtd_info;
};

static int running = 1;

static int point_to_flash(void)
{
	/*
	 * Point it to the real flash for sanity. Because hostboot has
	 * expectations as to where the flash is we can't use the kernel
	 * provided UNMAP ioctl().
	 *
	 * That that ioctl() does is detect the size of the flash and map it
	 * appropriately on the LPC bus on the host. The issue with this is that
	 * if a machine has a different flash size to what hostboot expects the
	 * mapping will be incorrect.
	 *
	 * For example 32MB of flash for a platform would mean that hostboot
	 * expects  flash to be at 0x0e000000 - 0x0fffffff on the LPC bus. If
	 * the machine actually has 64MB of flash then the UNMAP ioctl() would
	 * map it 0x0c000000 - 0x0fffffff but hostboot will still read at
	 * 0x0e000000.
	 *
	 * Until hostboot learns how to talk to this daemon this hardcode will
	 * get hostboot going. Furthermore, when hostboot does learn to talk
	 * then this mapping is unnecessary and this code should be removed.
	 */

	int r = 0, devmem_fd;
	char *devmem_ptr;

	MSG_OUT("Pointing HOST LPC bus at the actual flash\n");
	MSG_OUT("Assuming 32MB of flash: HOST LPC 0x%08x -> BMC 0x%08x\n",
		BOOT_HICR7 & 0xffff0000, BOOT_HICR7 << 16);
	devmem_fd = open("/dev/mem", O_RDWR);
	if (devmem_fd == -1) {
		r = -errno;
		MSG_ERR("Couldn't open /dev/mem: %s\n", strerror(-r));
		goto out;
	}
	devmem_ptr = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED,
			devmem_fd, 0x1e789000);
	if (devmem_ptr == MAP_FAILED) {
		r = -errno;
		MSG_ERR("Couldn't mmap() /dev/mem at 0x1e789000 for 0x1000: %s\n",
				strerror(-r));
		goto out;
	}
	*(uint32_t *)&devmem_ptr[0x88] = BOOT_HICR7;
	*(uint32_t *)&devmem_ptr[0x8c] = BOOT_HICR8;
	munmap(devmem_ptr, 0x1000);
	close(devmem_fd);
	/* Sigh */

out:
	return r;
}

static int flash_write(struct mbox_context *context, uint32_t pos, uint32_t len)
{
	int rc;
	struct erase_info_user erase_info = {
		.start = pos,
	};

	assert(context);

	erase_info.length = ALIGN_UP(len, context->mtd_info.erasesize);

	MSG_OUT("Erasing 0x%08x for 0x%08x (aligned: 0x%08x)\n", pos, len, erase_info.length);
	if (ioctl(-context->fds[MTD_FD].fd, MEMERASE, &erase_info) == -1) {
		MSG_ERR("Couldn't MEMERASE ioctl, flash write lost: %s\n", strerror(errno));
		return -1;
	}

	if (lseek(-context->fds[MTD_FD].fd, pos, SEEK_SET) == (off_t) -1) {
		MSG_ERR("Couldn't seek to 0x%08x into MTD, flash write lost: %s\n", pos, strerror(errno));
		return -1;
	}

	while (erase_info.length) {
		rc = write(-context->fds[MTD_FD].fd, context->lpc_mem + pos, erase_info.length);
		if (rc == -1) {
			MSG_ERR("Couldn't write to flash! Flash write lost: %s\n", strerror(errno));
			return -1;
		}
		erase_info.length -= rc;
		pos += rc;
	}

	return 0;
}

/* TODO: Add come consistency around the daemon exiting and either
 * way, ensuring it responds.
 * I'm in favour of an approach where it does its best to stay alive
 * and keep talking, the hacky prototype was written the other way.
 * This function is now inconsistent
 */
static int dispatch_mbox(struct mbox_context *context)
{
	int r = 0;
	int len;
	off_t pos;
	uint8_t byte;
	union mbox_regs resp, req = { 0 };
	uint16_t sizepg, basepg, dirtypg;
	uint32_t dirtycount;
	struct aspeed_lpc_ctrl_mapping map;

	assert(context);

	map.addr = context->base;
	map.size = context->size;
	map.offset = 0;
	map.window_type = ASPEED_LPC_CTRL_WINDOW_MEMORY;
	map.window_id = 0; /* Theres only one */

	MSG_OUT("Dispatched to mbox\n");
	r = read(context->fds[MBOX_FD].fd, &req, sizeof(req.raw));
	if (r < 0) {
		r = -errno;
		MSG_ERR("Couldn't read: %s\n", strerror(errno));
		goto out;
	}
	if (r < sizeof(req.msg)) {
		MSG_ERR("Short read: %d expecting %zu\n", r, sizeof(req.msg));
		r = -1;
		goto out;
	}

	/* We are NOT going to update the last two 'status' bytes */
	memcpy(&resp, &req, sizeof(req.msg));

	sizepg = context->size >> context->pgsize;
	basepg = context->base >> context->pgsize;
	MSG_OUT("Got data in with command %d\n", req.msg.command);
	switch (req.msg.command) {
		case MBOX_C_RESET_STATE:
			/* Called by early hostboot? TODO */
			resp.msg.response = MBOX_R_SUCCESS;
			r = point_to_flash();
			if (r) {
				resp.msg.response = MBOX_R_SYSTEM_ERROR;
				MSG_ERR("Couldn't point the LPC BUS back to actual flash\n");
			}
			break;
		case MBOX_C_GET_MBOX_INFO:
			/* TODO Freak if data.data[0] isn't 1 */
			resp.msg.data[0] = 1;
			put_u16(&resp.msg.data[1], sizepg);
			put_u16(&resp.msg.data[3], sizepg);
			resp.msg.response = MBOX_R_SUCCESS;
			/* Wow that can't stay negated thats horrible */
			MSG_OUT("LPC_CTRL_IOCTL_MAP to 0x%08x for 0x%08x\n", map.addr, map.size);
			r = ioctl(-context->fds[LPC_CTRL_FD].fd,
					ASPEED_LPC_CTRL_IOCTL_MAP, &map);
			if (r < 0) {
				r = -errno;
				resp.msg.response = MBOX_R_SYSTEM_ERROR;
				MSG_ERR("Couldn't MAP ioctl(): %s\n", strerror(errno));
			}
			break;
		case MBOX_C_GET_FLASH_INFO:
			put_u32(&resp.msg.data[0], context->mtd_info.size);
			put_u32(&resp.msg.data[4], context->mtd_info.erasesize);
			resp.msg.response = MBOX_R_SUCCESS;
			break;
		case MBOX_C_READ_WINDOW:
			/*
			 * We could probably play tricks with LPC mapping.
			 * That would require kernel involvement.
			 * We could also always copy the relevant flash part to
			 * context->base even if it turns out that offset is in
			 * the window...
			 * This approach is easiest.
			 */
			if (context->dirty)
				read(-context->fds[MTD_FD].fd, context->lpc_mem, context->size);
			basepg += get_u16(&req.msg.data[0]);
			put_u16(&resp.msg.data[0], basepg);
			resp.msg.response = MBOX_R_SUCCESS;
			context->dirty = false;
			break;
		case MBOX_C_CLOSE_WINDOW:
			context->dirty = true;
			break;
		case MBOX_C_WRITE_WINDOW:
			basepg += get_u16(&req.msg.data[0]);
			put_u16(&resp.msg.data[0], basepg);
			resp.msg.response = MBOX_R_SUCCESS;
			context->dirtybase = basepg << context->pgsize;
			break;
		/* Optimise these later */
		case MBOX_C_WRITE_DIRTY:
		case MBOX_C_WRITE_FENCE:
			dirtypg = get_u16(&req.msg.data[0]);
			dirtycount = get_u32(&req.msg.data[2]);
			if (dirtycount == 0) {
				resp.msg.response = MBOX_R_PARAM_ERROR;
				break;
			}
			/*
			 * dirtypg is actually offset within window so we probs
			 * need to know if the window isn't at zero
			 */
			if (flash_write(context, dirtypg << context->pgsize, dirtycount) != 0) {
				resp.msg.response = MBOX_R_WRITE_ERROR;
				break;
			}
			resp.msg.response = MBOX_R_SUCCESS;
			break;
		case MBOX_C_ACK:
			resp.msg.response = MBOX_R_SUCCESS;
			pos = lseek(context->fds[MBOX_FD].fd, MBOX_BMC_BYTE, SEEK_SET);
			if (pos != MBOX_BMC_BYTE) {
				r = -errno;
				MSG_ERR("Couldn't lseek() to byte %d: %s\n", MBOX_BMC_BYTE,
						strerror(errno));
			}
			/*
			 * NAND what is in the hardware and the request.
			 * This prevents the host being able to SET bits, it can
			 * only request set ones be cleared.
			 */
			byte = ~(req.msg.data[0] & req.raw[MBOX_BMC_BYTE]);
			len = write(context->fds[MBOX_FD].fd, &byte, 1);
			if (len != 1) {
				r = -errno;
				MSG_ERR("Couldn't write to BMC status reg: %s\n",
						strerror(errno));
			}
			pos = lseek(context->fds[MBOX_FD].fd, 0, SEEK_SET);
			if (pos != 0) {
				r = -errno;
				MSG_ERR("Couldn't reset MBOX offset to zero\n");
			}
			break;
		case MBOX_C_COMPLETED_COMMANDS:
			/* This implementation always completes before responding */
			resp.msg.data[0] = 0;
			resp.msg.response = MBOX_R_SUCCESS;
			break;
		default:
			MSG_ERR("UNKNOWN MBOX COMMAND\n");
			resp.msg.response = MBOX_R_PARAM_ERROR;
			r = -1;
	}

	MSG_OUT("Writing response to MBOX regs\n");
	len = write(context->fds[MBOX_FD].fd, &resp, sizeof(resp.msg));
	if (len < sizeof(resp.msg)) {
		r = -errno;
		MSG_ERR("Didn't write the full response\n");
	}

out:
	return r;
}

static void usage(const char *name)
{
	fprintf(stderr, "Usage %s [ -v[v] | --syslog ]\n", name);
	fprintf(stderr, "\t--verbose\t Be [more] verbose\n");
	fprintf(stderr, "\t--syslog\t Log output to syslog (pointless without -v)\n\n");
}

int main(int argc, char *argv[])
{
	struct mbox_context *context;
	const char *name = argv[0];
	char *pnor_filename = NULL;
	int opt, polled, r, i;
	struct aspeed_lpc_ctrl_mapping map;

	static const struct option long_options[] = {
		{ "verbose", no_argument, 0, 'v' },
		{ "syslog",  no_argument, 0, 's' },
		{ 0,         0,           0,  0  }
	};

	context = calloc(1, sizeof(*context));
	for (i = 0; i < TOTAL_FDS; i++)
		context->fds[i].fd = -1;

	mbox_vlog = &mbox_log_console;
	while ((opt = getopt_long(argc, argv, "v", long_options, NULL)) != -1) {
		switch (opt) {
			case 0:
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
			default:
				usage(name);
				exit(EXIT_FAILURE);
		}
	}

	if (verbosity == MBOX_LOG_VERBOSE)
		MSG_OUT("Verbose logging\n");

	if (verbosity == MBOX_LOG_DEBUG)
		MSG_OUT("Debug logging\n");

	MSG_OUT("Starting\n");

	MSG_OUT("Opening %s\n", MBOX_HOST_PATH);
	context->fds[MBOX_FD].fd = open(MBOX_HOST_PATH, O_RDWR | O_NONBLOCK);
	if (context->fds[MBOX_FD].fd < 0) {
		r = -errno;
		MSG_ERR("Couldn't open %s with flags O_RDWR: %s\n",
				MBOX_HOST_PATH, strerror(errno));
		goto finish;
	}

	MSG_OUT("Opening %s\n", LPC_CTRL_PATH);
	context->fds[LPC_CTRL_FD].fd = open(LPC_CTRL_PATH, O_RDWR | O_SYNC);
	if (context->fds[LPC_CTRL_FD].fd < 0) {
		r = -errno;
		MSG_ERR("Couldn't open %s with flags O_RDWR: %s\n",
				LPC_CTRL_PATH, strerror(errno));
		goto finish;
	}

	MSG_OUT("Getting buffer size...\n");
	/* This may become more variable in the future */
	context->pgsize = 12; /* 4K */
	map.window_type = ASPEED_LPC_CTRL_WINDOW_MEMORY;
	map.window_id = 0; /* Theres only one */
	if (ioctl(context->fds[LPC_CTRL_FD].fd, ASPEED_LPC_CTRL_IOCTL_GET_SIZE,
				&map) < 0) {
		r = -errno;
		MSG_OUT("fail\n");
		MSG_ERR("Couldn't get lpc control buffer size: %s\n", strerror(-r));
		goto finish;
	}
	/* And strip the first nibble, LPC access speciality */
	context->size = map.size;
	context->base = -context->size & 0x0FFFFFFF;

	/* READ THE COMMENT AT THE START OF THIS FUNCTION! */
	r = point_to_flash();
	if (r) {
		MSG_ERR("Failed to point the LPC BUS at the actual flash: %s\n",
				strerror(-r));
		goto finish;
	}

	MSG_OUT("Mapping %s for %u\n", LPC_CTRL_PATH, context->size);
	context->lpc_mem = mmap(NULL, context->size, PROT_READ | PROT_WRITE, MAP_SHARED,
			context->fds[LPC_CTRL_FD].fd, 0);
	if (context->lpc_mem == MAP_FAILED) {
		r = -errno;
		MSG_ERR("Didn't manage to mmap %s: %s\n", LPC_CTRL_PATH, strerror(errno));
		goto finish;
	}

	pnor_filename = get_dev_mtd();
	if (!pnor_filename) {
		MSG_ERR("Couldn't find the PNOR /dev/mtd partition\n");
		r = -1;
		goto finish;
	}

	MSG_OUT("Opening %s\n", pnor_filename);
	context->fds[MTD_FD].fd = open(pnor_filename, O_RDWR);
	if (context->fds[MTD_FD].fd < 0) {
		r = -errno;
		MSG_ERR("Couldn't open %s with flags O_RDWR: %s\n",
				pnor_filename, strerror(errno));
		goto finish;
	}

	if (ioctl(context->fds[MTD_FD].fd, MEMGETINFO, &context->mtd_info) == -1) {
		MSG_ERR("Couldn't get information about MTD: %s\n", strerror(errno));
		return -1;
	}

	/*
	 * Copy flash into RAM early, same time.
	 * The kernel has created the LPC->AHB mapping also, which means
	 * flash should work.
	 * Ideally we tell the kernel whats up and when to do stuff...
	 */
	MSG_OUT("Loading flash into ram at %p for 0x%08x bytes\n",
			context->lpc_mem, context->size);
	r = read(context->fds[MTD_FD].fd, context->lpc_mem, context->size);
	if (r != context->size) {
		MSG_ERR("Couldn't copy mtd into ram: %d\n", r);
		goto finish;
	}

	context->fds[MBOX_FD].events = POLLIN;
	/* Ignore in poll() */
	context->fds[LPC_CTRL_FD].fd = -context->fds[LPC_CTRL_FD].fd;
	context->fds[MTD_FD].fd = -context->fds[MTD_FD].fd;

	/* Test the single write facility by setting all the regs to 0xFF */
	MSG_OUT("Setting all MBOX regs to 0xff individually...\n");
	for (i = 0; i < MBOX_REG_BYTES; i++) {
		uint8_t byte = 0xff;
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
	if (lseek(context->fds[MBOX_FD].fd, 0, SEEK_SET) != 0) {
		r = -errno;
		MSG_ERR("Couldn't reset MBOX pos to zero\n");
		goto finish;
	}

	MSG_OUT("Entering polling loop\n");
	while (running) {
		polled = poll(context->fds, TOTAL_FDS, 1000);
		if (polled == 0)
			continue;
		if (polled < 0) {
			r = -errno;
			MSG_ERR("Error from poll(): %s\n", strerror(errno));
			break;
		}
		r = dispatch_mbox(context);
		if (r < 0) {
			MSG_ERR("Error handling MBOX event: %s\n", strerror(-r));
			break;
		}
	}

	MSG_OUT("Exiting\n");

	/* Unnegate so we can close it */
	context->fds[LPC_CTRL_FD].fd = -context->fds[LPC_CTRL_FD].fd;
	context->fds[MTD_FD].fd = -context->fds[MTD_FD].fd;

finish:
	if (context->lpc_mem)
		munmap(context->lpc_mem, context->size);

	free(pnor_filename);
	close(context->fds[MTD_FD].fd);
	close(context->fds[LPC_CTRL_FD].fd);
	close(context->fds[MBOX_FD].fd);
	free(context);

	return r;
}

