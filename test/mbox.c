/*
 * MBox Daemon Test File
 *
 * Copyright 2017 IBM
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

#define _GNU_SOURCE /* fallocate */
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "mbox.h"
#include "mboxd_flash.h"
#include "mboxd_lpc.h"
#include "mboxd_msg.h"
#include "mboxd_windows.h"

#include "test/mbox.h"

#define STEP 16

void dump_buf(const uint8_t *buf, size_t len)
{
	int i;

	for (i = 0; i < len; i += STEP) {
		int delta;
		int max;
		int j;

		delta = len - i;
		max = delta > STEP ? STEP : delta;

		printf("0x%08x:\t", i);
		for (j = 0; j < max; j++)
			printf("0x%02x, ", buf[i + j]);

		printf("\n");
	}
	printf("\n");
}

/*
 * Because we are using a file and not a pipe for the mbox file descriptor we
 * need to handle a difference in behaviour. For a given command and response
 * sequence the first 16 bytes of the file are occupied by the mbox command.
 * The response occupies the following 14 bytes for a total of 30 bytes.
 *
 * We also have to ensure we lseek() to reset the file descriptor offset back
 * to the start of the file before dispatching the mbox command.
 */

/* Macros for handling the pipe/file discrepancy */
#define RESPONSE_OFFSET	16
#define RESPONSE_SIZE	14

int mbox_cmp(struct mbox_context *context, const uint8_t *expected, size_t len)
{
	struct stat details;
	uint8_t *map;
	int rc;
	int fd;

	fd = context->fds[MBOX_FD].fd;
	fstat(fd, &details);

	map = mmap(NULL, details.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	assert(map != MAP_FAILED);
	assert(details.st_size >= (RESPONSE_OFFSET + len));

	rc = memcmp(expected, &map[RESPONSE_OFFSET], len);

	if (rc != 0) {
		printf("\nMBOX state (%ld):\n", details.st_size);
		dump_buf(map, details.st_size);
		printf("Expected response (%lu):\n", len);
		dump_buf(expected, len);
	}

	munmap(map, details.st_size);

	return rc;
}

int mbox_command_write(struct mbox_context *context, const uint8_t *command,
		size_t len)
{
	size_t remaining;
	int rc;
	int fd;

	fd = context->fds[MBOX_FD].fd;
	rc = lseek(fd, 0, SEEK_SET);
	if (rc != 0)
		return -1;

	remaining = len;
	while (remaining > 0) {
		rc = write(fd, command, remaining);
		if (rc < 0)
			goto out;
		remaining -= rc;
	}

	rc = lseek(fd, 0, SEEK_SET);
	if (rc != 0)
		return -1;

out:
	return rc;
}

int mbox_command_dispatch(struct mbox_context *context, const uint8_t *command,
		size_t len)
{
	uint8_t status;
	int rc;

	rc = mbox_command_write(context, command, len);
	if (rc < 0)
		return rc;

	rc = dispatch_mbox(context);
	if (rc < 0)
		return -rc;

	/*
	 * The aspeed-lpc-ctrl driver implements mailbox register access
	 * through the usual read()/write() chardev interface.
	 *
	 * The typical access sequence is:
	 *
	 * 1. Read all the registers out
	 * 2. Perform the action specified
	 * 3. Write a response to the registers.
	 *
	 * For the tests the "device" file descriptor is backed by a temporary
	 * file. The above sequence leads to a file-size of 30 bytes: 16 bytes
	 * for the issued command, followed by a 14-byte response.
	 *
	 * However, the typical access pattern isn't the only access pattern.
	 * Individual byte registers can be accessed by lseek()'ing on the
	 * device's file descriptor and issuing read() or write() as desired.
	 * The daemon uses this property to manage the BMC status byte, and the
	 * implementation cleans up after status byte operations by lseek()'ing
	 * back to offset zero.
	 *
	 * Thus for the BMC_EVENT_ACK command the file only reaches a size of
	 * 16 bytes; the daemon's response overwrites the first 14 bytes of the
	 * command injected by the tests.
	 *
	 * The consequence of this is that the response status byte can either
	 * appear at offset 13, or offset 29, depending on the command.
	 *
	 * However, regardless of what command is issued the response data is
	 * written to the device and the file descriptor is left in the
	 * post-write() state. This means the status byte can always be
	 * accessed relative to the current position by an lseek() of type
	 * SEEK_CUR for offset -1.
	 *
	 */
	rc = lseek(context->fds[MBOX_FD].fd, -1, SEEK_CUR);
	if (rc < 0)
		return rc;

	rc = read(context->fds[MBOX_FD].fd, &status, sizeof(status));
	if (rc < 0)
		return rc;

	return status;
}

struct mbox_test_context {
	struct tmpf mbox;
	struct tmpf flash;
	struct tmpf lpc;
	struct mbox_context context;
} test;

void cleanup(void)
{
	tmpf_destroy(&test.mbox);
	tmpf_destroy(&test.flash);
	tmpf_destroy(&test.lpc);
}

int __init_mbox_dev(struct mbox_context *context, const char *path);
int __init_lpc_dev(struct mbox_context *context, const char *path);

struct mbox_context *mbox_create_test_context(int n_windows, size_t len)
{
	int rc;

	mbox_vlog = &mbox_log_console;
	verbosity = 2;

	atexit(cleanup);

	rc = tmpf_init(&test.mbox, "mboxXXXXXX");
	assert(rc == 0);

	rc = tmpf_init(&test.flash, "flashXXXXXX");
	assert(rc == 0);

	rc = tmpf_init(&test.lpc, "lpcXXXXXX");
	assert(rc == 0);

	test.context.windows.num = n_windows;
	test.context.windows.default_size = len;

	/*
	 * We need to control MBOX_FD, so don't call __init_mbox_dev().
	 * Instead, insert our temporary file's fd directly into the context
	 */
	test.context.fds[MBOX_FD].fd = test.mbox.fd;

	rc = init_flash_dev(&test.context);
	assert(rc == 0);

	rc = fallocate(test.flash.fd, 0, 0, test.context.mtd_info.size);
	assert(rc == 0);

	rc = fallocate(test.lpc.fd, 0, 0, test.context.mtd_info.size);
	assert(rc == 0);

	rc = __init_lpc_dev(&test.context, test.lpc.path);
	assert(rc == 0);

	rc = init_windows(&test.context);
	assert(rc == 0);

	return rc ? NULL : &test.context;
}

/* From ccan's container_of module, CC0 license */
#define container_of(member_ptr, containing_type, member)		\
	 ((containing_type *)						\
	  ((char *)(member_ptr)						\
	   - container_off(containing_type, member))			\
	  + check_types_match(*(member_ptr), ((containing_type *)0)->member))

/* From ccan's container_of module, CC0 license */
#define container_off(containing_type, member)	\
		offsetof(containing_type, member)

/* From ccan's check_type module, CC0 license */
#define check_type(expr, type)			\
	((typeof(expr) *)0 != (type *)0)

/* From ccan's check_type module, CC0 license */
#define check_types_match(expr1, expr2)		\
	((typeof(expr1) *)0 != (typeof(expr2) *)0)

int mbox_set_mtd_data(struct mbox_context *context, const void *data,
		size_t len)
{
	struct mbox_test_context *arg;
	void *map;

	/* Sanity check */
	arg = container_of(context, struct mbox_test_context, context);
	if (&test != arg)
		return -1;

	if (len > test.context.mtd_info.size)
		return -2;

	map = mmap(NULL, test.context.mtd_info.size, PROT_WRITE, MAP_SHARED,
			test.flash.fd, 0);
	assert(map != MAP_FAILED);
	memcpy(map, data, len);
	munmap(map, test.context.mtd_info.size);

	return 0;
}

char *get_dev_mtd(void)
{
	return strdup(test.flash.path);
}
