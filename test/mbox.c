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

void dump_fd(int fd)
{
	struct stat details;
	uint8_t *map;

	fstat(fd, &details);

	map = mmap(NULL, details.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	assert(map != MAP_FAILED);

	printf("Size: %ld\n", details.st_size);
	dump_buf(map, details.st_size);
	munmap(map, details.st_size);

}

void mbox_dump(struct mbox_context *context)
{
	printf("\nMBOX state:\n");
	dump_fd(context->fds[MBOX_FD].fd);
}

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
		mbox_dump(context);
		printf("Expected response (%lu):\n", len);
		dump_buf(expected, len);
	}

	munmap(map, details.st_size);

	return rc;
}

int mbox_command(struct mbox_context *context, const uint8_t *command, size_t len)
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

out:
	rc = lseek(fd, 0, SEEK_SET);
	if (rc != 0)
		return -1;

	return 0;
}

struct mbox_test_context {
	struct tmpf mbox;
	struct tmpf flash;
	struct tmpf lpc;
	struct mbox_context ctx;
} tctx;

void cleanup(void)
{
	tmpf_destroy(&tctx.mbox);
	tmpf_destroy(&tctx.flash);
	tmpf_destroy(&tctx.lpc);
}

int __init_mbox_dev(struct mbox_context *context, const char *path);
int __init_lpc_dev(struct mbox_context *context, const char *path);

struct mbox_context *mbox_create_test_context(int n_windows, size_t len)
{
	int rc;

	mbox_vlog = &mbox_log_console;
	verbosity = 2;

	atexit(cleanup);

	rc = tmpf_init(&tctx.mbox, "mboxXXXXXX");
	assert(rc == 0);

	rc = tmpf_init(&tctx.flash, "flashXXXXXX");
	assert(rc == 0);

	rc = tmpf_init(&tctx.lpc, "lpcXXXXXX");
	assert(rc == 0);
	
	tctx.ctx.windows.num = n_windows;
	tctx.ctx.windows.default_size = len;

	/*
	 * We need to control MBOX_FD, so don't call __init_mbox_dev().
	 * Instead, insert our temporary file's fd directly into the context
	 */
	tctx.ctx.fds[MBOX_FD].fd = tctx.mbox.fd;

	rc = __init_lpc_dev(&tctx.ctx, tctx.lpc.path);
	assert(rc == 0);

	tctx.ctx.mem = calloc(1, tctx.ctx.mem_size);
	assert(tctx.ctx.mem);

	rc = init_flash_dev(&tctx.ctx);
	assert(rc == 0);
	tctx.ctx.flash_size = tctx.ctx.mtd_info.size;

	rc = fallocate(tctx.flash.fd, 0, 0, tctx.ctx.mtd_info.size);
	assert(rc == 0);

	rc = init_windows(&tctx.ctx);
	assert(rc == 0);

	rc = init_window_mem(&tctx.ctx);
	assert(rc == 0);

	return &tctx.ctx;
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

int mbox_set_mtd_data(struct mbox_context *context, const void *data, size_t len)
{
	int remaining;
	int written;
	int rc;

	/* Sanity check */
	{
		struct mbox_test_context *test =
			container_of(context, struct mbox_test_context, ctx);
		assert(&tctx == test);
	}

	rc = lseek(tctx.flash.fd, 0, SEEK_SET);
	if (rc < 0)
		return rc;

	remaining = len;
	do {
		written = write(tctx.flash.fd, data, len);
		if (written < 0)
			return written;

		remaining -= written;
	} while (remaining && written);

	return 0;
}

char *get_dev_mtd(void)
{
	return strdup(tctx.flash.path);
}
