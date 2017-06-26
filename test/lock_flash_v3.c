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

#include <assert.h>
#include <sys/mman.h>

#include "mbox.h"
#include "mboxd_msg.h"

#include "test/mbox.h"
#include "test/system.h"

static const uint8_t get_info[] = {
	0x02, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t create_write_window[] = {
	0x06, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t mark_write_dirty_all[] = {
	0x07, 0x02, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t write_flush[] = {
	0x08, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t lock_flash[] = {
	0x0b, 0x09, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t mark_write_erase_start[] = {
	0x0a, 0x0a, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t mark_write_erase_end[] = {
	0x0a, 0x0b, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t mark_write_erase_middle[] = {
	0x0a, 0x0c, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

const uint8_t start_data[] = { 0xaa, 0xaa, 0xaa };
const uint8_t dirty_data[] = { 0x55, 0x55, 0x55 };
const uint8_t erase_data[] = { 0xff, 0x55, 0xff };
const uint8_t lockf_data[] = { 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };

#define MEM_SIZE	sizeof(start_data)
#define ERASE_SIZE	1
#define N_WINDOWS	1
#define WINDOW_SIZE	sizeof(start_data)

int main(void)
{
	struct mbox_context *ctx;
	uint8_t *map, *lmap;
	int rc;

	system_set_reserved_size(MEM_SIZE);
	system_set_mtd_sizes(MEM_SIZE, ERASE_SIZE);

	ctx = mbox_create_test_context(N_WINDOWS, WINDOW_SIZE);
	rc = mbox_set_mtd_data(ctx, start_data, sizeof(start_data));
	assert(rc == 0);

	map = mmap(NULL, MEM_SIZE, PROT_READ, MAP_PRIVATE,
			ctx->fds[MTD_FD].fd, 0);
	assert(map != MAP_FAILED);

	rc = mbox_command_dispatch(ctx, get_info, sizeof(get_info));
	assert(rc == 1);

	rc = mbox_command_dispatch(ctx, create_write_window,
			sizeof(create_write_window));
	assert(rc == 1);

	/* Try to write the whole window, not locked -> should be allowed */

	((uint8_t *)ctx->mem)[0] = 0x55;
	((uint8_t *)ctx->mem)[1] = 0x55;
	((uint8_t *)ctx->mem)[2] = 0x55;

	rc = mbox_command_dispatch(ctx, mark_write_dirty_all,
			sizeof(mark_write_dirty_all));
	assert(rc == 1);

	rc = mbox_command_dispatch(ctx, write_flush, sizeof(write_flush));
	assert(rc == 1);

	rc = memcmp(dirty_data, map, sizeof(dirty_data));
	assert(rc == 0);

	/* Lock the middle byte of the window */

	rc = mbox_command_dispatch(ctx, lock_flash, sizeof(lock_flash));
	assert(rc == 1);

	/* Try to write the whole window, locked -> should not be allowed */

	((uint8_t *)ctx->mem)[0] = 0x11;
	((uint8_t *)ctx->mem)[1] = 0x11;
	((uint8_t *)ctx->mem)[2] = 0x11;

	rc = mbox_command_dispatch(ctx, mark_write_dirty_all,
			sizeof(mark_write_dirty_all));
	assert(rc == MBOX_R_LOCKED_ERROR);

	/* Try to flush -> window contents shouldn't change */

	rc = mbox_command_dispatch(ctx, write_flush, sizeof(write_flush));
	assert(rc == 1);

	rc = memcmp(dirty_data, map, sizeof(dirty_data));
	assert(rc == 0);

	/* Try to erase first & last byte, not locked -> should be allowed */

	rc = mbox_command_dispatch(ctx, mark_write_erase_start,
			sizeof(mark_write_erase_start));
	assert(rc == 1);

	rc = mbox_command_dispatch(ctx, mark_write_erase_end,
			sizeof(mark_write_erase_end));
	assert(rc == 1);

	rc = mbox_command_dispatch(ctx, write_flush, sizeof(write_flush));
	assert(rc == 1);

	rc = memcmp(erase_data, map, sizeof(erase_data));
	assert(rc == 0);

	/* Try to erase the middle, locked -> should not be allowed */

	rc = mbox_command_dispatch(ctx, mark_write_erase_middle,
			sizeof(mark_write_erase_middle));
	assert(rc == MBOX_R_LOCKED_ERROR);

	/*
	 * Write to the reserved memory then try to open the window again ->
	 * Changes shouldn't be visible when window is reloaded
	 */

	((uint8_t *)ctx->mem)[0] = 0xee;
	((uint8_t *)ctx->mem)[1] = 0xee;
	((uint8_t *)ctx->mem)[2] = 0xee;

	rc = mbox_command_dispatch(ctx, create_write_window,
			sizeof(create_write_window));
	assert(rc == 1);

	rc = memcmp(erase_data, map, sizeof(erase_data));
	assert(rc == 0);

	/* Check the lock file was written successfully */

	lmap = mmap(NULL, MEM_SIZE, PROT_READ, MAP_PRIVATE,
			ctx->fds[LOCK_FD].fd, 0);
	assert(lmap != MAP_FAILED);

	rc = memcmp(lockf_data, lmap, sizeof(lockf_data));
	assert(rc == 0);

	return rc;
}
