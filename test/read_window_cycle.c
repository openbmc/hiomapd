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

#include "mbox.h"
#include "mboxd_msg.h"

#include "test/mbox.h"
#include "test/system.h"

static const uint8_t get_info[] = {
	0x02, 0xaa, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t create_read_window_block_0[] = {
	0x04, 0xaa, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t create_read_window_block_1[] = {
	0x04, 0xaa, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t create_read_window_block_2[] = {
	0x04, 0xaa, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

uint8_t data[] = { 0x00, 0x01, 0x02 };

#define MEM_SIZE	sizeof(data)
#define ERASE_SIZE	1
#define N_WINDOWS	MEM_SIZE - 1
#define WINDOW_SIZE	1

int main(void)
{
	struct mbox_context *ctx;
	int rc;
	int i;

	system_set_reserved_size(N_WINDOWS);
	system_set_mtd_sizes(MEM_SIZE, ERASE_SIZE);

	ctx = mbox_create_test_context(N_WINDOWS, WINDOW_SIZE);
	rc = mbox_set_mtd_data(ctx, data, sizeof(data));
	assert(rc == 0);

	rc = mbox_command_dispatch(ctx, get_info, sizeof(get_info));
	assert(rc == 1);

	/* Make each block appear in each window */
	for (i = 0; i < 2; i++) {
		rc = mbox_command_dispatch(ctx, create_read_window_block_0,
				sizeof(create_read_window_block_0));
		assert(rc == 1);
		assert(((uint8_t *)ctx->mem)[(0 + i) & 1] == 0x00);

		rc = mbox_command_dispatch(ctx, create_read_window_block_1,
				sizeof(create_read_window_block_1));
		assert(rc == 1);
		assert(((uint8_t *)ctx->mem)[(1 + i) & 1] == 0x01);

		rc = mbox_command_dispatch(ctx, create_read_window_block_2,
				sizeof(create_read_window_block_2));
		assert(rc == 1);
		assert(((uint8_t *)ctx->mem)[(2 + i) & 1] == 0x02);
	}

	return !(rc == 1);
};
