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

static const uint8_t get_mbox_info[] = {
	0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t invalid[] = {
	0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t response[] = {
	0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
};

#define MEM_SIZE	3
#define ERASE_SIZE	1
#define N_WINDOWS	1
#define WINDOW_SIZE	1

int invalid_uninitialised(struct mbox_context *ctx)
{
	int rc;

	rc = mbox_command_dispatch(ctx, invalid, sizeof(invalid));
	assert(rc == 2);

	rc = mbox_cmp(ctx, response, sizeof(response));
	assert(rc == 0);

	return rc;
}

int invalid_initialised(struct mbox_context *ctx)
{
	int rc;

	rc = mbox_command_dispatch(ctx, get_mbox_info, sizeof(get_mbox_info));
	assert(rc == 1);

	rc = mbox_command_dispatch(ctx, invalid, sizeof(invalid));
	assert(rc == 2);

	rc = mbox_cmp(ctx, response, sizeof(response));
	assert(rc == 0);

	return rc;
}

int main(void)
{
	struct mbox_context *ctx;

	system_set_reserved_size(MEM_SIZE);
	system_set_mtd_sizes(MEM_SIZE, ERASE_SIZE);

	ctx = mbox_create_test_context(N_WINDOWS, WINDOW_SIZE);

	invalid_uninitialised(ctx);

	invalid_initialised(ctx);

	return 0;
}
