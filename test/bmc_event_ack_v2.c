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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "mbox.h"
#include "mboxd_msg.h"

#include "test/mbox.h"
#include "test/system.h"

#define FLAGS 0xc3

static const uint8_t command[] = {
	0x09, 0xaa, FLAGS, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, FLAGS
};

#define MEM_SIZE	3
#define ERASE_SIZE	1
#define N_WINDOWS	1
#define WINDOW_SIZE	1

int main(void)
{
	struct mbox_context *ctx;
	struct stat details;
	uint8_t *map;
	int rc;

	system_set_reserved_size(MEM_SIZE);
	system_set_mtd_sizes(MEM_SIZE, ERASE_SIZE);

	ctx = mbox_create_test_context(N_WINDOWS, WINDOW_SIZE);

	rc = mbox_command_dispatch(ctx, command, sizeof(command));
	assert(rc == 1);

	rc = fstat(ctx->fds[MBOX_FD].fd, &details);
	assert(rc == 0);

	assert(details.st_size == 16);

	map = mmap(NULL, details.st_size, PROT_READ, MAP_PRIVATE,
			ctx->fds[MBOX_FD].fd, 0);
	assert(map != MAP_FAILED);

	if (map[15] != 0x00)
		return -1;

	return rc;
}
