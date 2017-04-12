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
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common.h"
#include "mbox.h"
#include "mboxd_flash.h"

#include "test/tmpf.h"

#define TEST_SIZE 4096

static struct tmpf tmp;

void cleanup(void)
{
	tmpf_destroy(&tmp);
}

int main(void)
{
	struct mbox_context context;
	ssize_t processed;
	int rand_fd;
	char *src;
	char *dst;
	int rc;

	atexit(cleanup);

	src = malloc(TEST_SIZE);
	dst = malloc(TEST_SIZE);
	if (!(src && dst)) {
		rc = -1;
		goto free;
	}

	rand_fd = open("/dev/urandom", O_RDONLY);
	if (rand_fd < 0) {
		rc = rand_fd;
		goto free;
	}

	rc = tmpf_init(&tmp, "flashXXXXXX");
	if (rc < 0)
		goto free;

	processed = read(rand_fd, src, TEST_SIZE);
	if (processed != TEST_SIZE) {
		rc = -1;
		goto free;
	}

	processed = write(tmp.fd, src, TEST_SIZE);
	if (processed != TEST_SIZE) {
		rc = -1;
		goto free;
	}

	context.fds[MTD_FD].fd = tmp.fd;

	copy_flash(&context, 0, dst, TEST_SIZE);
	assert(0 == memcmp(src, dst, TEST_SIZE));

free:
	free(src);
	free(dst);

	return rc;
}
