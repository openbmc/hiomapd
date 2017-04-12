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
	if (!(src && dst))
		return -1;

	rand_fd = open("/dev/urandom", O_RDONLY);
	if (rand_fd < 0)
		return rand_fd;

	rc = tmpf_init(&tmp, "flashXXXXXX");
	if (rc < 0)
		return -1;

	processed = read(rand_fd, src, TEST_SIZE);
	if(processed != TEST_SIZE)
		return -1;

	processed = write(tmp.fd, src, TEST_SIZE);
	if (processed != TEST_SIZE)
		return -1;

	context.fds[MTD_FD].fd = tmp.fd;

	copy_flash(&context, 0, dst, TEST_SIZE);
	assert(0 == memcmp(src, dst, TEST_SIZE));

	return 0;
}
