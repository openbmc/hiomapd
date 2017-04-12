#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <linux/types.h>

#include "mbox.h"
#include "mboxd_flash.h"

#include "test/tmpf.h"

static struct tmpf mtd;

void cleanup_mtd(void)
{
	tmpf_destroy(&mtd);
}

char *get_dev_mtd(void)
{
	int rc;

	rc = tmpf_init(&mtd, "flashXXXXXX");
	if (rc < 0)
		return NULL;

	return strdup(mtd.path);
}

struct erase_info_user *recorded;
int n_ioctls;

int ioctl(int fd, unsigned long request, ...)
{
	va_list ap;
	struct erase_info_user *provided, *alloced;

	if (!(request == MEMERASE || request == MEMGETINFO)) {
		printf("Uh-oh: ioctl() called with request 0x%08lx\n", request);
		return -1;
	}

	switch (request) {
	case MEMGETINFO:
		break;
	case MEMERASE:
		va_start(ap, request);
		provided = va_arg(ap, struct erase_info_user *);

		n_ioctls++;

		alloced = realloc(recorded, n_ioctls * sizeof(*recorded));
		if (!alloced)
			return -1;
		recorded = alloced;

		memcpy(&recorded[n_ioctls - 1], provided, sizeof(*provided));

		va_end(ap);
		break;
	default:
		break;
	}

	return 0;
}

void dump_ioctls(void)
{
	int i;

	printf("n_ioctls: %d\n", n_ioctls);

	for (i = 0; i < n_ioctls; i++)
		printf("%d: start: %d, length %d\n",
				i, recorded[i].start, recorded[i].length);
}

#define TEST_SIZE 3

int main(void)
{
	struct mbox_context context;
	char data[TEST_SIZE];
	int rc;

	rc = atexit(cleanup_mtd);
	if (rc)
		return rc;

	n_ioctls = 0;
	recorded = NULL;

	context.flash_size = 3;
	init_flash_dev(&context);
	context.erase_size_shift = 0;

	/* Erase from an unknown state */
	rc = erase_flash(&context, 0, sizeof(data));

	assert(rc == 0);
	assert(n_ioctls == 1);
	assert(recorded[0].start == 0);
	assert(recorded[0].length == sizeof(data));

	free(recorded);
	recorded = NULL;
	n_ioctls = 0;

	/* Erase an erased flash */
	rc = erase_flash(&context, 0, sizeof(data));

	assert(rc == 0);
	assert(n_ioctls == 0);

	/* Erase written flash */
	memset(data, 0xaa, sizeof(data));
	rc = write_flash(&context, 0, data, sizeof(data));
	assert(rc == 0);
	rc = erase_flash(&context, 0, sizeof(data));

	assert(rc == 0);
	assert(n_ioctls == 1);
	assert(recorded[0].start == 0);
	assert(recorded[0].length == sizeof(data));

	free(recorded);
	recorded = NULL;
	n_ioctls = 0;

	/* Erase the start of flash */
	memset(data, 0xaa, sizeof(data));
	rc = write_flash(&context, 0, data, 2);
	assert(rc == 0);
	rc = erase_flash(&context, 0, sizeof(data));

	assert(rc == 0);
	assert(n_ioctls == 1);
	assert(recorded[0].start == 0);
	assert(recorded[0].length == 2);

	free(recorded);
	recorded = NULL;
	n_ioctls = 0;

	/* Erase the end of flash */
	memset(data, 0xaa, sizeof(data));
	rc = write_flash(&context, 1, data, 2);
	assert(rc == 0);
	rc = erase_flash(&context, 0, sizeof(data));

	assert(rc == 0);
	assert(n_ioctls == 1);
	assert(recorded[0].start == 1);
	assert(recorded[0].length == 2);

	free(recorded);
	recorded = NULL;
	n_ioctls = 0;

	/* Erase each end of flash */
	memset(data, 0xaa, sizeof(data));
	rc = write_flash(&context, 0, data, 1);
	rc = write_flash(&context, 2, data, 1);
	assert(rc == 0);
	rc = erase_flash(&context, 0, sizeof(data));

	assert(rc == 0);
	assert(n_ioctls == 2);
	assert(recorded[0].start == 0);
	assert(recorded[0].length == 1);
	assert(recorded[1].start == 2);
	assert(recorded[1].length == 1);

	free(recorded);
	recorded = NULL;
	n_ioctls = 0;

	/* Erase the middle of flash */
	memset(data, 0xaa, sizeof(data));
	rc = write_flash(&context, 1, data, 1);
	assert(rc == 0);
	rc = erase_flash(&context, 0, sizeof(data));

	assert(rc == 0);
	assert(n_ioctls == 1);
	assert(recorded[0].start == 1);
	assert(recorded[0].length == 1);

	free(recorded);
	recorded = NULL;
	n_ioctls = 0;

	return rc;
}
