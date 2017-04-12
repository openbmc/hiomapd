#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "mbox.h"
#include "mboxd_flash.h"

#include "test/tmpf.h"

struct tmpf _tmp, *tmp = &_tmp;

void cleanup(void)
{
	tmpf_destroy(tmp);
}

char *get_dev_mtd(void)
{
	int rc;

	rc = tmpf_init(tmp, "flashXXXXXX");
	if (rc < 0)
		return NULL;

	return strdup(tmp->path);
}

int ioctl(int fd, unsigned long request, ...)
{
	return (request == MEMGETINFO) ? 0 : -1;
}

int main(void)
{
	struct mbox_context _context, *context = &_context;
	char src[3];
	uint8_t *map;
	int rc;

	atexit(cleanup);

	context->flash_size = 3;
	rc = init_flash_dev(context);
	assert(rc == 0);

	context->erase_size_shift = 0;

	map = mmap(NULL, 3, PROT_READ, MAP_PRIVATE, tmp->fd, 0);
	assert(map != MAP_FAILED);

	memset(src, 0xaa, sizeof(src));
	rc = write_flash(context, 0, src, sizeof(src));
	assert(rc == 0);
	rc = memcmp(src, map, sizeof(src));
	assert(rc == 0);

	memset(src, 0x55, sizeof(src));
	rc = write_flash(context, 0, src, sizeof(src));
	assert(rc == 0);
	rc = memcmp(src, map, sizeof(src));
	assert(rc == 0);

	src[0] = 0xff;
	rc = write_flash(context, 0, src, 1);
	assert(rc == 0);
	rc = memcmp(src, map, sizeof(src));
	assert(rc == 0);

	src[1] = 0xff;
	rc = write_flash(context, 1, &src[1], 1);
	assert(rc == 0);
	rc = memcmp(src, map, sizeof(src));
	assert(rc == 0);

	src[2] = 0xff;
	rc = write_flash(context, 2, &src[2], 1);
	assert(rc == 0);
	rc = memcmp(src, map, sizeof(src));
	assert(rc == 0);
}
