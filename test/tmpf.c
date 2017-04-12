#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test/tmpf.h"

int tmpf_init(struct tmpf *tmpf, const char *template)
{
	strncpy(tmpf->path, template, sizeof(tmpf->path) - 1);

	tmpf->fd = mkstemp(tmpf->path);
	if (tmpf->fd < 0) {
		perror("mkstemp");
		return -1;
	}

	return 0;
}

void tmpf_destroy(struct tmpf *tmpf)
{
	if (tmpf->fd)
		close(tmpf->fd);

	if (tmpf->path)
		unlink(tmpf->path);
}
