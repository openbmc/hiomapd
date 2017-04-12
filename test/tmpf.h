#ifndef MBOX_TEST_UTILS_H
#define MBOX_TEST_UTILS_H

#include <linux/limits.h>

struct tmpf {
	int fd;
	char path[PATH_MAX];
};

int tmpf_init(struct tmpf *tmpf, const char *template);

void tmpf_destroy(struct tmpf *tmpf);

#endif /* MBOX_TEST_UTILS_H */
