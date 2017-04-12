
#ifndef TEST_MBOX_H
#define TEST_MBOX_H

#include <stddef.h>
#include <stdint.h>

#include "../common.h"
#include "../mbox.h"

#include "tmpf.h"

struct mbox_context *mbox_create_test_context(int n_windows, size_t len);
int mbox_set_mtd_data(struct mbox_context *context, const void *data, size_t len);
void mbox_dump(struct mbox_context *context);
int mbox_cmp(struct mbox_context *context, const uint8_t *expected, size_t len);
int mbox_command(struct mbox_context *context, const uint8_t *command, size_t len);

/* Helpers */
void dump_buf(const uint8_t *buf, size_t len);
void dump_fd(int fd);

#endif /* TEST_MBOX_H */
