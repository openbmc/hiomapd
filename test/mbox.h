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

#ifndef TEST_MBOX_H
#define TEST_MBOX_H

#include <stddef.h>
#include <stdint.h>

#include "../common.h"
#include "../mbox.h"

#include "tmpf.h"

struct mbox_context *mbox_create_test_context(int n_windows, size_t len);

int mbox_set_mtd_data(struct mbox_context *context, const void *data,
		size_t len);

void mbox_dump(struct mbox_context *context);

int mbox_cmp(struct mbox_context *context, const uint8_t *expected, size_t len);

int mbox_command_write(struct mbox_context *context, const uint8_t *command,
		size_t len);

int mbox_command_dispatch(struct mbox_context *context, const uint8_t *command,
	size_t len);

/* Helpers */
void dump_buf(const uint8_t *buf, size_t len);

#endif /* TEST_MBOX_H */
