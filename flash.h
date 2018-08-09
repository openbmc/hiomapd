/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2018 IBM Corp. */

#ifndef FLASH_H
#define FLASH_H

#define FLASH_DIRTY	0x00
#define FLASH_ERASED	0x01

/* Estimate as to how long (milliseconds) it takes to access a MB from flash */
#define FLASH_ACCESS_MS_PER_MB		8000

#include "mbox.h"

int flash_dev_init(struct mbox_context *context);
void flash_dev_free(struct mbox_context *context);
int64_t flash_copy(struct mbox_context *context, uint32_t offset, void *mem,
		   uint32_t size);
int flash_set_bytemap(struct mbox_context *context, uint32_t offset,
		      uint32_t count, uint8_t val);
int flash_erase(struct mbox_context *context, uint32_t offset, uint32_t count);
int flash_write(struct mbox_context *context, uint32_t offset, void *buf,
		uint32_t count);

#endif /* FLASH_H */
