/*
 * Copyright 2016 IBM
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

#ifndef MBOXD_FLASH_H
#define MBOXD_FLASH_H

#define FLASH_DIRTY		0x00
#define FLASH_ERASED		0x01
#define FLASH_LOCKED		0x04 /* Make this the same as the window one */

#define FLASH_LOCKED_FILE	"/var/lib/obmc/flash_locked_bmap"

#include "mbox.h"

int init_flash_dev(struct mbox_context *context);
void free_flash_dev(struct mbox_context *context);
int init_flash_lock_file(struct mbox_context *context);
void close_flash_lock_file(struct mbox_context *context);
int copy_flash(struct mbox_context *context, uint32_t offset, void *mem,
	       uint32_t size);
bool search_flash_bytemap(struct mbox_context *context, uint32_t offset,
			  uint32_t size, uint8_t val, uint32_t *loc);
int set_flash_bytemap(struct mbox_context *context, uint32_t offset,
		      uint32_t count, uint8_t val);
int save_flash_lock(struct mbox_context *context, uint32_t offset,
		    uint32_t count);
int clear_flash_lock(struct mbox_context *context);
int write_flash(struct mbox_context *context, uint32_t offset, void *buf,
		uint32_t count);
int smart_erase_flash(struct mbox_context *context, uint32_t offset,
		      uint32_t count);

#endif /* MBOXD_FLASH_H */
