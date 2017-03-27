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

#define FLASH_DIRTY	0x00
#define FLASH_ERASED	0x01

int init_flash_dev(struct mbox_context *context);
int copy_flash(struct mbox_context *context, uint32_t offset, void *mem,
	       uint32_t size);
int set_flash_bytemap(struct mbox_context *context, uint32_t offset,
		      uint32_t count, uint8_t val);
int erase_flash(struct mbox_context *context, uint32_t offset, uint32_t count);
int write_flash(struct mbox_context *context, uint32_t offset, void *buf,
		uint32_t count);

#endif /* MBOXD_FLASH_H */
