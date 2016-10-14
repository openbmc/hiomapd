/* Copyright 2016 IBM
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *
 */

#ifndef PREFIX
#define PREFIX ""
#endif

enum {
   MBOX_LOG_NONE = 0,
   MBOX_LOG_VERBOSE = 1,
   MBOX_LOG_DEBUG = 2
} verbosity;

void (*mbox_vlog)(int p, const char *fmt, va_list args);

void mbox_log_console(int p, const char *fmt, va_list args);

__attribute__((format(printf, 2, 3)))
void mbox_log(int p, const char *fmt, ...);

uint16_t get_u16(uint8_t *ptr);

void put_u16(uint8_t *ptr, uint16_t val);

uint32_t get_u32(uint8_t *ptr);

void put_u32(uint8_t *ptr, uint32_t val);

char *get_dev_mtd(void);
