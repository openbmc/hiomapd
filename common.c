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

#define _GNU_SOURCE
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>

#include "common.h"

void (*mbox_vlog)(int p, const char *fmt, va_list args);

verbose verbosity;


void mbox_log_console(int p, const char *fmt, va_list args)
{
	struct timespec time;
	FILE *s = (p < LOG_WARNING) ? stdout : stderr;

	clock_gettime(CLOCK_REALTIME, &time);

	fprintf(s, "[%s %ld.%.9ld] ", PREFIX, time.tv_sec, time.tv_nsec);

	vfprintf(s, fmt, args);
}

__attribute__((format(printf, 2, 3)))
void mbox_log(int p, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	mbox_vlog(p, fmt, args);
	va_end(args);
}

uint16_t get_u16(uint8_t *ptr)
{
	return *(uint16_t *)ptr;
}

void put_u16(uint8_t *ptr, uint16_t val)
{
	memcpy(ptr, &val, sizeof(val));
}

uint32_t get_u32(uint8_t *ptr)
{
	return *(uint32_t *)ptr;
}

void put_u32(uint8_t *ptr, uint32_t val)
{
	memcpy(ptr, &val, sizeof(val));
}

