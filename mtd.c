/*
 * Mailbox Daemon Implementation
 *
 * Copyright 2018 IBM
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
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "common.h"

static bool is_pnor_part(const char *str)
{
	return strcasestr(str, "pnor") != NULL;
}

char *get_dev_mtd(void)
{
	FILE *f;
	char *ret = NULL, *pos = NULL;
	char line[255];

	f = fopen("/proc/mtd", "r");
	if (!f)
		return NULL;

	while (!pos && fgets(line, sizeof(line), f) != NULL) {
		/* Going to have issues if we didn't get the full line */
		if (line[strlen(line) - 1] != '\n')
			break;

		if (is_pnor_part(line)) {
			pos = strchr(line, ':');
			if (!pos)
				break;
		}
	}
	fclose(f);

	if (pos) {
		*pos = '\0';
		if (asprintf(&ret, "/dev/%s", line) == -1)
			ret = NULL;
	}

	return ret;
}
