/*
 * Mailbox Daemon Temporary File helpers
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

#ifndef MBOX_TEST_UTILS_H
#define MBOX_TEST_UTILS_H

#include <linux/limits.h>

struct tmpf {
	int fd;
	char path[PATH_MAX];
};

int tmpf_init(struct tmpf *tmpf, const char *template_str);

void tmpf_destroy(struct tmpf *tmpf);

#endif /* MBOX_TEST_UTILS_H */
