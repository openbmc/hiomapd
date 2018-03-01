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

#include <linux/types.h>
#include <mtd/mtd-user.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "linux/aspeed-lpc-ctrl.h"

static struct aspeed_lpc_ctrl_mapping ctrl = {
};

static struct mtd_info_user mtd = {
	.type = MTD_NORFLASH,
	.flags = MTD_WRITEABLE,
};

void system_set_reserved_size(uint32_t size)
{
	ctrl.size = size;
}

void system_set_mtd_sizes(uint32_t size, uint32_t erasesize)
{
	mtd.size = size;
	mtd.erasesize = erasesize;
	mtd.writesize = erasesize;
}

int ioctl(int fd, unsigned long request, ...)
{
	int rc = 0;
	va_list ap;

	switch (request) {
	case MEMGETINFO:
	{
		struct mtd_info_user *info;

		va_start(ap, request);
		info = va_arg(ap, struct mtd_info_user *);
		memcpy(info, &mtd, sizeof(mtd));
		va_end(ap);
		break;
	}
	case MEMERASE:
	{
		struct erase_info_user *info;
		uint8_t *map;

		va_start(ap, request);
		info = va_arg(ap, struct erase_info_user *);

		if (info->start + info->length > mtd.size)
			return -1;

		map = mmap(NULL, mtd.size, PROT_WRITE, MAP_SHARED, fd, 0);
		if (map == MAP_FAILED)
			return -1;

		memset(&map[info->start], 0xff, info->length);
		munmap(map, mtd.size);

		va_end(ap);
		break;
	}
	case ASPEED_LPC_CTRL_IOCTL_GET_SIZE:
	{
		struct aspeed_lpc_ctrl_mapping *info;

		va_start(ap, request);
		info = va_arg(ap, struct aspeed_lpc_ctrl_mapping *);
		info->size = ctrl.size;
		va_end(ap);
		break;
	}
	case ASPEED_LPC_CTRL_IOCTL_MAP:
		break;
	default:
		printf("ioctl() called with unhandled request 0x%08lx\n", request);
		rc = -1;
		break;
	}

	return rc;
}
