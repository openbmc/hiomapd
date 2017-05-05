/*
 * Mailbox Daemon Window Helpers
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

#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/mman.h>
#include <unistd.h>

extern "C" {
#include "common.h"
}

#include "config.h"
#include "mboxd_flash.h"
#include "mboxd_pnor_partition_table.h"

#include <string>
#include <exception>
#include <stdexcept>
#include <experimental/filesystem>

namespace fs = std::experimental::filesystem;
/*
 * copy_flash() - Copy data from the virtual pnor into a provided buffer
 * @context:    The mbox context pointer
 * @offset:     The pnor offset to copy from (bytes)
 * @mem:        The buffer to copy into (must be of atleast 'size' bytes)
 * @size:       The number of bytes to copy
 *
 * Return:      0 on success otherwise negative error code
 */
int copy_flash(struct mbox_context* context, uint32_t offset, void* mem,
               uint32_t size)
{
    int rc = 0;

    MSG_DBG("Copy virtual pnor to %p for size 0x%.8x from offset 0x%.8x\n",
            mem, size, offset);

    /* The virtual PNOR partition table starts at offset 0 in the virtual
     * pnor image. Check if host asked for an offset that lies within the
     * partition table.
     */
    try
    {
        size_t sz =
            vpnor_get_partition_table_size(context) << context->block_size_shift;
        if (offset < sz)
        {
            struct pnor_partition_table* table =
                vpnor_get_partition_table(context);
            memcpy(mem,
                   ((uint8_t*)table) + offset,
                   min_u32(sz - offset, size));
            free(table);
        }
        else
        {
            /* Copy from virtual pnor into the window buffer */
            auto partition = vpnor_get_partition(context, offset);
            if (!partition)
            {
                std::string msg = "Couldn't get the partition info for offset " +
                                  offset;
                throw std::runtime_error(msg);
            }

            fs::path partitionFilePath = context->paths.ro_loc;
            partitionFilePath /= partition->data.name;

            auto fd = open(partitionFilePath.c_str(), O_RDONLY);
            if (fd == -1)
            {
                throw std::runtime_error("Couldn't open the partition file");
            }

            auto mapped_mem = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd,
                                   offset);

            if (mem == MAP_FAILED)
            {
                std::string msg = "Failed to map" + partitionFilePath.string() + ":"
                                  + strerror(errno);
                close(fd);
                throw std::runtime_error(msg);
            }
            //copy to the reserved memory area
            memcpy(mem, mapped_mem, size);
            munmap(mapped_mem, size);
            close(fd);
        }
    }
    catch (const std::exception& e)
    {
        MSG_ERR(e.what());
        rc = -1;
    }
    return rc;
}
