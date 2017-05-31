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
#include "pnor_partition.hpp"
#include "xyz/openbmc_project/Common/error.hpp"
#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog-errors.hpp>

#include <string>
#include <exception>
#include <stdexcept>

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
    using namespace phosphor::logging;
    using namespace sdbusplus::xyz::openbmc_project::Common::Error;
    using namespace std::string_literals;

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
            const struct pnor_partition_table* table =
                vpnor_get_partition_table(context);
            memcpy(mem,
                   ((uint8_t*)table) + offset,
                   min_u32(sz - offset, size));
        }
        else
        {
            openpower::virtual_pnor::RORequest roRequest;
            auto partitionInfo = roRequest.getPartitionInfo(context, offset);

            auto mapped_mem = mmap(NULL, partitionInfo->data.actual,
                                   PROT_READ, MAP_PRIVATE, roRequest.fd(), 0);

            if (mem == MAP_FAILED)
            {
                MSG_ERR("Failed to map partition=%s:Error=%s\n",
                        partitionInfo->data.name, strerror(errno));

                elog<InternalFailure>();
            }

            // if the asked offset + no of bytes to read is greater
            // then size of the partition file then throw error.

            uint32_t baseOffset = partitionInfo->data.base << context->block_size_shift;

            if ((offset + size) > (baseOffset + partitionInfo->data.actual))
            {
                MSG_ERR("Offset is beyond the partition file length[0x%.8x]\n",
                        partitionInfo->data.actual);
                munmap(mapped_mem, partitionInfo->data.actual);
                elog<InternalFailure>();
            }

            //copy to the reserved memory area
            auto diffOffset = offset - baseOffset;
            memcpy(mem, (char*)mapped_mem + diffOffset , size);
            munmap(mapped_mem, partitionInfo->data.actual);
        }
    }
    catch (InternalFailure& e)
    {
        commit<InternalFailure>();
        rc = -1;
    }
    return rc;
}

/*
 * write_flash() - Write to the virtual pnor from a provided buffer
 * @context: The mbox context pointer
 * @offset:  The flash offset to write to (bytes)
 * @buf:     The buffer to write from (must be of atleast size)
 * @size:    The number of bytes to write
 *
 * Return:  0 on success otherwise negative error code
 */

int write_flash(struct mbox_context* context, uint32_t offset, void* buf,
                uint32_t count)
{
    using namespace phosphor::logging;
    using namespace sdbusplus::xyz::openbmc_project::Common::Error;
    using namespace std::string_literals;

    int rc = 0;
    MSG_DBG("Write flash @ 0x%.8x for 0x%.8x from %p\n", offset, count, buf);
    try
    {
        openpower::virtual_pnor::RWRequest rwRequest;
        auto partitionInfo = rwRequest.getPartitionInfo(context, offset);


        auto mapped_mem = mmap(NULL, partitionInfo->data.actual,
                               PROT_READ | PROT_WRITE,
                               MAP_SHARED, rwRequest.fd(), 0);
        if (mapped_mem == MAP_FAILED)
        {
            MSG_ERR("Failed to map partition=%s:Error=%s\n",
                    partitionInfo->data.name, strerror(errno));

            elog<InternalFailure>();
        }
        //copy to the mapped memory.

        uint32_t baseOffset = partitionInfo->data.base << context->block_size_shift;

        // if the asked offset + no of bytes to write is greater
        // then size of the partition file then throw error.
        if ((offset + count) > (baseOffset + partitionInfo->data.actual))
        {
            MSG_ERR("Offset is beyond the partition file length[0x%.8x]\n",
                     partitionInfo->data.actual);
            munmap(mapped_mem, partitionInfo->data.actual);
            elog<InternalFailure>();
        }

        auto diffOffset = offset - baseOffset;
        memcpy((char*)mapped_mem + diffOffset , buf, count);
        munmap(mapped_mem, partitionInfo->data.actual);

        set_flash_bytemap(context, offset, count, FLASH_DIRTY);
    }
    catch (InternalFailure & e)
    {
        rc = -1;
    }
    return rc;
}
