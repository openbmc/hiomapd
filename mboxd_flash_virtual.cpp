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
#include <sys/ioctl.h>
#include <algorithm>

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

#include <memory>
#include <string>
#include <exception>
#include <stdexcept>

/** @brief unique_ptr functor to release a char* reference. */
struct StringDeleter
{
    void operator()(char* ptr) const
    {
        free(ptr);
    }
};
using StringPtr = std::unique_ptr<char, StringDeleter>;

int init_flash_dev(struct mbox_context *context)
{
    StringPtr filename(get_dev_mtd());
    int fd = 0;
    int rc = 0;

    if (!filename)
    {
        MSG_ERR("Couldn't find the flash /dev/mtd partition\n");
        return -1;
    }

    MSG_DBG("Opening %s\n", filename.get());

    fd = open(filename.get(), O_RDWR);
    if (fd < 0)
    {
        MSG_ERR("Couldn't open %s with flags O_RDWR: %s\n",
                filename.get(), strerror(errno));
        return -errno;
    }

    // Read the Flash Info
    if (ioctl(fd, MEMGETINFO, &context->mtd_info) == -1)
    {
        MSG_ERR("Couldn't get information about MTD: %s\n",
                strerror(errno));
        close(fd);
        return -errno;
    }

    if (context->flash_size == 0)
    {
        // See comment in mboxd_flash_physical.c on why
        // this is needed.
        context->flash_size = context->mtd_info.size;
    }

    // Hostboot requires a 4K block-size to be used in the FFS flash structure
    context->mtd_info.erasesize = 4096;
    context->erase_size_shift = log_2(context->mtd_info.erasesize);
    context->flash_bmap = NULL;
    context->fds[MTD_FD].fd = -1;

    close(fd);
    return rc;
}

void free_flash_dev(struct mbox_context *context)
{
    // No-op
}

int set_flash_bytemap(struct mbox_context *context, uint32_t offset,
                      uint32_t count, uint8_t val)
{
    // No-op
    return 0;
}

int erase_flash(struct mbox_context *context, uint32_t offset, uint32_t count)
{
    // No-op
    return 0;
}

/*
 * copy_flash() - Copy data from the virtual pnor into a provided buffer
 * @context:    The mbox context pointer
 * @offset:     The pnor offset to copy from (bytes)
 * @mem:        The buffer to copy into (must be of atleast 'size' bytes)
 * @size:       The number of bytes to copy
 * Return:      Number of bytes copied on success, otherwise negative error
 *              code. copy_flash will copy at most 'size' bytes, but it may
 *              copy less.
 */
int64_t copy_flash(struct mbox_context* context, uint32_t offset, void* mem,
                   uint32_t size)
{
    using namespace phosphor::logging;
    using namespace sdbusplus::xyz::openbmc_project::Common::Error;
    using namespace std::string_literals;

    int rc = size;

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
            rc = std::min(sz - offset, static_cast<size_t>(size));
            memcpy(mem, ((uint8_t*)table) + offset, rc);
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
            //copy to the reserved memory area
            auto diffOffset = offset - baseOffset;
            rc = std::min(partitionInfo->data.actual - diffOffset, size);
            memcpy(mem, (char*)mapped_mem + diffOffset , rc);
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
