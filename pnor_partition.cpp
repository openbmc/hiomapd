// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2018 IBM Corp.
#include "pnor_partition.hpp"
#include "config.h"
#include "mboxd_flash.h"
#include "mboxd_pnor_partition_table.h"
#include "xyz/openbmc_project/Common/error.hpp"
#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog-errors.hpp>

#include <stdint.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "common.h"

#include <string>
#include <exception>
#include <stdexcept>
#include <iostream>

namespace openpower
{
namespace virtual_pnor
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using namespace std::string_literals;

ReturnCode Request::open(const std::string& path, int mode)
{
    if (mode == O_RDWR && partition->data.user.data[1] & PARTITION_READONLY)
    {
        MSG_ERR("Can't open RO partition '%s' for write\n", path.c_str());
        return ReturnCode::PARTITION_READ_ONLY;
    }

    fs::path partitionFilePath = path;

    if (!fs::exists(partitionFilePath))
    {
        return ReturnCode::FILE_NOT_FOUND;
    }

    auto descriptor = ::open(partitionFilePath.c_str(), mode);
    if (descriptor < 0)
    {
        return ReturnCode::FILE_OPEN_FAILURE;
    }

    fd.set(descriptor);
    descriptor = -1;

    return ReturnCode::SUCCESS;
}

std::string Request::getPartitionFilePath(struct mbox_context* context,
                                          uint32_t offset)
{
    partition = vpnor_get_partition(context, offset);
    if (!partition)
    {
        MSG_ERR("Couldn't get the partition info for offset 0x%" PRIx32 "\n",
                offset);
        elog<InternalFailure>();
    }

    fs::path partitionFilePath;

    // Check if partition exists in patch location
    partitionFilePath = context->paths.patch_loc;
    partitionFilePath /= partition->data.name;
    if (fs::is_regular_file(partitionFilePath))
    {
        return partitionFilePath.string();
    }

    switch (partition->data.user.data[1] &
            (PARTITION_PRESERVED | PARTITION_READONLY))
    {
        case PARTITION_PRESERVED:
            partitionFilePath = context->paths.prsv_loc;
            break;

        case PARTITION_READONLY:
            partitionFilePath = context->paths.ro_loc;
            break;

        default:
            partitionFilePath = context->paths.rw_loc;
    }
    partitionFilePath /= partition->data.name;
    return partitionFilePath.string();
}

const pnor_partition* RORequest::getPartitionInfo(struct mbox_context* context,
                                                  uint32_t offset)
{
    std::string path = getPartitionFilePath(context, offset);
    ReturnCode rc = Request::open(path, O_RDONLY);
    if (rc == ReturnCode::SUCCESS)
    {
        return partition;
    }
    // not interested in any other error except FILE_NOT_FOUND
    if (rc != ReturnCode::FILE_NOT_FOUND)
    {
        MSG_ERR(
            "RORequest: Error opening partition file '%s' (offset 0x%" PRIx32
            "): %u\n",
            path.c_str(), offset, static_cast<uint8_t>(rc));
        elog<InternalFailure>();
    }

    // if the offset lies in read only partition then throw error.
    if (partition->data.user.data[1] & PARTITION_READONLY)
    {
        MSG_ERR("RORequest: Requested offset 0x%" PRIx32
                " is in a read-only partition (%s)\n",
                offset, path.c_str());
        elog<InternalFailure>();
    }

    // we don't get the file in the respective partition(RW/PSRV)
    // try to open it from RO location.

    fs::path partitionFilePath = context->paths.ro_loc;
    partitionFilePath /= partition->data.name;

    rc = Request::open(partitionFilePath, O_RDONLY);
    if (rc != ReturnCode::SUCCESS)
    {
        MSG_ERR("RORequest: Failed to open partition file '%s' at RO fallback "
                "(offset 0x%" PRIx32 "): %u\n",
                partitionFilePath.c_str(), offset, static_cast<uint8_t>(rc));
        elog<InternalFailure>();
    }

    return partition;
}

const pnor_partition* RWRequest::getPartitionInfo(struct mbox_context* context,
                                                  uint32_t offset)
{
    std::string path = getPartitionFilePath(context, offset);
    std::error_code ec;

    ReturnCode rc = Request::open(path, O_RDWR);
    if (rc == ReturnCode::SUCCESS)
    {
        return partition;
    }
    // not interested in any other error except FILE_NOT_FOUND
    if (rc != ReturnCode::FILE_NOT_FOUND)
    {
        MSG_ERR(
            "RWRequest: Error opening partition file '%s' (offset 0x%" PRIx32
            "): %d\n",
            path.c_str(), offset, static_cast<uint8_t>(rc));
        elog<InternalFailure>();
    }

    // if the file is not available in the respective(RW/PSRV) partition
    // then copy the file from RO to the respective(RW/PSRV) partition
    // and open it for writing.

    fs::path fromPath = context->paths.ro_loc;
    fromPath /= partition->data.name;
    if (!fs::exists(fromPath))
    {
        MSG_ERR("RWRequest: Partition '%s' for offset 0x%" PRIx32
                " not found in RO directory '%s'\n",
                partition->data.name, offset, context->paths.ro_loc);
        elog<InternalFailure>();
    }
    // copy the file from ro to respective partition
    fs::path toPath = context->paths.rw_loc;

    if (partition->data.user.data[1] & PARTITION_PRESERVED)
    {
        toPath = context->paths.prsv_loc;
    }

    MSG_DBG("RWRequest: Didn't find '%s' under '%s', copying from '%s'\n",
            partition->data.name, toPath.c_str(), fromPath.c_str());

    toPath /= partition->data.name;
    if (!fs::copy_file(fromPath, toPath, ec))
    {
        MSG_ERR("RWRequest: Failed to copy file from '%s' to '%s': %d\n",
                fromPath.c_str(), toPath.c_str(), ec.value());
        elog<InternalFailure>();
    }

    rc = Request::open(toPath.c_str(), O_RDWR);

    if (rc != ReturnCode::SUCCESS)
    {
        MSG_ERR("RWRequest: Failed to open file at '%s': %d\n", toPath.c_str(),
                static_cast<uint8_t>(rc));
        elog<InternalFailure>();
    }

    return partition;
}

} // namespace virtual_pnor
} // namespace openpower
