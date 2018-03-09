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
        MSG_ERR("Can't open the RO partition for write");
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
        MSG_ERR("Couldn't get the partition info for offset[0x%.8x]", offset);
        log<level::ERR>("Request::getPartitionFilePath error in call to "
                        "vpnor_get_partition",
                        entry("OFFSET=%d", offset));
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
        log<level::ERR>("RORequest::getPartitionInfo error in opening "
                        "partition file",
                        entry("RC=%d", rc), entry("FILE_NAME=%s", path.c_str()),
                        entry("OFFSET=%d", offset));
        elog<InternalFailure>();
    }

    // if the offset lies in read only partition then throw error.
    if (partition->data.user.data[1] & PARTITION_READONLY)
    {
        MSG_ERR("Can't open the partition file");
        log<level::ERR>("RORequest::getPartitionInfo error offset is "
                        "in read only partition",
                        entry("FILE_NAME=%s", path.c_str()),
                        entry("OFFSET=%d", offset),
                        entry("USER_DATA=%s", partition->data.user.data[1]));
        elog<InternalFailure>();
    }

    // we don't get the file in the respective partition(RW/PSRV)
    // try to open it from RO location.

    fs::path partitionFilePath = context->paths.ro_loc;
    partitionFilePath /= partition->data.name;

    rc = Request::open(partitionFilePath, O_RDONLY);
    if (rc != ReturnCode::SUCCESS)
    {
        log<level::ERR>("RORequest::getPartitionInfo error in opening "
                        "partition file from read only location",
                        entry("RC=%d", rc),
                        entry("FILE_NAME=%s", partitionFilePath.c_str()));
        elog<InternalFailure>();
    }

    return partition;
}

const pnor_partition* RWRequest::getPartitionInfo(struct mbox_context* context,
                                                  uint32_t offset)
{
    std::string path = getPartitionFilePath(context, offset);

    ReturnCode rc = Request::open(path, O_RDWR);
    if (rc == ReturnCode::SUCCESS)
    {
        return partition;
    }
    // not interested in any other error except FILE_NOT_FOUND
    if (rc != ReturnCode::FILE_NOT_FOUND)
    {
        log<level::ERR>("RWRequest::getPartitionInfo error in opening "
                        "partition file",
                        entry("RC=%d", rc), entry("FILE_NAME=%s", path.c_str()),
                        entry("OFFSET=%d", offset));
        elog<InternalFailure>();
    }

    // if the file is not available in the respective(RW/PSRV) partition
    // then copy the file from RO to the respective(RW/PSRV) partition
    // and open it for writing.

    fs::path fromPath = context->paths.ro_loc;
    fromPath /= partition->data.name;
    if (!fs::exists(fromPath))
    {
        MSG_ERR("Couldn't find the file[%s]", fromPath.c_str());
        log<level::ERR>("RWRequest::getPartitionInfo error in opening "
                        "partition file from read only location",
                        entry("FILE_NAME=%s", fromPath.c_str()),
                        entry("OFFSET=%d", offset));
        elog<InternalFailure>();
    }
    // copy the file from ro to respective partition
    fs::path toPath = context->paths.rw_loc;

    if (partition->data.user.data[1] & PARTITION_PRESERVED)
    {
        toPath = context->paths.prsv_loc;
    }

    toPath /= partition->data.name;

    MSG_DBG("Didn't find the file in the desired partition so copying[%s]\n",
            toPath.c_str());

    if (fs::copy_file(fromPath, toPath))
    {
        MSG_DBG("File copied from[%s] to [%s]\n", fromPath.c_str(),
                toPath.c_str());
    }

    rc = Request::open(toPath.c_str(), O_RDWR);

    if (rc != ReturnCode::SUCCESS)
    {
        log<level::ERR>("RWRequest::getPartitionInfo error in opening "
                        "partition file from read write location",
                        entry("RC=%d", rc),
                        entry("FILE_NAME=%s", toPath.c_str()));
        elog<InternalFailure>();
    }

    return partition;
}

} // namespace virtual_pnor
} // namespace openpower
