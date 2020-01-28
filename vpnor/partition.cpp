// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2018 IBM Corp.
extern "C" {
#include "mboxd.h"
}

#include "config.h"

#include "vpnor/partition.hpp"
#include "vpnor/table.hpp"
#include "xyz/openbmc_project/Common/error.hpp"

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include <exception>
#include <iostream>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <stdexcept>
#include <string>

#include "common.h"
#include "vpnor/backend.h"

namespace openpower
{
namespace virtual_pnor
{

namespace fs = std::experimental::filesystem;

fs::path Request::getPartitionFilePath(int flags)
{
    struct vpnor_data* priv = (struct vpnor_data*)backend->priv;

    // Check if partition exists in patch location
    auto dst = fs::path(priv->paths.patch_loc) / partition.data.name;
    if (fs::is_regular_file(dst))
    {
        return dst;
    }

    switch (partition.data.user.data[1] &
            (PARTITION_PRESERVED | PARTITION_READONLY))
    {
        case PARTITION_PRESERVED:
            dst = priv->paths.prsv_loc;
            break;

        case PARTITION_READONLY:
            dst = priv->paths.ro_loc;
            break;

        default:
            dst = priv->paths.rw_loc;
    }
    dst /= partition.data.name;

    if (fs::exists(dst))
    {
        return dst;
    }

    if (flags == O_RDONLY)
    {
        dst = fs::path(priv->paths.ro_loc) / partition.data.name;
        assert(fs::exists(dst));
        return dst;
    }

    assert(flags == O_RDWR);
    auto src = fs::path(priv->paths.ro_loc) / partition.data.name;
    assert(fs::exists(src));

    MSG_DBG("RWRequest: Didn't find '%s' under '%s', copying from '%s'\n",
            partition.data.name, dst.c_str(), src.c_str());

    dst = priv->paths.rw_loc;
    if (partition.data.user.data[1] & PARTITION_PRESERVED)
    {
        dst = priv->paths.prsv_loc;
    }

    dst /= partition.data.name;
    fs::copy_file(src, dst);
    fs::permissions(dst, fs::perms::add_perms | fs::perms::owner_write);

    return dst;
}

size_t Request::clamp(size_t len)
{
    size_t maxAccess = offset + len;
    size_t partSize = partition.data.size << backend->block_size_shift;
    return std::min(maxAccess, partSize) - offset;
}

/* Post-condition: All bytes written or an error has occurred */
#define request_access_all(fn, dst, src, len) \
({ \
    size_t __len = len; \
    ssize_t wrote; \
    while (__len) { \
        wrote = TEMP_FAILURE_RETRY(fn(dst, src, __len)); \
        if (wrote < 0) \
            break; \
        __len -= wrote; \
    } \
    __len ? -1 : 0; \
})

ssize_t Request::read(void* dst, size_t len)
{
        len = clamp(len);

        fs::path path = getPartitionFilePath(O_RDONLY);

        MSG_INFO("Fulfilling read request against %s at offset 0x%zx into %p "
                 "for %zu\n",
                 path.c_str(), offset, dst, len);

        size_t fileSize = fs::file_size(path);

        int fd = ::open(path.c_str(), O_RDONLY);
        if (fd == -1)
        {
            MSG_ERR("Failed to open backing file at '%s': %d\n", path.c_str(),
                    errno);
            throw std::system_error(errno, std::system_category());
        }

        int rc = lseek(fd, offset, SEEK_SET);
        if (rc < 0) {
            throw std::system_error(errno, std::system_category());
        }

        auto access_len = std::min(len, fileSize);
        rc = request_access_all(::read, fd, dst, access_len);
        if (rc < 0) {
            throw std::system_error(errno, std::system_category());
        }
        memset((char *)dst + access_len, 0xff, len - access_len);

        close(fd);

        return len;
}

ssize_t Request::write(void* dst, size_t len)
{
        if (len != clamp(len))
        {
            std::stringstream err;
            err << "Request size 0x" << std::hex << len << " from offset 0x"
                << std::hex << offset << " exceeds the partition size 0x"
                << std::hex
                << (partition.data.size << backend->block_size_shift);
            throw OutOfBoundsOffset(err.str());
        }

        /* Ensure file is at least the size of the maximum access */
        fs::path path = getPartitionFilePath(O_RDWR);

        MSG_INFO("Fulfilling write request against %s at offset 0x%zx from %p "
                 "for %zu\n",
                 path.c_str(), offset, dst, len);

        int fd = ::open(path.c_str(), O_RDWR);
        if (fd == -1)
        {
            MSG_ERR("Failed to open backing file at '%s': %d\n", path.c_str(),
                    errno);
            throw std::system_error(errno, std::system_category());
        }

        int rc = lseek(fd, offset, SEEK_SET);
        if (rc < 0) {
            throw std::system_error(errno, std::system_category());
        }

        rc = request_access_all(::write, fd, dst, len);
        if (rc < 0) {
            throw std::system_error(errno, std::system_category());
        }
        backend_set_bytemap(backend, base + offset, len, FLASH_DIRTY);

        close(fd);

        return len;
}

} // namespace virtual_pnor
} // namespace openpower
