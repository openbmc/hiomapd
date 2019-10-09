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

void Request::resize(const fs::path& path, size_t len)
{
    size_t maxAccess = offset + len;
    size_t fileSize = fs::file_size(path);
    if (maxAccess < fileSize)
    {
        return;
    }
    MSG_DBG("Resizing %s to %zu bytes\n", path.c_str(), maxAccess);
    int rc = truncate(path.c_str(), maxAccess);
    if (rc == -1)
    {
        MSG_ERR("Failed to resize %s: %d\n", path.c_str(), errno);
        throw std::system_error(errno, std::system_category());
    }
}

size_t Request::fulfil(const fs::path& path, int flags, void* buf, size_t len)
{
    if (!(flags == O_RDONLY || flags == O_RDWR))
    {
        std::stringstream err;
        err << "Require O_RDONLY (0x" << std::hex << O_RDONLY << " or O_RDWR "
            << std::hex << O_RDWR << " for flags, got: 0x" << std::hex << flags;
        throw std::invalid_argument(err.str());
    }

    int fd = ::open(path.c_str(), flags);
    if (fd == -1)
    {
        MSG_ERR("Failed to open backing file at '%s': %d\n", path.c_str(),
                errno);
        throw std::system_error(errno, std::system_category());
    }

    if (flags == O_RDONLY)
    {
        MSG_INFO("Fulfilling read request against %s at offset 0x%zx into %p "
                 "for %zu\n",
                 path.c_str(), offset, buf, len);
    }
    else
    {
        MSG_INFO("Fulfilling write request against %s at offset 0x%zx from %p "
                 "for %zu\n",
                 path.c_str(), offset, buf, len);
    }

    size_t fileSize = fs::file_size(path);
    int mprot = PROT_READ | ((flags == O_RDWR) ? PROT_WRITE : 0);
    auto map = mmap(NULL, fileSize, mprot, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED)
    {
        close(fd);
        MSG_ERR("Failed to map backing file '%s' for %zd bytes: %d\n",
                path.c_str(), fileSize, errno);
        throw std::system_error(errno, std::system_category());
    }

    // copy to the reserved memory area
    if (flags == O_RDONLY)
    {
        memset(buf, 0xff, len);
        memcpy(buf, (char*)map + offset, std::min(len, fileSize));
    }
    else
    {
        memcpy((char*)map + offset, buf, len);
        backend_set_bytemap(backend, base + offset, len, FLASH_DIRTY);
    }
    munmap(map, fileSize);
    close(fd);

    return len;
}

} // namespace virtual_pnor
} // namespace openpower
