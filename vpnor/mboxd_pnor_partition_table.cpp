// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2018 IBM Corp.
#include "config.h"

#include <assert.h>

extern "C" {
#include "backend.h"
}

#include "pnor_partition_table.hpp"
#include "xyz/openbmc_project/Common/error.hpp"

#include <experimental/filesystem>
#include <phosphor-logging/elog-errors.hpp>

#include "common.h"
#include "mboxd.h"
#include "mboxd_pnor_partition_table.h"

void vpnor_default_paths(vpnor_partition_paths* paths)
{
    strncpy(paths->ro_loc, PARTITION_FILES_RO_LOC, PATH_MAX);
    paths->ro_loc[PATH_MAX - 1] = '\0';
    strncpy(paths->rw_loc, PARTITION_FILES_RW_LOC, PATH_MAX);
    paths->rw_loc[PATH_MAX - 1] = '\0';
    strncpy(paths->prsv_loc, PARTITION_FILES_PRSV_LOC, PATH_MAX);
    paths->prsv_loc[PATH_MAX - 1] = '\0';
    strncpy(paths->patch_loc, PARTITION_FILES_PATCH_LOC, PATH_MAX);
    paths->prsv_loc[PATH_MAX - 1] = '\0';
}

int vpnor_init(struct backend* backend, const vpnor_partition_paths* paths)
{
    namespace err = sdbusplus::xyz::openbmc_project::Common::Error;
    namespace fs = std::experimental::filesystem;
    namespace vpnor = openpower::virtual_pnor;

    if (!(backend && paths))
        return -EINVAL;

    vpnor_data* priv = new vpnor_data;
    assert(priv);

    priv->paths = *paths;
    backend->priv = priv;

    try
    {
        priv->vpnor = new vpnor_partition_table;
        priv->vpnor->table =
            new openpower::virtual_pnor::partition::Table(backend);
    }
    catch (vpnor::TocEntryError& e)
    {
        MSG_ERR("%s\n", e.what());
        try
        {
            phosphor::logging::commit<err::InternalFailure>();
        }
        catch (const std::exception& e)
        {
            MSG_ERR("Failed to commit InternalFailure: %s\n", e.what());
        }
        return -EINVAL;
    }

    return 0;
}

int vpnor_copy_bootloader_partition(const struct backend* backend, void* buf,
                                    uint32_t count)
{
    // The hostboot bootloader has certain size/offset assumptions, so
    // we need a special partition table here.
    // It assumes the PNOR is 64M, the TOC size is 32K, the erase block is
    // 4K, the page size is 4K.
    // It also assumes the TOC is at the 'end of pnor - toc size - 1 page size'
    // offset, and first looks for the TOC here, before proceeding to move up
    // page by page looking for the TOC. So it is optimal to place the TOC at
    // this offset.
    constexpr size_t eraseSize = 0x1000;
    constexpr size_t pageSize = 0x1000;
    constexpr size_t pnorSize = 0x4000000;
    constexpr size_t tocMaxSize = 0x8000;
    constexpr size_t tocStart = pnorSize - tocMaxSize - pageSize;
    constexpr auto blPartitionName = "HBB";

    namespace err = sdbusplus::xyz::openbmc_project::Common::Error;
    namespace fs = std::experimental::filesystem;
    namespace vpnor = openpower::virtual_pnor;

    try
    {
        vpnor_partition_table vtbl{};
        struct vpnor_data priv;
        struct backend local = *backend;

        priv.vpnor = &vtbl;
        priv.paths = ((struct vpnor_data*)backend->priv)->paths;
        local.priv = &priv;
        local.block_size_shift = log_2(eraseSize);

        openpower::virtual_pnor::partition::Table blTable(&local);

        vtbl.table = &blTable;

        size_t tocOffset = 0;

        const pnor_partition& partition = blTable.partition(blPartitionName);
        size_t hbbOffset = partition.data.base * eraseSize;
        uint32_t hbbSize = partition.data.actual;

        if (count < tocStart + blTable.capacity() ||
            count < hbbOffset + hbbSize)
        {
            MSG_ERR("Reserved memory too small for dumb bootstrap\n");
            return -EINVAL;
        }

        uint8_t* buf8 = static_cast<uint8_t*>(buf);
        backend_copy(&local, tocOffset, buf8 + tocStart, blTable.capacity());
        backend_copy(&local, hbbOffset, buf8 + hbbOffset, hbbSize);
    }
    catch (err::InternalFailure& e)
    {
        phosphor::logging::commit<err::InternalFailure>();
        return -EIO;
    }
    catch (vpnor::ReasonedError& e)
    {
        MSG_ERR("%s\n", e.what());
        phosphor::logging::commit<err::InternalFailure>();
        return -EIO;
    }

    return 0;
}

void vpnor_destroy(struct backend* backend)
{
    struct vpnor_data* priv = (struct vpnor_data*)backend->priv;

    if (priv)
    {
        if (priv->vpnor)
        {
            delete priv->vpnor->table;
        }
        delete priv->vpnor;
    }
    delete priv;
}
