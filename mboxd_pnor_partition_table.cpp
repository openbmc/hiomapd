#include "mboxd_pnor_partition_table.h"
#include "common.h"
#include "mbox.h"
#include "mboxd_flash.h"
#include "pnor_partition_table.hpp"
#include "config.h"
#include <experimental/filesystem>

struct vpnor_partition_table
{
    openpower::virtual_pnor::partition::Table* table = nullptr;
};

void init_vpnor(struct mbox_context *context)
{
    if (context && !context->vpnor)
    {
        strcpy(context->paths.ro_loc, PARTITION_FILES_RO_LOC);
        strcpy(context->paths.rw_loc, PARTITION_FILES_RW_LOC);
        strcpy(context->paths.prsv_loc, PARTITION_FILES_PRSV_LOC);
        strcpy(context->paths.patch_loc, PARTITION_FILES_PATCH_LOC);

        context->vpnor = new vpnor_partition_table;
        context->vpnor->table =
            new openpower::virtual_pnor::partition::Table(
                    1 << context->erase_size_shift,
                    context->flash_size);
    }
}

void vpnor_create_partition_table_from_path(struct mbox_context *context,
                                            const char *path)
{
    std::experimental::filesystem::path dir(path);

    if (context && !context->vpnor)
    {
        context->vpnor = new vpnor_partition_table;
        context->vpnor->table =
            new openpower::virtual_pnor::partition::Table(
                    std::move(dir),
                    1 << context->erase_size_shift,
                    context->flash_size);
    }
}

size_t vpnor_get_partition_table_size(const struct mbox_context *context)
{
    return context && context->vpnor ?
        context->vpnor->table->size() : 0;
}

const struct pnor_partition_table* vpnor_get_partition_table(
                                       const struct mbox_context *context)
{
    return context && context->vpnor ?
        &(context->vpnor->table->getHostTable()) : nullptr;
}

const struct pnor_partition* vpnor_get_partition(
                                 const struct mbox_context *context,
                                 const size_t offset)
{
    return context && context->vpnor ?
        &(context->vpnor->table->partition(offset)) : nullptr;
}

void vpnor_copy_bootloader_partition(const struct mbox_context *context)
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

    openpower::virtual_pnor::partition::Table blTable(eraseSize, pnorSize);
    vpnor_partition_table vtbl{};
    vtbl.table = &blTable;
    struct mbox_context local{};
    local.vpnor = &vtbl;
    local.block_size_shift = log_2(eraseSize);
    memcpy(&local.paths, &context->paths, sizeof(local.paths));

    size_t tocOffset = 0;
    uint32_t tocSize = blTable.size() * eraseSize;
    // Copy TOC
    copy_flash(&local, tocOffset,
               static_cast<uint8_t*>(context->mem) + tocStart,
               tocSize);
    const pnor_partition& partition = blTable.partition(blPartitionName);
    size_t hbbOffset = partition.data.base * eraseSize;
    uint32_t hbbSize = partition.data.actual;
    // Copy HBB
    copy_flash(&local, hbbOffset,
               static_cast<uint8_t*>(context->mem) + hbbOffset, hbbSize);
}

void destroy_vpnor(struct mbox_context *context)
{
    if(context && context->vpnor)
    {
        delete context->vpnor->table;
        delete context->vpnor;
        context->vpnor = nullptr;
    }
}
