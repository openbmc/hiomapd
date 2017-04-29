#include "mboxd_flash_partition_intf.hpp"
#include "mboxd_flash_partition.hpp"

struct vpnor_partition_table
{
    openpower::virtual_pnor::partition::Table* table = nullptr;
};

void vpnor_create_partition_table(struct mbox_context *context)
{
    if (context)
    {
        if (!context->table)
        {
            context->table = new vpnor_partition_table;
	    context->table->table =
                new openpower::virtual_pnor::partition::Table;
        }
    }
}

size_t vpnor_get_partition_table_size(const struct mbox_context *context)
{
    return context && context->table ? context->table->table->size() : 0;
}

const struct pnor_partition_table* vpnor_get_partition_table(
                                       const struct mbox_context *context)
{
    return context && context->table ? context->table->table->table() :
                                       nullptr;
}

const struct pnor_partition* vpnor_get_partition(
                                const struct mbox_context *context,
                                const off_t offset)
{
    return context && context->table ?
        context->table->table->partition(offset) : nullptr;
}

void vpnor_destroy_partition_table(struct mbox_context *context)
{
    if(context && context->table)
    {
        delete context->table->table;
        delete context->table;
        context->table = nullptr;
    }
}
