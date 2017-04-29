#include "mboxd_flash_partition_intf.hpp"

namespace internal
{
    openpower::flash::partition::Table* table = nullptr;
}

int createPartition()
{
    if(!internal::table)
    {
        internal::table = new openpower::flash::partition::Table;
    }

    return 0;
}

size_t getPartitionSize()
{
    if(internal::table)
    {
        return internal::table->size();
    }

    return 0;
}

const partition_hdr* getPartitionHeader()
{
    if(internal::table)
    {
        return &(internal::table->hdr());
    }

    return nullptr;
}

const partition_entry* getAllPartitionEntries(size_t* sz)
{
    if(internal::table)
    {
        *sz = internal::table->entryList().size() * sizeof(partition_entry);
        return (internal::table->entryList()).data();
    }

    return nullptr;
}

const partition_entry* getPartitionEntry(const off_t offset)
{
    if(internal::table)
    {
        return internal::table->entry(offset);
    }

    return nullptr;
}

int removePartition()
{
    if(internal::table)
    {
        delete internal::table;
        internal::table = nullptr;

        return 0;
    }

    return -1;
}
