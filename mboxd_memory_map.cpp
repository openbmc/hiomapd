extern "C"
{
#include "common.h"
}

#include "config.h"
#include "flash_partition.h"

#include <endian.h>
#include <errno.h>
#include <string.h>

#include "mboxd_flash_partition_intf.hpp"
#include "mboxd_memory_map.hpp"

namespace openpower
{
namespace flash
{

MemoryMap::~MemoryMap()
{
    for (const auto entry : mappedMemorySet)
    {
        if (entry.second.bmcMappedMemory)
        {
            munmap(entry.second.bmcMappedMemory, entry.second.size);
        }
        if (entry.second.fd)
        {
            close(entry.second.fd);
        }
    }
}

MemInfo MemoryMap::getMappedMemory(uint32_t offset)
{
    MemInfo info;
    for (const auto entry : mappedMemorySet)
    {
        auto baseOffset = entry.first;
        auto lastOffset = entry.first + entry.second.size;
        if (offset >= baseOffset && offset < lastOffset)
        {
            // We keep the base offset of any partition
            // so adjust the offset.
            // add the diff of base offset and the requested offset
            // into the bmc mapped memory.

            info.bmcMappedMemory = entry.second.bmcMappedMemory +
                                   (offset - baseOffset);

            info.size = entry.second.size -
                        (offset - baseOffset);

            return info;
        }
    }

    // didn't get the offset in the existed set then need to load the
    // file ino memory.

    auto memInfo = loadFileIntoMemory(offset);
    if (memInfo.second.fd)
    {
        memInfo.second.bmcMappedMemory = memInfo.second.bmcMappedMemory +
                                         (offset - memInfo.first);

        memInfo.second.size =  memInfo.second.size - (offset - memInfo.first);
    }
    return  memInfo.second;

}

std::pair<uint32_t, MemInfo> MemoryMap::loadFileIntoMemory(uint32_t offset)
{
    MemInfo info;

    auto partition = getPartitionEntry(offset);

    // TODO: We would need it now as currently the data is
    // in BE format,will remove once it is fixed in the previous commit.

    auto base = be32toh(partition->base);
    auto size = be32toh(partition->size);
    auto actual = be32toh(partition->actual);

    if (!partition)
    {
        std::string msg = "Couldn't get the partition info for offset " + offset;
        throw std::runtime_error(msg);
    }
    std::string partitionFile = std::string(PARTITION_FILES_LOC) + "/" +
                                partition->name;

    auto fd = open(partitionFile.c_str(), O_RDONLY);
    if (fd == -1)
    {
        throw std::runtime_error("Couldn't open the partition file");
    }
    auto mem = mmap(NULL,
                    actual,
                    PROT_READ, MAP_PRIVATE, fd, 0);

    if (mem == MAP_FAILED)
    {
        std::string msg = "Failed to map" + partitionFile + ":" + strerror(errno);
        close(fd);
        throw std::runtime_error(msg);
    }

    info.fd = fd;
    info.bmcMappedMemory = mem;
    info.size = actual;

    base = base << shift;

    mappedMemorySet.emplace(base, info);

    return std::pair<uint32_t, MemInfo>(base, info);
}

void MemoryMap::unloadFileFromMemory(uint32_t offset)
{
    for (const auto entry : mappedMemorySet)
    {
        auto baseAddr = entry.first;
        auto lastAddr = entry.first + entry.second.size;

        if (offset >= baseAddr && offset < lastAddr)
        {
            if (entry.second.bmcMappedMemory)
            {
                munmap(entry.second.bmcMappedMemory, entry.second.size);
            }
            if (entry.second.fd)
            {
                close(entry.second.fd);
            }
            mappedMemorySet.erase(offset);
        }
    }

}
}//namespace flash
}//namespace openpower
