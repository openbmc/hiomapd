#include "mboxd_flash_partition.hpp"
#include "common.h"
#include "config.h"
#include <syslog.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <regex>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <iostream>

namespace openpower
{
namespace virtual_pnor
{
namespace partition
{
namespace block
{

// The PNOR erase-block size is 4 KB (1 << 12)
constexpr size_t shift = 12;
constexpr size_t size = 1 << shift;

};

namespace details
{

uint32_t checksum(const void* data, size_t size)
{
    uint32_t checksum = 0;

    for (size_t i = 0; i < (size / sizeof(uint32_t)); ++i)
    {
        checksum ^= (static_cast<const uint32_t*>(data))[i];
    }
    checksum = htobe32(checksum);

    return checksum;
}

}

Table::Table():
    Table(fs::path(PARTITION_FILES_LOC))
{
}

Table::Table(fs::path&& directory):
    // partition table is at least 1 block
    sz(block::size >> block::shift),
    // At least one block on the PNOR
    blocks(block::size >> block::shift),
    tbl(nullptr),
    directory(std::move(directory)),
    numParts(0)
{
    preparePartitions();
    align();
    prepareHeader();
}

Table::~Table()
{
    if(tbl)
    {
        std::free(tbl);
        tbl = nullptr;
    }
}

void Table::align()
{
    // Align partition table size to block boundary
    sz = (align_up((numParts * sizeof(pnor_partition)),
                    block::size)) >> block::shift;

    // If partition table is larger than a block, fixup size and partition start
    // offsets.
    if (sz > block::size)
    {
        off_t diff = sz - block::size;
        blocks += diff;
        std::for_each(
            &(tbl->partitions[0]),
            &(tbl->partitions[numParts]),
            [&](pnor_partition& p){ p.base += diff; });
    }
}

void Table::prepareHeader()
{
    tbl->magic = htobe32(PARTITION_HEADER_MAGIC);
    tbl->version = htobe32(PARTITION_VERSION_1);
    tbl->size = htobe32(sz);
    tbl->entry_size = htobe32(sizeof(pnor_partition));
    tbl->entry_count = htobe32(numParts);
    tbl->block_size = htobe32(block::size);
    tbl->block_count = htobe32(blocks);
    tbl->checksum = details::checksum(tbl,
                                      sizeof(pnor_partition_table) -
                                      sizeof(tbl->checksum));
}

void Table::preparePartitions()
{
    // Parse PNOR toc (table of contents) file, which has lines like :
    // partition01=HBB,00010000,000a0000,ECC,PRESERVED
    std::string line;

    fs::path tocFile = directory;
    tocFile /= PARTITION_TOC_FILE;
    std::ifstream file(tocFile.c_str());

    // Find number of lines in partition file - this will help
    // determine the number of partitions and hence also how much
    // memory to allocate for the partitions array.
    // The actual number of partitions may turn out to be lesser than this,
    // in case of errors.
    while (std::getline(file, line))
    {
        ++numParts;
    }

    size_t partitionSize = numParts * sizeof(pnor_partition);
    tbl = static_cast<pnor_partition_table*>(
              std::malloc(sizeof(pnor_partition_table) + partitionSize));
    if (!tbl)
    {
        std::cerr << "Out of memory";
        std::exit(EXIT_FAILURE);
    }
    std::memset(tbl, 0, sizeof(pnor_partition_table) + partitionSize);

    numParts = 0;
    file.clear();
    file.seekg(0, file.beg);
    std::regex regex
    {
        "^partition([0-9]+)=([A-Za-z0-9_]+),"
        "([0-9a-fA-F]+),([0-9a-fA-F]+)",
        std::regex::extended
    };
    std::smatch match;

    while (std::getline(file, line))
    {
        if (std::regex_search(line, match, regex))
        {
            fs::path partitionFile = directory;
            partitionFile /= match[2].str();
            pnor_partition partition{};

            struct stat results;
            // Get size of partition file
            if (-1 == stat(partitionFile.c_str(), &results))
            {
                MSG_ERR("stat() failed on %s", partitionFile.c_str());
                continue;
            }

            auto name = match[2].str();
            strncpy(partition.name,
                    name.c_str(),
                    min_u32(name.length(), PARTITION_NAME_MAX));

            partition.base = htobe32(blocks);
            size_t sizeInBlocks = align_up(results.st_size, block::size) >>
                                  block::shift;
            blocks += sizeInBlocks;
            partition.size = htobe32(sizeInBlocks);
            partition.actual = htobe32(results.st_size);

            auto id = std::stoul(match[1].str());
            partition.id = htobe32(id);
            partition.pid = htobe32(PARENT_PATITION_ID);
            partition.type = htobe32(PARTITION_TYPE_DATA);
            partition.flags = 0; // flags unused

            auto userdata = match.suffix().str();
            if (std::string::npos != userdata.find("ECC"))
            {
                partition.user.data[0] = htobe32(PARTITION_ECC_PROTECTED);
            }
            auto data = 0;
            if (std::string::npos != userdata.find("READONLY"))
            {
                data |= PARTITION_READONLY;
            }
            if (std::string::npos != userdata.find("PRESERVED"))
            {
                data |= PARTITION_PRESERVED;
            }
            partition.user.data[1] = htobe32(data);

            partition.checksum = details::checksum(
                                               &partition,
                                               sizeof(pnor_partition) -
                                               sizeof(partition.checksum));

            tbl->partitions[numParts] = partition;
            ++numParts;
        }
    }
}

const pnor_partition* Table::partition(const off_t offset) const
{
    const pnor_partition* p = nullptr;
    auto offt = htobe32(offset >> block::shift);

    for (auto i = 0; i < numParts; ++i)
    {
        if ((offt >= tbl->partitions[i].base) &&
            (offt < (tbl->partitions[i].base + tbl->partitions[i].size)))
        {
            p = &(tbl->partitions[i]);
            break;
        }
    }

    return p;
}

}
}
}
