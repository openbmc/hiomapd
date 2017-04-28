#include "pnor_partition_table.hpp"
#include "endian.hpp"
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
namespace details
{

uint32_t checksum(const void* data, size_t size)
{
    uint32_t checksum = 0;

    for (size_t i = 0; i < (size / sizeof(uint32_t)); ++i)
    {
        checksum ^= (static_cast<const uint32_t*>(data))[i];
    }

    return checksum;
}

} // namespace details

namespace partition
{
namespace block
{

// The PNOR erase-block size is 4 KB (1 << 12)
constexpr size_t shift = 12;
constexpr size_t size = 1 << shift;

} // namespace block

Table::Table():
    Table(fs::path(PARTITION_FILES_LOC))
{
}

Table::Table(fs::path&& directory):
    szBlocks(0),
    imgBlocks(0),
    tbl(nullptr),
    directory(std::move(directory)),
    numParts(0)
{
    preparePartitions();
    prepareHeader();
}

Table::~Table()
{
    std::free(tbl);
    tbl = nullptr;
}

void Table::prepareHeader()
{
    tbl->magic = PARTITION_HEADER_MAGIC;
    tbl->version = PARTITION_VERSION_1;
    tbl->size = szBlocks;
    tbl->entry_size = sizeof(pnor_partition);
    tbl->entry_count = numParts;
    tbl->block_size = block::size;
    tbl->block_count = imgBlocks;
    tbl->checksum = details::checksum(tbl,
                                      sizeof(pnor_partition_table) -
                                      sizeof(tbl->checksum));
}

inline void Table::allocateMemory(const fs::path& tocFile)
{
    size_t num = 0;
    std::string line;
    std::ifstream file(tocFile.c_str());

    // Find number of lines in partition file - this will help
    // determine the number of partitions and hence also how much
    // memory to allocate for the partitions array.
    // The actual number of partitions may turn out to be lesser than this,
    // in case of errors.
    while (std::getline(file, line))
    {
        // Check if line starts with "partition"
        if (std::string::npos != line.find("partition", 0))
        {
            ++num;
        }
    }

    size_t totalSizeBytes = sizeof(pnor_partition_table) +
                            (num * sizeof(pnor_partition));
    size_t totalSizeAligned = align_up(totalSizeBytes, block::size);
    szBlocks = totalSizeAligned >> block::shift;
    imgBlocks = szBlocks;
    tbl = static_cast<pnor_partition_table*>(std::malloc(totalSizeAligned));
    if (!tbl)
    {
        std::cerr << "Out of memory";
        std::exit(EXIT_FAILURE);
    }
    std::memset(tbl, 0, totalSizeAligned);
}

inline void Table::writeSizes(pnor_partition& part, const size_t size)
{
    part.base = imgBlocks;
    size_t sizeInBlocks = align_up(size, block::size) >> block::shift;
    imgBlocks += sizeInBlocks;
    part.size = sizeInBlocks;
    part.actual = size;
}

inline void Table::writeUserdata(pnor_partition& part, const std::string& data)
{
    if (std::string::npos != data.find("ECC"))
    {
        part.user.data[0] = PARTITION_ECC_PROTECTED;
    }
    auto perms = 0;
    if (std::string::npos != data.find("READONLY"))
    {
        perms |= PARTITION_READONLY;
    }
    if (std::string::npos != data.find("PRESERVED"))
    {
        perms |= PARTITION_PRESERVED;
    }
    part.user.data[1] = perms;
}

inline void Table::writeDefaults(pnor_partition& part)
{
    part.pid = PARENT_PATITION_ID;
    part.type = PARTITION_TYPE_DATA;
    part.flags = 0; // flags unused
}

inline void Table::writeNameAndId(pnor_partition& part, const std::string& name,
                                  const std::string& id)
{
    strncpy(part.name,
            name.c_str(),
            min_u32(name.length(), PARTITION_NAME_MAX));
    part.id = std::stoul(id);
}

void Table::preparePartitions()
{
    fs::path tocFile = directory;
    tocFile /= PARTITION_TOC_FILE;
    allocateMemory(tocFile);

    std::ifstream file(tocFile.c_str());
    static constexpr auto ID_MATCH = 1;
    static constexpr auto NAME_MATCH = 2;
    // Parse PNOR toc (table of contents) file, which has lines like :
    // partition01=HBB,00010000,000a0000,ECC,PRESERVED, to indicate partitions
    std::regex regex
    {
        "^partition([0-9]+)=([A-Za-z0-9_]+),"
        "([0-9a-fA-F]+),([0-9a-fA-F]+)",
        std::regex::extended
    };
    std::smatch match;
    std::string line;

    while (std::getline(file, line))
    {
        if (std::regex_search(line, match, regex))
        {
            fs::path partitionFile = directory;
            partitionFile /= match[NAME_MATCH].str();
            struct stat results;
            // Get size of partition file
            if (-1 == stat(partitionFile.c_str(), &results))
            {
                MSG_ERR("stat() failed on %s", partitionFile.c_str());
                continue;
            }

            tbl->partitions[numParts] = {};
            writeNameAndId(tbl->partitions[numParts], match[NAME_MATCH].str(),
                           match[ID_MATCH].str());
            writeDefaults(tbl->partitions[numParts]);
            writeSizes(tbl->partitions[numParts], results.st_size);
            writeUserdata(tbl->partitions[numParts], match.suffix().str());
            tbl->partitions[numParts].checksum =
                details::checksum(
                    &(tbl->partitions[numParts]),
                    sizeof(pnor_partition) -
                    sizeof(tbl->partitions[numParts].checksum));

            ++numParts;
        }
    }
}

const pnor_partition* Table::partition(const off_t offset) const
{
    const pnor_partition* p = nullptr;
    auto offt = offset >> block::shift;

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

} // namespace partition

pnor_partition_table*  endianFixup(const pnor_partition_table& tbl)
{
    size_t size = tbl.size << partition::block::shift;
    pnor_partition_table* table =
        static_cast<pnor_partition_table*>(std::malloc(size));
    if (!table)
    {
        std::cerr << "Out of memory";
        std::exit(EXIT_FAILURE);
    }
    std::memcpy(table, &tbl, size);

    table->magic = endian::toVpnor(table->magic);
    table->version = endian::toVpnor(table->version);
    table->size = endian::toVpnor(table->size);
    table->entry_size = endian::toVpnor(table->entry_size);
    table->entry_count = endian::toVpnor(table->entry_count);
    table->block_size = endian::toVpnor(table->block_size);
    table->block_count = endian::toVpnor(table->block_count);
    table->checksum = endian::toVpnor(table->checksum);

    for (auto i = 0; i < tbl.entry_count; ++i)
    {
        table->partitions[i].base = endian::toVpnor(table->partitions[i].base);
        table->partitions[i].size = endian::toVpnor(table->partitions[i].size);
        table->partitions[i].pid = endian::toVpnor(table->partitions[i].pid);
        table->partitions[i].id = endian::toVpnor(table->partitions[i].id);
        table->partitions[i].type = endian::toVpnor(table->partitions[i].type);
        table->partitions[i].flags =
            endian::toVpnor(table->partitions[i].flags);
        table->partitions[i].actual =
            endian::toVpnor(table->partitions[i].actual);
        for (auto j = 0; j < PARTITION_USER_WORDS; ++j)
        {
            table->partitions[i].user.data[j] =
                endian::toVpnor(table->partitions[i].user.data[j]);
        }
        table->partitions[i].checksum =
            endian::toVpnor(table->partitions[i].checksum);
    }

    return table;
}

} // namespace virtual_pnor
} // namespace openpower
