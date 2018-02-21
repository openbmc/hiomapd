#include "pnor_partition_table.hpp"
#include "common.h"
#include "config.h"
#include "xyz/openbmc_project/Common/error.hpp"
#include <phosphor-logging/elog-errors.hpp>
#include <syslog.h>
#include <endian.h>
#include <regex>
#include <fstream>
#include <algorithm>

namespace openpower
{
namespace virtual_pnor
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

namespace partition
{

Table::Table(size_t blockSize, size_t pnorSize) :
    Table(fs::path(PARTITION_FILES_RO_LOC), blockSize, pnorSize)
{
}

Table::Table(fs::path&& directory, size_t blockSize, size_t pnorSize) :
    szBlocks(0), directory(std::move(directory)), numParts(0),
    blockSize(blockSize), pnorSize(pnorSize)
{
    preparePartitions();
    prepareHeader();
    hostTbl = endianFixup(tbl);
}

void Table::prepareHeader()
{
    decltype(auto) table = getNativeTable();
    table.data.magic = PARTITION_HEADER_MAGIC;
    table.data.version = PARTITION_VERSION_1;
    table.data.size = szBlocks;
    table.data.entry_size = sizeof(pnor_partition);
    table.data.entry_count = numParts;
    table.data.block_size = blockSize;
    table.data.block_count = pnorSize / blockSize;
    table.checksum = details::checksum(table.data);
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

    size_t totalSizeBytes =
        sizeof(pnor_partition_table) + (num * sizeof(pnor_partition));
    size_t totalSizeAligned = align_up(totalSizeBytes, blockSize);
    szBlocks = totalSizeAligned / blockSize;
    tbl.resize(totalSizeAligned);
}

inline void Table::writeSizes(pnor_partition& part, size_t start, size_t end)
{
    size_t size = end - start;
    part.data.base = align_up(start, blockSize) / blockSize;
    size_t sizeInBlocks = align_up(size, blockSize) / blockSize;
    part.data.size = sizeInBlocks;

    // If a a patch partition file exists, populate actual size with its file
    // size if it is smaller than the total size.
    fs::path patchFile(PARTITION_FILES_PATCH_LOC);
    patchFile /= part.data.name;
    if (fs::is_regular_file(patchFile))
    {
        part.data.actual =
            std::min(size, static_cast<size_t>(fs::file_size(patchFile)));
    }
    else
    {
        part.data.actual = size;
    }
}

inline void Table::writeUserdata(pnor_partition& part, uint32_t version,
                                 const std::string& data)
{
    std::istringstream stream(data);
    std::string flag{};
    auto perms = 0;

    while (std::getline(stream, flag, ','))
    {
        if (flag == "ECC")
        {
            part.data.user.data[0] = PARTITION_ECC_PROTECTED;
        }
        else if (flag == "READONLY")
        {
            perms |= PARTITION_READONLY;
        }
        else if (flag == "PRESERVED")
        {
            perms |= PARTITION_PRESERVED;
        }
        else if (flag == "REPROVISION")
        {
            perms |= PARTITION_REPROVISION;
        }
        else if (flag == "VOLATILE")
        {
            perms |= PARTITION_VOLATILE;
        }
        else if (flag == "CLEARECC")
        {
            perms |= PARTITION_CLEARECC;
        }
    }

    part.data.user.data[1] = perms;

    part.data.user.data[1] |= version;
}

static inline void writeDefaults(pnor_partition& part)
{
    part.data.pid = PARENT_PATITION_ID;
    part.data.type = PARTITION_TYPE_DATA;
    part.data.flags = 0; // flags unused
}

static inline void writeNameAndId(pnor_partition& part, std::string&& name,
                                  const std::string& id)
{
    name.resize(PARTITION_NAME_MAX);
    memcpy(part.data.name, name.c_str(), sizeof(part.data.name));
    part.data.id = std::stoul(id);
}

bool Table::parseTocLine(fs::path& dir, const std::string& line,
                         pnor_partition& part)
{
    static constexpr auto ID_MATCH = 1;
    static constexpr auto NAME_MATCH = 2;
    static constexpr auto START_ADDR_MATCH = 4;
    static constexpr auto END_ADDR_MATCH = 6;
    static constexpr auto VERSION_MATCH = 8;
    constexpr auto versionShift = 24;

    // Parse PNOR toc (table of contents) file, which has lines like :
    // partition01=HBB,0x00010000,0x000a0000,0x80,ECC,PRESERVED, to indicate
    // partition information
    std::regex regex{
        "^partition([0-9]+)=([A-Za-z0-9_]+),"
        "(0x)?([0-9a-fA-F]+),(0x)?([0-9a-fA-F]+),(0x)?([A-Fa-f0-9]{2})",
        std::regex::extended};

    std::smatch match;
    if (!std::regex_search(line, match, regex))
    {
        return false;
    }

    fs::path partitionFile = dir;
    partitionFile /= match[NAME_MATCH].str();
    if (!fs::exists(partitionFile))
    {
        MSG_ERR("Partition file %s does not exist", partitionFile.c_str());
        return false;
    }

    writeNameAndId(part, match[NAME_MATCH].str(), match[ID_MATCH].str());
    writeDefaults(part);

    unsigned long start =
        std::stoul(match[START_ADDR_MATCH].str(), nullptr, 16);
    unsigned long end = std::stoul(match[END_ADDR_MATCH].str(), nullptr, 16);
    writeSizes(part, start, end);

    // Use the shift to convert "80" to 0x80000000
    unsigned long version = std::stoul(match[VERSION_MATCH].str(), nullptr, 16);
    writeUserdata(part, version << versionShift, match.suffix().str());
    part.checksum = details::checksum(part.data);

    return true;
}

void Table::preparePartitions()
{
    fs::path tocFile = directory;
    tocFile /= PARTITION_TOC_FILE;
    allocateMemory(tocFile);

    std::ifstream file(tocFile.c_str());
    std::string line;
    decltype(auto) table = getNativeTable();

    while (std::getline(file, line))
    {
        if (parseTocLine(directory, line, table.partitions[numParts]))
        {
            ++numParts;
        }
    }
}

const pnor_partition& Table::partition(size_t offset) const
{
    const decltype(auto) table = getNativeTable();
    size_t offt = offset / blockSize;

    for (decltype(numParts) i{}; i < numParts; ++i)
    {
        if ((offt >= table.partitions[i].data.base) &&
            (offt <
             (table.partitions[i].data.base + table.partitions[i].data.size)))
        {
            return table.partitions[i];
        }
    }

    MSG_ERR("Partition corresponding to offset %zu not found", offset);
    elog<InternalFailure>();

    static pnor_partition p{};
    return p;
}

const pnor_partition& Table::partition(const std::string& name) const
{
    const decltype(auto) table = getNativeTable();

    for (decltype(numParts) i{}; i < numParts; ++i)
    {
        if (name == table.partitions[i].data.name)
        {
            return table.partitions[i];
        }
    }

    MSG_ERR("Partition %s not found", name.c_str());
    log<level::ERR>("Table::partition partition not found ",
                    entry("PARTITION_NAME=%s", name.c_str()));
    elog<InternalFailure>();
    static pnor_partition p{};
    return p;
}

} // namespace partition

PartitionTable endianFixup(const PartitionTable& in)
{
    PartitionTable out;
    out.resize(in.size());
    auto src = reinterpret_cast<const pnor_partition_table*>(in.data());
    auto dst = reinterpret_cast<pnor_partition_table*>(out.data());

    dst->data.magic = htobe32(src->data.magic);
    dst->data.version = htobe32(src->data.version);
    dst->data.size = htobe32(src->data.size);
    dst->data.entry_size = htobe32(src->data.entry_size);
    dst->data.entry_count = htobe32(src->data.entry_count);
    dst->data.block_size = htobe32(src->data.block_size);
    dst->data.block_count = htobe32(src->data.block_count);
    dst->checksum = details::checksum(dst->data);

    for (decltype(src->data.entry_count) i{}; i < src->data.entry_count; ++i)
    {
        auto psrc = &src->partitions[i];
        auto pdst = &dst->partitions[i];
        strncpy(pdst->data.name, psrc->data.name, PARTITION_NAME_MAX);
        // Just to be safe
        pdst->data.name[PARTITION_NAME_MAX] = '\0';
        pdst->data.base = htobe32(psrc->data.base);
        pdst->data.size = htobe32(psrc->data.size);
        pdst->data.pid = htobe32(psrc->data.pid);
        pdst->data.id = htobe32(psrc->data.id);
        pdst->data.type = htobe32(psrc->data.type);
        pdst->data.flags = htobe32(psrc->data.flags);
        pdst->data.actual = htobe32(psrc->data.actual);
        for (size_t j = 0; j < PARTITION_USER_WORDS; ++j)
        {
            pdst->data.user.data[j] = htobe32(psrc->data.user.data[j]);
        }
        pdst->checksum = details::checksum(pdst->data);
    }

    return out;
}

} // namespace virtual_pnor
} // namespace openpower
