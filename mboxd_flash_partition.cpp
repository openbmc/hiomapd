#include "mboxd_flash_partition.hpp"
#include "mboxd_flash_location.hpp"
#include "common.h"
#include <sys/stat.h>
#include <stdlib.h>
#include <regex>

namespace openpower
{
namespace flash
{
namespace partition
{
namespace block
{

// The partition table is at least 1 block.
constexpr size_t shift = 0xC; // 1 block = 4096 bytes (1 << 12)
// The partition table size and the start of the partitions itself
// are all block-size aligned.
constexpr size_t partitionStart = 1 << shift;

};

namespace details
{

uint32_t checksum(const void* data, size_t size)
{
    uint32_t checksum = 0;

    for (size_t i = 0; i < (size / 4); ++i)
    {
        checksum ^= (static_cast<const uint32_t*>(data))[i];
    }
    checksum = htobe32(checksum);

    return checksum;
}

}

Table::Table():
    sz(block::partitionStart),
    header({})
{
    entries = genEntries();
    align(entries);
    genHeader();
}

void Table::align(Entries& entries)
{
    // Align partition table size to block-size if need be.
    sz = align_up((entries.size() * sizeof(partition_entry)),
                   1 << block::shift);

    // If partition table is larger than a block, fixup size and partition start
    // offsets.
    if (sz > block::partitionStart)
    {
        off_t diff = sz - block::partitionStart;
        std::for_each(
            entries.begin(),
            entries.end(),
            [&](partition_entry& e){ e.base += diff; });
    }
}

void Table::genHeader()
{
    header.magic = htobe32(HDR_MAGIC);
    header.version = htobe32(PARTITION_VERSION_1);
    header.size = htobe32(sz >> block::shift);
    header.entry_size = htobe32(sizeof(partition_entry));
    header.entry_count = htobe32(entries.size());
    header.block_size = htobe32(1 << block::shift);
    header.block_count = htobe32(sz >> block::shift);
    header.checksum = details::checksum(&header,
                                        sizeof(partition_hdr) -
                                        sizeof(header.checksum));
}

Entries Table::genEntries()
{
    Entries entries;

    // Parse PNOR toc (table of contents) file
    openpower::flash::Location location;
    std::string line;
    std::regex regex
    {
        "^partition([0-9]+)=([A-Za-z0-9_]+),"
        "([0-9a-fA-F]+),([0-9a-fA-F]+)(,[A-Z]+)*",
        std::regex::extended
    };
    std::smatch match;

    off_t offset = block::partitionStart;
    while (std::getline(location.file(), line))
    {
        if (std::regex_search(line, match, regex))
        {
            auto path = location.directory() + "/" + match[2].str();
            partition_entry entry{};

            struct stat results;
            // Get size of partition file
            if (!stat(path.c_str(), &results))
            {
                entry.actual = results.st_size;
            }
            else
            {
                continue;
            }

            strcpy(entry.name, match[2].str().c_str());

            entry.base = htobe32(offset >> block::shift);
            entry.size = align_up(entry.actual, 1 << block::shift);
            offset += entry.size;
            entry.size = htobe32(entry.size >> block::shift);
            entry.actual = htobe32(entry.actual);

            entry.id = htobe32(atoi(match[1].str().c_str()));
            entry.pid = htobe32(ENTRY_PID_TOPLEVEL);
            entry.type = htobe32(PARTITION_TYPE_DATA);
            entry.flags = 0;

            applyProperties(line, entry);

            entry.checksum = details::checksum(&entry,
                                               sizeof(partition_entry) -
                                               sizeof(entry.checksum));

            entries.emplace_back(entry);
        }
    }

    return entries;
}

void Table::applyProperties(const std::string& line,
                            partition_entry& entry)
{
    if (std::string::npos != line.find("ECC"))
    {
        entry.user.data[0] = htobe32(PARTITION_ECC_PROTECTED);
    }

    entry.user.data[1] = 0;
    if (std::string::npos != line.find("READONLY"))
    {
        entry.user.data[1] |= PARTITION_READONLY;
    }
    if (std::string::npos != line.find("PRESERVED"))
    {
        entry.user.data[1] |= PARTITION_PRESERVED;
    }
    entry.user.data[1] = htobe32(entry.user.data[1]);
}

const partition_entry* Table::entry(const off_t offset) const
{
    const partition_entry* e = nullptr;

    for (const auto& itr : entries)
    {
        if (htobe32(offset >> block::shift) == itr.base)
        {
            e = &itr;
            break;
        }
    }

    return e;
}

}
}
}
