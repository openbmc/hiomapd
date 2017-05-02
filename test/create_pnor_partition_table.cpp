#include "mboxd_flash_partition.hpp"
#include <assert.h>
#include <string.h>
#include <vector>
#include <fstream>
#include <experimental/filesystem>

constexpr auto toc = "/tmp/pnor.toc";
constexpr auto dir = "/tmp";
constexpr auto line = "partition01=HBB,00000000,00000400,ECC,PRESERVED";
constexpr auto partition = "HBB";

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

int main()
{
    std::ofstream tocFile(toc);
    tocFile.write(line, strlen(line));

    std::ofstream partitionFile(std::string(dir) + "/" + partition);
    std::vector<char> empty(0x400, 0);
    partitionFile.write(empty.data(), empty.size());

    fs::path path(dir);
    openpower::virtual_pnor::partition::Table table(std::move(path));

    pnor_partition_table tbl{};
    tbl.magic = htobe32(PARTITION_HEADER_MAGIC);
    tbl.version = htobe32(PARTITION_VERSION_1);
    tbl.size = htobe32(1); // 1 block
    tbl.entry_size = htobe32(sizeof(pnor_partition));
    tbl.entry_count = htobe32(1); // 1 partition
    tbl.block_size = htobe32(4096);
    tbl.block_count = htobe32(2); // 1 table block and 1 partition block
    tbl.checksum = checksum(&tbl,
                            sizeof(pnor_partition_table) -
                            sizeof(tbl.checksum));

    pnor_partition part{};
    strcpy(part.name, partition);
    part.base = htobe32(1); // starts after 1 block
    part.size = htobe32(1); // 1 block
    part.actual = htobe32(0x400); // 1 KB
    part.id = htobe32(1);
    part.pid = htobe32(PARENT_PATITION_ID);
    part.type = htobe32(PARTITION_TYPE_DATA);
    part.flags = 0;
    part.user.data[0] = htobe32(PARTITION_ECC_PROTECTED);
    part.user.data[1] |= htobe32(PARTITION_PRESERVED);
    part.checksum = checksum(&part,
                             sizeof(pnor_partition) -
                             sizeof(part.checksum));

    const pnor_partition_table* result = table.table();

    auto rc = memcmp(&tbl, result, sizeof(pnor_partition_table));
    assert(rc == 0);

    rc = memcmp(&part, &(result->partitions[0]), sizeof(pnor_partition));
    assert(rc == 0);

    const pnor_partition* first = table.partition(4096);
    rc = memcmp(first, &(result->partitions[0]), sizeof(pnor_partition));
    assert(rc == 0);

    return 0;
}
