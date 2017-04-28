#include "pnor_partition_table.hpp"
#include "config.h"
#include <assert.h>
#include <string.h>
#include <vector>
#include <fstream>
#include <experimental/filesystem>

constexpr auto line = "partition01=HBB,00000000,00000400,ECC,PRESERVED";
constexpr auto partition = "HBB";
char tmplt[] = "/tmp/tmpdir.XXXXXX";

int main()
{
    char* tmpdir = mkdtemp(tmplt);
    assert(tmpdir != nullptr);

    fs::path tocFilePath{tmpdir};
    tocFilePath /= PARTITION_TOC_FILE;
    std::ofstream tocFile(tocFilePath.c_str());
    tocFile.write(line, strlen(line));
    tocFile.close();

    fs::path partitionFilePath{tmpdir};
    partitionFilePath /= partition;
    std::ofstream partitionFile(partitionFilePath.c_str());
    std::vector<char> empty(1, 0); // 1 byte file
    partitionFile.write(empty.data(), empty.size());
    partitionFile.close();

    openpower::virtual_pnor::partition::Table table(fs::path{tmpdir});

    pnor_partition_table tbl{};
    tbl.magic = PARTITION_HEADER_MAGIC;
    tbl.version = PARTITION_VERSION_1;
    tbl.size = 1; // 1 block
    tbl.entry_size = sizeof(pnor_partition);
    tbl.entry_count = 1; // 1 partition
    tbl.block_size = 4096;
    tbl.block_count = 2; // 1 table block and 1 partition block
    tbl.checksum = openpower::virtual_pnor::details::checksum(
                       &tbl,
                       sizeof(pnor_partition_table) -
                       sizeof(tbl.checksum));

    pnor_partition part{};
    strcpy(part.name, partition);
    part.base = 1; // starts after 1 block
    part.size = 1; // 1 block
    part.actual = 1; // 1 byte
    part.id = 1;
    part.pid = PARENT_PATITION_ID;
    part.type = PARTITION_TYPE_DATA;
    part.flags = 0;
    part.user.data[0] = PARTITION_ECC_PROTECTED;
    part.user.data[1] |= PARTITION_PRESERVED;
    part.checksum = openpower::virtual_pnor::details::checksum(
                        &part,
                        sizeof(pnor_partition) -
                        sizeof(part.checksum));

    const pnor_partition_table* result = table.getLE();

    fs::remove_all(fs::path{tmpdir});

    auto rc = memcmp(&tbl, result, sizeof(pnor_partition_table));
    assert(rc == 0);

    rc = memcmp(&part, &(result->partitions[0]), sizeof(pnor_partition));
    assert(rc == 0);

    const pnor_partition* first = table.partition(4096);
    rc = memcmp(first, &(result->partitions[0]), sizeof(pnor_partition));
    assert(rc == 0);

    return 0;
}
