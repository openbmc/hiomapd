#include "pnor_partition_table.hpp"
#include "config.h"
#include <assert.h>
#include <string.h>
#include <vector>
#include <fstream>
#include <experimental/filesystem>

constexpr auto line = "partition01=HBB,00000000,00000400,ECC,PRESERVED";
constexpr auto partitionName = "HBB";
char tmplt[] = "/tmp/vpnor_partitions.XXXXXX";

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
    partitionFilePath /= partitionName;
    std::ofstream partitionFile(partitionFilePath.c_str());
    std::vector<char> empty(1, 0); // 1 byte file
    partitionFile.write(empty.data(), empty.size());
    partitionFile.close();

    openpower::virtual_pnor::partition::Table table(fs::path{tmpdir});

    pnor_partition_table expectedTable{};
    expectedTable.data.magic = PARTITION_HEADER_MAGIC;
    expectedTable.data.version = PARTITION_VERSION_1;
    expectedTable.data.size = 1; // 1 block
    expectedTable.data.entry_size = sizeof(pnor_partition);
    expectedTable.data.entry_count = 1; // 1 partition
    expectedTable.data.block_size = 4096;
    expectedTable.data.block_count = 2; // 1 table block and 1 partition block
    expectedTable.checksum = openpower::virtual_pnor::details::checksum(
                                 &expectedTable.data,
                                 sizeof(expectedTable.data));

    pnor_partition expectedPartition{};
    strcpy(expectedPartition.data.name, partitionName);
    expectedPartition.data.base = 1; // starts after 1 block
    expectedPartition.data.size = 1; // 1 block
    expectedPartition.data.actual = 1; // 1 byte
    expectedPartition.data.id = 1;
    expectedPartition.data.pid = PARENT_PATITION_ID;
    expectedPartition.data.type = PARTITION_TYPE_DATA;
    expectedPartition.data.flags = 0;
    expectedPartition.data.user.data[0] = PARTITION_ECC_PROTECTED;
    expectedPartition.data.user.data[1] |= PARTITION_PRESERVED;
    expectedPartition.checksum = openpower::virtual_pnor::details::checksum(
                                     &expectedPartition.data,
                                     sizeof(expectedPartition.data));

    const pnor_partition_table* result = table.getNativeTable();

    fs::remove_all(fs::path{tmpdir});

    auto rc = memcmp(&expectedTable, result, sizeof(pnor_partition_table));
    assert(rc == 0);

    rc = memcmp(&expectedPartition, &(result->partitions[0]),
                sizeof(pnor_partition));
    assert(rc == 0);

    const pnor_partition* first = table.partition(4096);
    rc = memcmp(first, &(result->partitions[0]), sizeof(pnor_partition));
    assert(rc == 0);

    return 0;
}
