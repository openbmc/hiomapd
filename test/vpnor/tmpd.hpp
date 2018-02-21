/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2018 IBM Corp. */

#include <assert.h>
#include <string.h>
#include <vector>
#include <fstream>
#include <experimental/filesystem>

#include "config.h"
#include "pnor_partition_table.hpp"

namespace fs = std::experimental::filesystem;

namespace openpower
{
namespace virtual_pnor
{
namespace test
{

template <std::size_t N>
void createVpnorTree(fs::path &root, const std::string (&toc)[N],
                     size_t blockSize)
{
    fs::path tocFilePath{root};
    tocFilePath /= PARTITION_TOC_FILE;
    std::ofstream tocFile(tocFilePath.c_str());

    for (const std::string &line : toc)
    {
        pnor_partition part;

        openpower::virtual_pnor::parseTocLine(line, blockSize, part);

        /* Populate the partition in the tree */
        fs::path partitionFilePath{root};
        partitionFilePath /= part.data.name;
        std::ofstream partitionFile(partitionFilePath.c_str());
        std::vector<char> empty(part.data.size, 0);
        partitionFile.write(empty.data(), empty.size());
        partitionFile.close();

        /* Update the ToC if the partition file was created */
        tocFile.write(line.c_str(), line.length());
        tocFile.write("\n", 1);
    }

    tocFile.close();
}

} // test
} // virtual_pnor
} // openpower
