/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2018 IBM Corp. */

#include <assert.h>
#include <string.h>
#include <vector>
#include <fstream>
#include <experimental/filesystem>

#include "config.h"
#include "pnor_partition_table.hpp"

namespace openpower
{
namespace virtual_pnor
{
namespace test
{

namespace fs = std::experimental::filesystem;

class VpnorRoot
{
  public:
    template <std::size_t N>
    VpnorRoot(const std::string (&toc)[N], size_t blockSize)
    {
        char tmplt[] = "/tmp/vpnor_root.XXXXXX";
        char* tmpdir = mkdtemp(tmplt);
        root = fs::path{tmpdir};

        fs::path tocFilePath{root};
        tocFilePath /= PARTITION_TOC_FILE;
        std::ofstream tocFile(tocFilePath.c_str());

        for (const std::string& line : toc)
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

    VpnorRoot(const VpnorRoot&) = delete;
    VpnorRoot& operator=(const VpnorRoot&) = delete;
    VpnorRoot(VpnorRoot&&) = delete;
    VpnorRoot& operator=(VpnorRoot&&) = delete;

    ~VpnorRoot()
    {
        fs::remove_all(root);
    }
    const fs::path& path()
    {
        return root;
    }
    size_t write(const std::string& name, const void* data, size_t len);

  private:
    fs::path root;
};

} // test
} // virtual_pnor
} // openpower
