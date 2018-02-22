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

        for (const auto& attr : attributes)
        {
            fs::create_directory(root / attr);
        }

        fs::path tocFilePath = root / "ro" / PARTITION_TOC_FILE;

        for (const std::string& line : toc)
        {
            pnor_partition part;

            openpower::virtual_pnor::parseTocLine(line, blockSize, part);

            /* Populate the partition in the tree */
            std::vector<char> zeroed(part.data.actual, 0);
            fs::path partitionFilePath = root / "ro" / part.data.name;
            std::ofstream(partitionFilePath)
                .write(zeroed.data(), zeroed.size());

            /* Update the ToC if the partition file was created */
            std::ofstream(tocFilePath, std::ofstream::app) << line << "\n";
        }
    }

    VpnorRoot(const VpnorRoot&) = delete;
    VpnorRoot& operator=(const VpnorRoot&) = delete;
    VpnorRoot(VpnorRoot&&) = delete;
    VpnorRoot& operator=(VpnorRoot&&) = delete;

    ~VpnorRoot()
    {
        fs::remove_all(root);
    }
    fs::path ro()
    {
        return fs::path{root} / "ro";
    }
    fs::path rw()
    {
        return fs::path{root} / "rw";
    }
    fs::path prsv()
    {
        return fs::path{root} / "prsv";
    }
    fs::path patch()
    {
        return fs::path{root} / "patch";
    }
    size_t write(const std::string& name, const void* data, size_t len);

  private:
    fs::path root;
    const std::string attributes[4] = {"ro", "rw", "prsv", "patch"};
};

} // test
} // virtual_pnor
} // openpower
