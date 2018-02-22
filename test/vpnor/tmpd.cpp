// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2018 IBM Corp.

#include "test/vpnor/tmpd.hpp"

namespace openpower
{
namespace virtual_pnor
{
namespace test
{

namespace fs = std::experimental::filesystem;

size_t VpnorRoot::write(const std::string &name, const void *data, size_t len)
{
    fs::path path{root};
    path /= name;

    if (!fs::exists(path))
        /* It's not in the ToC */
        throw std::invalid_argument(name);

    std::ofstream partitionFile(path.c_str());
    partitionFile.write((const char *)data, len);
    partitionFile.close();

    return len;
}

} // test
} // virtual_pnor
} // openpower
