/*
 * MBox Daemon Test File
 *
 * Copyright 2018 IBM
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "config.h"
#include "mboxd_pnor_partition_table.h"

extern "C" {
#include "test/mbox.h"
#include "test/system.h"
}

#include <assert.h>
#include <string.h>

#include <vector>
#include <fstream>
#include <experimental/filesystem>

// A read window assumes that the toc is located at offset 0,
// so create dummy partition at arbitrary offset 0x100.
constexpr auto line = "partition01=HBB,00000100,0001000,ECC,PRESERVED";
constexpr auto partition = "HBB";
char tmplt[] = "/tmp/create_read_test.XXXXXX";
uint8_t data[8] = {0xaa, 0x55, 0xaa, 0x66, 0x77, 0x88, 0x99, 0xab};

#define BLOCK_SIZE 4096
#define MEM_SIZE (BLOCK_SIZE * 2)
#define ERASE_SIZE BLOCK_SIZE
#define N_WINDOWS 1
#define WINDOW_SIZE BLOCK_SIZE

static const uint8_t get_info[] = {0x02, 0x00, 0x02, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00};
// offset 0x100 and size 6
static const uint8_t create_read_window[] = {0x04, 0x01, 0x01, 0x00, 0x06, 0x00,
                                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0x00};

static const uint8_t response[] = {0x04, 0x01, 0xfe, 0xff, 0x01, 0x00, 0x01,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

namespace fs = std::experimental::filesystem;

int main()
{
    char* tmpdir = mkdtemp(tmplt);
    assert(tmpdir != nullptr);

    // create the toc file
    fs::path tocFilePath{tmpdir};
    tocFilePath /= PARTITION_TOC_FILE;
    std::ofstream tocFile(tocFilePath.c_str());
    tocFile.write(line, strlen(line));
    tocFile.close();

    // create the partition file
    fs::path partitionFilePath{tmpdir};
    partitionFilePath /= partition;
    std::ofstream partitionFile(partitionFilePath.c_str());

    partitionFile.write((char*)data, sizeof(data));
    partitionFile.close();

    system_set_reserved_size(MEM_SIZE);
    system_set_mtd_sizes(MEM_SIZE, ERASE_SIZE);

    struct mbox_context* ctx = mbox_create_test_context(N_WINDOWS, WINDOW_SIZE);
    strcpy(ctx->paths.ro_loc, tmpdir);
    strcpy(ctx->paths.rw_loc, tmpdir);
    strcpy(ctx->paths.prsv_loc, tmpdir);

    vpnor_create_partition_table_from_path(ctx, tmpdir);

    int rc = mbox_command_dispatch(ctx, get_info, sizeof(get_info));
    assert(rc == 1);

    // send the request for partition1
    rc = mbox_command_dispatch(ctx, create_read_window,
                               sizeof(create_read_window));
    assert(rc == 1);

    rc = mbox_cmp(ctx, response, sizeof(response));
    assert(rc == 0);

    // Compare the reserved memory to the pnor
    rc = memcmp(ctx->mem, data, 6);
    assert(rc == 0);

    // TODO: Add few more test cases for read from multiple partitions(PRSV/RW)
    //      Read beyond the partition file size.
    //      openbmc/openbmc#1868

    fs::remove_all(fs::path{tmpdir});
    return rc;
}
