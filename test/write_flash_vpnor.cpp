/*
 * MBox Daemon Test File
 *
 * Copyright 2017 IBM
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
#include "mbox.h"
#include "test/tmpf.h"
#include "mboxd_flash.h"
}

#include <assert.h>
#include <unistd.h>

#include <fstream>
#include <experimental/filesystem>

#include <sys/mman.h>
#include <sys/syslog.h>
#include <sys/ioctl.h>
#include <fcntl.h>

uint8_t data[8] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7};

#define BLOCK_SIZE 4096
#define OFFSET BLOCK_SIZE
#define MEM_SIZE (BLOCK_SIZE * 2)
#define DATA_SIZE sizeof(data)
#define ERASE_SIZE BLOCK_SIZE
#define BLOCK_SIZE_SHIFT 12

void init(struct mbox_context* ctx)
{

    namespace fs = std::experimental::filesystem;
    using namespace std::string_literals;

    std::string tocData =
        "partition01=TEST1,00001000,00001400,ECC,READONLY\n"s +
        "partition02=TEST2,00002000,00002008,ECC,READWRITE\n"s +
        "partition03=TEST3,00003000,00003400,ECC,PRESERVED"s;

    std::vector<std::string> templatePaths = {
        "/tmp/ro.XXXXXX", "/tmp/rw.XXXXXX", "/tmp/prsv.XXXXXX",
        "/tmp/patch.XXXXXX"};

    std::vector<std::string> partitions = {"TEST1", "TEST2", "TEST3"};

    // create various partition directory

    std::string tmpROdir = mkdtemp(const_cast<char*>(templatePaths[0].c_str()));
    assert(tmpROdir.length() != 0);

    std::string tmpRWdir = mkdtemp(const_cast<char*>(templatePaths[1].c_str()));
    assert(tmpRWdir.length() != 0);

    std::string tmpPRSVdir =
        mkdtemp(const_cast<char*>(templatePaths[2].c_str()));
    assert(tmpPRSVdir.length() != 0);

    std::string tmpPATCHdir =
        mkdtemp(const_cast<char*>(templatePaths[3].c_str()));
    assert(tmpPATCHdir.length() != 0);

    // create the toc file
    fs::path tocFilePath = tmpROdir;

    tocFilePath /= PARTITION_TOC_FILE;
    std::ofstream tocFile(tocFilePath.c_str());
    tocFile.write(tocData.c_str(), static_cast<int>(tocData.length()));
    tocFile.close();

    // create the partition files in the ro directory
    for (auto partition : partitions)
    {
        fs::path partitionFilePath{tmpROdir};
        partitionFilePath /= partition;
        std::ofstream partitionFile(partitionFilePath.c_str());
        partitionFile.write(reinterpret_cast<char*>(data), sizeof(data));
        partitionFile.close();
    }

    // copy partition2 file from ro to rw
    std::string roFile = tmpROdir + "/" + "TEST2";
    std::string rwFile = tmpRWdir + "/" + "TEST2";
    assert(fs::copy_file(roFile, rwFile) == true);

    mbox_vlog = &mbox_log_console;
    verbosity = (verbose)2;

    // setting context parameters
    ctx->erase_size_shift = BLOCK_SIZE_SHIFT;
    ctx->block_size_shift = BLOCK_SIZE_SHIFT;
    ctx->flash_bmap = reinterpret_cast<uint8_t*>(
        calloc(MEM_SIZE >> ctx->erase_size_shift, sizeof(*ctx->flash_bmap)));

    strcpy(ctx->paths.ro_loc, tmpROdir.c_str());
    strcpy(ctx->paths.rw_loc, tmpRWdir.c_str());
    strcpy(ctx->paths.prsv_loc, tmpPRSVdir.c_str());
    strcpy(ctx->paths.patch_loc, tmpPATCHdir.c_str());
}

int main(void)
{
    namespace fs = std::experimental::filesystem;

    int rc{};
    char src[DATA_SIZE]{0};
    struct mbox_context context;
    struct mbox_context* ctx = &context;
    memset(ctx, 0, sizeof(mbox_context));

    // Initialize the context before running the test case.
    init(ctx);

    std::string tmpROdir = ctx->paths.ro_loc;
    std::string tmpRWdir = ctx->paths.rw_loc;
    std::string tmpPRSVdir = ctx->paths.prsv_loc;
    std::string tmpPATCHdir = ctx->paths.patch_loc;

    // create the partition table
    vpnor_create_partition_table_from_path(ctx, tmpROdir.c_str());

    // Write to psrv partition

    // As file doesn't exist there, so it copies
    // the file from RO to PRSV and write the file in PRSV partition.

    memset(src, 0xaa, sizeof(src));

    rc = write_flash(ctx, (OFFSET * 3), src, sizeof(src));
    assert(rc == 0);

    auto fd = open((tmpPRSVdir + "/" + "TEST3").c_str(), O_RDONLY);
    auto map = mmap(NULL, MEM_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    assert(map != MAP_FAILED);

    // verify it is written
    rc = memcmp(src, map, sizeof(src));
    assert(rc == 0);
    munmap(map, MEM_SIZE);
    close(fd);

    // Write to the RO partition
    memset(src, 0x55, sizeof(src));
    fd = open((tmpROdir + "/" + "TEST1").c_str(), O_RDONLY);
    map = mmap(NULL, MEM_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    assert(map != MAP_FAILED);
    rc = write_flash(ctx, (OFFSET), src, sizeof(src));
    // Should not be allowed to write on RO
    assert(rc != 0);

    munmap(map, MEM_SIZE);
    close(fd);

    // Write to the RW partition
    memset(src, 0xbb, sizeof(src));
    fd = open((tmpRWdir + "/" + "TEST2").c_str(), O_RDONLY);
    map = mmap(NULL, MEM_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    assert(map != MAP_FAILED);
    rc = write_flash(ctx, (OFFSET * 2), src, sizeof(src));
    assert(rc == 0);
    rc = memcmp(src, map, sizeof(src));
    assert(rc == 0);

    // write beyond the partition length as the partition
    // file length is 8 byte(TEST2).
    rc = write_flash(ctx, (OFFSET * 2 + 3), src, sizeof(src) + 20);
    assert(rc == -1);

    memset(src, 0xcc, sizeof(src));
    rc = write_flash(ctx, (OFFSET * 2), src, sizeof(src));
    assert(rc == 0);
    rc = memcmp(src, map, sizeof(src));
    assert(rc == 0);

    src[0] = 0xff;
    rc = write_flash(ctx, (OFFSET * 2), src, 1);
    assert(rc == 0);
    rc = memcmp(src, map, sizeof(src));
    assert(rc == 0);

    src[1] = 0xff;
    rc = write_flash(ctx, (OFFSET * 2) + 1, &src[1], 1);
    assert(rc == 0);
    rc = memcmp(src, map, sizeof(src));
    assert(rc == 0);

    src[2] = 0xff;
    rc = write_flash(ctx, (OFFSET * 2) + 2, &src[2], 1);
    assert(rc == 0);
    rc = memcmp(src, map, sizeof(src));
    assert(rc == 0);

    munmap(map, MEM_SIZE);
    close(fd);

    // START Test patch location - Patch dir has preference over other locations
    // Copy partition2 file from ro to patch to simulate a patch file that is
    // different from the one in rw (partition2 in rw was modified with the
    // previous write test)
    fs::path roFile(tmpROdir);
    roFile /= "TEST2";
    fs::path patchFile(tmpPATCHdir);
    patchFile /= "TEST2";
    assert(fs::copy_file(roFile, patchFile) == true);

    // Write arbitrary data
    char srcPatch[DATA_SIZE]{0};
    memset(srcPatch, 0x33, sizeof(srcPatch));
    rc = write_flash(ctx, (OFFSET * 2), srcPatch, sizeof(srcPatch));
    assert(rc == 0);

    // Check that partition file in RW location still contains the original data
    fs::path rwFile(tmpRWdir);
    rwFile /= "TEST2";
    fd = open(rwFile.c_str(), O_RDONLY);
    map = mmap(NULL, MEM_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    assert(map != MAP_FAILED);
    rc = memcmp(src, map, sizeof(src));
    assert(rc == 0);
    munmap(map, MEM_SIZE);
    close(fd);

    // Check that partition file in PATCH location was written with the new data
    fd = open(patchFile.c_str(), O_RDONLY);
    map = mmap(NULL, MEM_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    assert(map != MAP_FAILED);
    rc = memcmp(srcPatch, map, sizeof(srcPatch));
    assert(rc == 0);
    munmap(map, MEM_SIZE);
    close(fd);

    // Remove patch file so that subsequent tests don't use it
    fs::remove(patchFile);
    // END Test patch location

    fs::remove_all(fs::path{tmpROdir});
    fs::remove_all(fs::path{tmpRWdir});
    fs::remove_all(fs::path{tmpPRSVdir});
    fs::remove_all(fs::path{tmpPATCHdir});

    destroy_vpnor(ctx);
    free(ctx->flash_bmap);

    return rc;
}
