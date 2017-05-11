#include "pnor_partition_table.hpp"
#include "config.h"

extern "C" {
#include "test/mbox.h"
#include "test/system.h"
}

#include <assert.h>
#include <string.h>

#include <vector>
#include <fstream>
#include <experimental/filesystem>

constexpr auto line = "partition01=HBB,00000000,00000400,ECC,PRESERVED";
constexpr auto partition = "HBB";
char tmplt[] = "/tmp/tmpdir.XXXXXX";

#define ERASE_SIZE      2
#define N_WINDOWS       2

static const uint8_t get_info[] = {
        0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
// offset 0 and size 10
static const uint8_t create_read_window_0[] = {
        0x04, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
// offset 1 and size 6
static const uint8_t create_read_window_1[] = {
        0x04, 0x02, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t response[] = {
        0x04, 0x02, 0xfd, 0xff, 0x06, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};


int main()
{
    char* tmpdir = mkdtemp(tmplt);
    assert(tmpdir != nullptr);
    //create the toc file
    fs::path tocFilePath{tmpdir};
    tocFilePath /= PARTITION_TOC_FILE;
    std::ofstream tocFile(tocFilePath.c_str());
    tocFile.write(line, strlen(line));
    tocFile.close();
    //create the partition file
    fs::path partitionFilePath{tmpdir};
    partitionFilePath /= partition;
    std::ofstream partitionFile(partitionFilePath.c_str());
    //Partition Data
    std::vector<char> partitionData = {'a', 'b', 'c', 'd', 'e', 'f',
                                       'g', 'h', 'i', 'j'};

    partitionFile.write(partitionData.data(), partitionData.size());
    partitionFile.close();
    
    struct mbox_context *ctx;
    int rc;

    system_set_reserved_size(partitionData.size());
    system_set_mtd_sizes(partitionData.size(), ERASE_SIZE);

    ctx = mbox_create_test_context(N_WINDOWS, (size_t)partitionData.size());

    // Doesn't need to set the mtd_data as we would be reading the data 
    // from the partition file.

    // TODO : need to introduce one more api which sets the partition 
    //        file location.

    rc = mbox_command_dispatch(ctx, get_info, sizeof(get_info));
    assert(rc == 1);
    
    // send the request for offest 0 which will create the
    // partition table.
    rc = mbox_command_dispatch(ctx, create_read_window_0,
                        sizeof(create_read_window_0));
    assert(rc == 1);

    // send the request for partition1
    rc = mbox_command_dispatch(ctx, create_read_window_1,
                        sizeof(create_read_window_1));
    assert(rc == 1);

    rc = mbox_cmp(ctx, response, sizeof(response));
    assert(rc == 0);

    /* Compare the reserved memory to the pnor */
    rc = memcmp(ctx->mem, partitionData.data(), 6);
    assert(rc == 0);
    return rc;
}
