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

constexpr auto line = "partition01=HBB,00000000,00000400,ECC,PRESERVED";
constexpr auto partition = "HBB";
char tmplt[] = "/tmp/tmpdir.XXXXXX";
uint8_t data[8] = { 0xaa, 0x55, 0xaa, 0x66, 0x77, 0x88, 0x99, 0xab };

#define MEM_SIZE    sizeof(data)
#define ERASE_SIZE      1
#define N_WINDOWS       1
#define WINDOW_SIZE sizeof(data)

static const uint8_t get_info[] = {
        0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
// offset 1 and size 6
static const uint8_t create_read_window[] = {
        0x04, 0x01, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t response[] = {
        0x04, 0x01, 0xfd, 0xff, 0x06, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

namespace fs = std::experimental::filesystem;

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

    struct mbox_context *ctx;
    int rc;

    system_set_reserved_size(MEM_SIZE);
    system_set_mtd_sizes(sizeof(data), ERASE_SIZE);

    ctx = mbox_create_test_context(N_WINDOWS, WINDOW_SIZE);

    //create the partition table
    vpnor_create_partition_table_from_path(ctx, tmpdir);

    rc = mbox_command_dispatch(ctx, get_info, sizeof(get_info));
    assert(rc == 1);


    // send the request for partition1
    rc = mbox_command_dispatch(ctx, create_read_window,
                        sizeof(create_read_window));
    assert(rc == 1);

    rc = mbox_cmp(ctx, response, sizeof(response));
    assert(rc == 0);

    /* Compare the reserved memory to the pnor */
    rc = memcmp(ctx->mem, data, 6);
    assert(rc == 0);
    return rc;
}
