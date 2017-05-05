#include <fcntl.h>
#include <stdarg.h>
#include <syslog.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

extern "C" {
#include "common.h"
#include "mboxd_windows.h"
}

#include "config.h"
#include "mboxd_pnor.h"
#include "mboxd_pnor_partition_table.h"

#include <string>
#include <exception>
#include <stdexcept>
#include <experimental/filesystem>


int copy_pnor(struct mbox_context* context, uint32_t offset, void* mem,
              uint32_t size)
{
    int rc = 0;
    try
    {
        auto partition = vpnor_get_partition(context, offset);

        if (!partition)
        {
            std::string msg = "Couldn't get the partition info for offset " + offset;
            throw std::runtime_error(msg);
        }

        namespace fs = std::experimental::filesystem;

        fs::path partitionFilePath = std::string(PARTITION_FILES_LOC);
        partitionFilePath /= partition->name;

        auto fd = open(partitionFilePath.c_str(), O_RDONLY);
        if (fd == -1)
        {
            throw std::runtime_error("Couldn't open the partition file");
        }

        // if partition size is > then window size
        size = partition->actual > size ? size : partition->actual;

        auto mapped_mem = mmap(NULL,
                               size,
                               PROT_READ, MAP_PRIVATE, fd, offset);

        if (mem == MAP_FAILED)
        {
            std::string msg = "Failed to map" + partitionFilePath.string() + ":" + strerror(
                                  errno);
            close(fd);
            throw std::runtime_error(msg);
        }

        //copy to the reserved memory area
        memcpy(mem,
               mapped_mem,
               size);

        munmap(mem, size);
        close(fd);
    }
    catch (const std::exception& e)
    {
        MSG_ERR(e.what());
    }
    return rc;
}
