#include <syslog.h>
#include <stdarg.h>

extern "C" {
#include "common.h"
#include "mboxd_windows.h"
}

#include "mboxd_pnor.hpp"
#include "mboxd_memory_map.hpp"

openpower::flash::MemoryMap* memoryMap = nullptr;

int copy_pnor(struct mbox_context* context, uint32_t offset, void* mem,
              uint32_t size)
{
    int rc = 0;
    if (!memoryMap)
    {
        memoryMap = new openpower::flash::MemoryMap();
    }
    try
    {
        auto memInfo = memoryMap->getMappedMemory(offset);

        size = size << openpower::flash::shift;
        size = memInfo.size > size ? size : memInfo.size;

        //copy to the reserved memory area

        memcpy(mem,
               memInfo.bmcMappedMemory,
               size);
    }
    catch (const std::exception& e)
    {
        MSG_ERR(e.what());
        return -1;
    }
    return rc;
}
