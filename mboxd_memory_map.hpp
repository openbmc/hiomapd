#pragma once

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <syslog.h>
#include <stdarg.h>
#include <unistd.h>

#include "config.h"

#include <map>

namespace openpower
{
namespace flash
{

constexpr size_t shift = 12; // 1 block = 4096 bytes (1 << 12)

struct MemInfo
{
    void* bmcMappedMemory; // bmc mapped memory.
    ssize_t size; // size in blocks.
    int fd; // Mapped file descriptor.

    MemInfo()
    {
        bmcMappedMemory = nullptr;
        size = 0;
        fd = -1;
    }

    MemInfo(int fd, void* mem, ssize_t size)
    {
        this->fd = fd;
        this->bmcMappedMemory = mem;
        this->size = size;
    }
};

/** @class MemoryMap
 *  @brief Does the memory mepping between the BMC memory and the offset.
 *
 */
class MemoryMap
{
    public:
        MemoryMap() = default;
        MemoryMap(const MemoryMap&) = delete;
        MemoryMap& operator=(const MemoryMap&) = delete;
        MemoryMap(MemoryMap&&) = delete;
        MemoryMap& operator=(MemoryMap &&) = delete;
        ~MemoryMap();


        /** @brief Get the BMC mapped memory info for the offest
         *
         *  @returns the info containg bmc info.
         */

        MemInfo getMappedMemory(struct mbox_context* context, uint32_t offset);

        /** @brief Unmap and close the file associated with the offset
         *
         */

        void unloadFileFromMemory(uint32_t offset);

    private:

        /** @brief Loads the associated file into memory.
         *
         *  @returns the pair of (offset and the memoryinfo).
         */

        std::pair<uint32_t, MemInfo> loadFileIntoMemory(struct mbox_context* context,
                uint32_t offset);

        /*
         * @brief Mapping of the offset and the bmc memory.
         *
         */

        std::map<uint32_t, MemInfo>mappedMemorySet;
};
}//namespace flash
}//namespace openpower
