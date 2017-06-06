#pragma once

#include "mboxd_pnor_partition_table.h"
#include <fcntl.h>
#include <string>
#include <unistd.h>
#include <experimental/filesystem>

namespace openpower
{
namespace file
{

class Descriptor
{
    private:
        /** default value */
        int fd = -1;

    public:
        Descriptor() = default;
        Descriptor(const Descriptor&) = delete;
        Descriptor& operator=(const Descriptor&) = delete;
        Descriptor(Descriptor&&) = delete;
        Descriptor& operator=(Descriptor &&) = delete;

        Descriptor(int fd) : fd(fd) {}

        ~Descriptor()
        {
            if (fd >= 0)
            {
                close(fd);
            }
        }

        int operator()() const
        {
            return fd;
        }

        void set(int descriptor)
        {
            fd = descriptor;
        }
};

}// namespace file

namespace virtual_pnor
{

namespace fs = std::experimental::filesystem;

enum class ReturnCode : uint8_t
{
    FILE_NOT_FOUND = 0,
    PARTITION_NOT_FOUND = 1,
    PARTITION_READ_ONLY = 2,
    FILE_OPEN_FAILURE = 3,
    SUCCESS = 4,
};

class Request
{
    public:

        Request() = default;
        Request(const Request&) = delete;
        Request& operator=(const Request&) = delete;
        Request(Request&&) = default;
        Request& operator=(Request&&) = default;
        ~Request() = default;

        openpower::file::Descriptor fd;

    protected:
        /** @brief opens the partition file
         *
         *  @param[in] filePath - Absolute file path.
         *  @param[in] mode - File open mode.
         */
        ReturnCode open(const std::string& filePath, int mode);

        /** @brief returns the partition file path associated with the offset.
         *
         *  @param[in] context - The mbox context pointer.
         *  @param[in] offset - The pnor offset(bytes).
         */

        std::string getPartitionFilePath(struct mbox_context* context,
                                         uint32_t offset);

        const pnor_partition* partition = nullptr;
};

/** @class RORequest
 *  @brief Represent the read request of the partition.
 *         Stores the partition meta data.
 */
class RORequest : public Request
{
    public:
        RORequest() = default;
        RORequest(const RORequest&) = delete;
        RORequest& operator=(const RORequest&) = delete;
        RORequest(RORequest&&) = default;
        RORequest& operator=(RORequest&&) = default;
        ~RORequest(){};

        /** @brief opens the partition file associated with the offset
         *         in read only mode and gets the partition details.
         *
         *  1.  Depending on the partition type,tries to open the file
         *      from the associated partition(RW/PRSV/RO).
         *  1a. if file not found in the corresponding
         *      partition(RW/PRSV/RO) then tries to read the file from
         *      the read only partition.
         *  1b. if the file not found in the read only partition then
         *      throw exception.
         *
         *  @param[in] context - The mbox context pointer.
         *  @param[in] offset - The pnor offset(bytes).
         */
        const pnor_partition* getPartitionInfo(struct mbox_context* context,
                                               uint32_t offset);
};

/** @class RWRequest
 *  @brief Represent the write request of the partition.
 *         Stores the partition meta data.
 */
class RWRequest : public Request
{
    public:

        RWRequest() = default;
        RWRequest(const RWRequest&) = delete;
        RWRequest& operator=(const RWRequest&) = delete;
        RWRequest(RWRequest&&) = default;
        RWRequest& operator=(RWRequest&&) = default;
        ~RWRequest() {};

        /** @brief opens the partition file associated with the offset
         *         in write mode and gets the parttition details.
         *
         *  1.  Depending on the partition type tries to open the file
         *      from the associated partition.
         *  1a. if file not found in the corresponding partition(RW/PRSV)
         *      then copy the file from the read only partition to the (RW/PRSV)
         *      partition depending on the partition type.
         *  1b. if the file not found in the read only partition then throw exception.
         *
         *  @param[in] context - The mbox context pointer.
         *  @param[in] offset - The pnor offset(bytes).
         */
        const pnor_partition* getPartitionInfo(struct mbox_context* context,
                                               uint32_t offset);
};

}// namespace virtual_pnor
}// namespace openpower
