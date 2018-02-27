/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2018 IBM Corp. */
#pragma once

extern "C" {
#include "mbox.h"
};

#include "mboxd_pnor_partition_table.h"
#include "pnor_partition_table.hpp"
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
    Descriptor& operator=(Descriptor&&) = delete;

    Descriptor(int fd) : fd(fd)
    {
    }

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

} // namespace file

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
    /** @brief Construct a flash access request
     *
     *  @param[in] ctx - The mbox context used to process the request
     *  @param[in] offset - The absolute offset into the flash device as
     *                      provided by the mbox message associated with the
     *                      request
     *
     *  The class does not take ownership of the ctx pointer. The lifetime of
     *  the ctx pointer must strictly exceed the lifetime of the class
     *  instance.
     */
    Request(struct mbox_context* ctx, size_t offset) :
        ctx(ctx), partition(ctx->vpnor->table->partition(offset)),
        base(partition.data.base << ctx->block_size_shift),
        offset(offset - base)
    {
    }
    Request(const Request&) = delete;
    Request& operator=(const Request&) = delete;
    Request(Request&&) = default;
    Request& operator=(Request&&) = default;
    ~Request() = default;

    ssize_t read(void* dst, size_t len)
    {
        return fulfil(dst, len, O_RDONLY);
    }

    ssize_t write(void* dst, size_t len)
    {
        return fulfil(dst, len, O_RDWR);
    }

  private:
    /** @brief Returns the partition file path associated with the offset.
     *
     *  The search strategy for the partition file depends on the value of the
     *  flags parameter.
     *
     *  For the O_RDONLY case:
     *
     *  1.  Depending on the partition type,tries to open the file
     *      from the associated partition(RW/PRSV/RO).
     *  1a. if file not found in the corresponding
     *      partition(RW/PRSV/RO) then tries to read the file from
     *      the read only partition.
     *  1b. if the file not found in the read only partition then
     *      throw exception.
     *
     * For the O_RDWR case:
     *
     *  1.  Depending on the partition type tries to open the file
     *      from the associated partition.
     *  1a. if file not found in the corresponding partition(RW/PRSV)
     *      then copy the file from the read only partition to the (RW/PRSV)
     *      partition depending on the partition type.
     *  1b. if the file not found in the read only partition then throw
     *      exception.
     *
     *  @param[in] flags - The flags that will be used to open the file. Must
     *                     be one of O_RDONLY or O_RDWR.
     *
     *  Post-condition: The file described by the returned path exists
     *
     *  Throws: std::filesystem_error, std::bad_alloc
     */
    std::experimental::filesystem::path getPartitionFilePath(int flags);

    /** @brief Fill dst with the content of the partition relative to offset.
     *
     *  @param[in] offset - The pnor offset(bytes).
     *  @param[out] dst - The buffer to fill with partition data
     *  @param[in] len - The length of the destination buffer
     */
    ssize_t fulfil(void* dst, size_t len, int flags);

    struct mbox_context* ctx;
    const pnor_partition& partition;
    size_t base;
    size_t offset;
};

} // namespace virtual_pnor
} // namespace openpower
