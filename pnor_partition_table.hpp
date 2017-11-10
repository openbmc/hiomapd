#pragma once

#include <vector>
#include <memory>
#include <numeric>
#include <experimental/filesystem>
#include "pnor_partition_defs.h"

namespace openpower
{
namespace virtual_pnor
{

namespace fs = std::experimental::filesystem;

using PartitionTable = std::vector<uint8_t>;
using checksum_t = uint32_t;

/** @brief Convert the input partition table to big endian.
 *
 *  @param[in] src - reference to the pnor partition table
 *
 *  @returns converted partition table
 */
PartitionTable endianFixup(const PartitionTable& src);

namespace details
{

/** @brief Compute XOR-based checksum, by XORing consecutive words
 *         in the input data. Input must be aligned to word boundary.
 *
 *  @param[in] data - input data on which checksum is computed
 *
 *  @returns computed checksum
 */
template <class T>
checksum_t checksum(const T& data)
{
    static_assert(sizeof(decltype(data)) % sizeof(checksum_t) == 0,
                  "sizeof(data) is not aligned to sizeof(checksum_t) boundary");

    auto begin = reinterpret_cast<const checksum_t*>(&data);
    auto end = begin + (sizeof(decltype(data)) / sizeof(checksum_t));

    return std::accumulate(begin, end, 0, std::bit_xor<checksum_t>());
}

} // namespace details

namespace partition
{

/** @class Table
 *  @brief Generates virtual PNOR partition table.
 *
 *  Generates virtual PNOR partition table upon construction. Reads
 *  the PNOR information generated by this tool :
 *  github.com/openbmc/openpower-pnor-code-mgmt/blob/master/generate-squashfs,
 *  which generates a minimalistic table-of-contents (toc) file and
 *  individual files to represent various partitions that are of interest -
 *  these help form the "virtual" PNOR, which is typically a subset of the full
 *  PNOR image.
 *  These files are stored in a well-known location on the PNOR.
 *  Based on this information, this class prepares the partition table whose
 *  structure is as outlined in pnor_partition.h.
 *
 *  The virtual PNOR supports 4KB erase blocks - partitions must be aligned to
 *  this size.
 */
class Table
{
    public:
        /** @brief Constructor accepting the path of the directory
         *         that houses the PNOR partition files.
         *
         *  @param[in] directory - path of the directory housing PNOR partitions
         *  @param[in] blockSize - PNOR block size, in bytes. See
         *             open-power/hostboot/blob/master/src/usr/pnor/ffs.h for
         *             the PNOR FFS structure.
         *  @param[in] pnorSize - PNOR size, in bytes
         */
        Table(fs::path&& directory,
              size_t blockSize,
              size_t pnorSize);

        /** @brief Constructor - creates partition table
         *
         *  @param[in] blockSize - PNOR block size, in bytes
         *  @param[in] pnorSize - PNOR size, in bytes
         */
        Table(size_t blockSize,
              size_t pnorSize);

        Table(const Table&) = delete;
        Table& operator=(const Table&) = delete;
        Table(Table&&) = delete;
        Table& operator=(Table&&) = delete;
        ~Table() = default;

        /** @brief Return size of partition table
         *
         *  @returns size_t - size of partition table in blocks
         */
        size_t size() const
        {
            return szBlocks;
        }

        /** @brief Return a partition table having byte-ordering
         *         that the host expects.
         *
         *  The host needs the partion table in big-endian.
         *
         *  @returns const reference to host partition table.
         */
        const pnor_partition_table& getHostTable() const
        {
            return *(reinterpret_cast<
                         const pnor_partition_table*>(hostTbl.data()));
        }

        /** @brief Return a little-endian partition table
         *
         *  @returns const reference to native partition table
         */
        const pnor_partition_table& getNativeTable() const
        {
            return *(reinterpret_cast<const pnor_partition_table*>(tbl.data()));
        }

        /** @brief Return partition corresponding to PNOR offset, the offset
         *         is within returned partition.
         *
         *  @param[in] offset - PNOR offset in bytes
         *
         *  @returns const reference to pnor_partition, if found, else an
         *           exception will be thrown.
         */
        const pnor_partition& partition(size_t offset) const;

        /** @brief Return partition corresponding to input partition name.
         *
         *  @param[in] name - PNOR partition name
         *
         *  @returns const reference to pnor_partition, if found, else an
         *           exception will be thrown.
         */
        const pnor_partition& partition(const std::string& name) const;

    private:
        /** @brief Prepares a vector of PNOR partition structures.
         */
        void preparePartitions();

        /** @brief Prepares the PNOR header.
         */
        void prepareHeader();

        /** @brief Allocate memory to hold the partion table. Determine the
         *         amount needed based on the partition files in the toc file.
         *
         *  @param[in] tocFile - Table of contents file path.
         */
        void allocateMemory(const fs::path& tocFile);

        /** @brief Populate fields related to sizes for the input
         *         pnor_partition structure.
         *
         *  @param[in/out] part - pnor_partition structure
         *  @param[in] start - partition start address
         *  @param[in] end - partition end address
         */
        void writeSizes(pnor_partition& part, size_t start, size_t end);

        /** @brief Populate userdata bits for the input
         *         pnor_partition structure.
         *
         *  @param[in/out] part - pnor_partition structure
         *  @param[in] version - partition version check algorithm to be used
         *                       (see pnor_partition_defs.h)
         *  @param[in] data - string having userdata fields in a
         *             comma-separated line.
         */
        void writeUserdata(pnor_partition& part, uint32_t version,
                           const std::string& data);

        /** @brief Populate the name and id fields for the input
         *         pnor_partition structure.
         *
         *  @param[in/out] part - pnor_partition structure
         *  @param[in] name - partition name
         *  @param[id] id - partition id
         */
        void writeNameAndId(pnor_partition& part, std::string&& name,
                            const std::string& id);

        /** @brief Populate default/unused fields for the input
         *         pnor_partition structure.
         *
         *  @param[in/out] part - pnor_partition structure
         */
        void writeDefaults(pnor_partition& part);

        /** @brief Return a little-endian partition table
         *
         *  @returns reference to native partition table
         */
        pnor_partition_table& getNativeTable()
        {
            return *(reinterpret_cast<pnor_partition_table*>(tbl.data()));
        }

        /** @brief Size of the PNOR partition table -
         *         sizeof(pnor_partition_table) +
         *         (no. of partitions * sizeof(pnor_partition)),
         *         measured in erase-blocks.
         */
        size_t szBlocks;

        /** @brief Size of virtual PNOR image, measured in erase-blocks */
        size_t imgBlocks;

        /** @brief Partition table */
        PartitionTable tbl;

        /** @brief Partition table with host byte ordering */
        PartitionTable hostTbl;

        /** @brief Directory housing generated PNOR partition files */
        fs::path directory;

        /** @brief Number of partitions */
        size_t numParts;

        /** @brief PNOR block size, in bytes */
        size_t blockSize;

        /** @brief PNOR size, in bytes */
        size_t pnorSize;
};

} // namespace partition
} // namespace virtual_pnor
} // namespace openpower