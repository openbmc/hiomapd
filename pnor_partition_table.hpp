#pragma once

#include <vector>
#include <experimental/filesystem>
#include "pnor_partition_defs.h"

namespace fs = std::experimental::filesystem;

namespace openpower
{
namespace virtual_pnor
{
namespace partition
{

/** @class Table
 *  @brief Generates virtual PNOR partition table.
 *
 *  Generates virtual PNOR partition table upon construction. Reads
 *  the PNOR information generated by this script :
 *  github.com/openbmc/openpower-pnor-code-mgmt/blob/master/generate-squashfs.
 *
 *  This script generates a minimalistic table-of-contents (toc) file and
 *  individual files to represent various partitions that are of interest -
 *  these help form the "virtual" PNOR, which is typically a subset of the full
 *  PNOR image.
 *  The script stores these in a well-known location on the PNOR.
 *  Based on this information, this class prepares the partition table whose
 *  structure is as outlined in pnor_partition.h.
 *
 *  The PNOR chip supports 4KB erase blocks - partitions need to be aligned
 *  accordingly.
 */
class Table
{
    public:
        /** @brief Constructor accepting the path of the directory
         *         that houses the PNOR partition files.
         *
         *  @param[in] directory - path of the directory housing PNOR partitions
         */
        Table(fs::path&& directory);

        Table();
        Table(const Table&) = delete;
        Table& operator=(const Table&) = delete;
        Table(Table&&) = delete;
        Table& operator=(Table&&) = delete;
        ~Table();

        /** @brief Return size of partition table
         *
         *  @returns size_t - size of partition table in blocks
         */
        size_t size() const
        {
            return sz;
        }

        /** @brief Return pointer to partition table
         *
         *  @returns const pointer to partition table
         */
        const pnor_partition_table* const table() const
        {
            return tbl;
        }

        /** @brief Return partition corresponding to PNOR offset, the offset
         *         is within returned partition.
         *
         *  @param[in] offset - PNOR offset in bytes
         *
         *  @returns const pointer to partition_entry
         */
        const pnor_partition* partition(const off_t offset) const;

    private:
        /** @brief Prepares a vector of PNOR partition structures.
         */
        void preparePartitions();

        /** @brief Prepares the PNOR header.
         */
        void prepareHeader();

        /** @brief Aligns partition offsets to the PNOR erase-block size (4KB).
         */
        void align();

        /** @brief Size of the PNOR partition table -
         *         sizeof(pnor_partition_table) +
         *         (no. of partitions * sizeof(pnor_partition)),
         *         measured in erase-blocks.
         */
        size_t sz;

        /** @brief Size of virtual PNOR image, measured in erase-blocks */
        size_t blocks;

        /** @brief Partition table header */
        pnor_partition_table* tbl;

        /** @brief Directory housing generated PNOR partition files */
        fs::path directory;

        /** @brief Number of partitions */
        size_t numParts;
};

}
}
}