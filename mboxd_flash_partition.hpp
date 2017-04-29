#pragma once

#include <string>
#include <vector>
#include "flash_partition.h"

namespace openpower
{
namespace flash
{
namespace partition
{

using Entries = std::vector<partition_entry>;

/** @class Table
 *  @brief Generates host flash partition table
 *
 *  Generates host flash partition table upon construction. Reads
 *  virtual flash partition information to prepare the partition table.
 */
class Table
{
    public:
        Table();
        Table(const Table&) = delete;
        Table& operator=(const Table&) = delete;
        Table(Table&&) = delete;
        Table& operator=(Table&&) = delete;
        ~Table() = default;

        /** @brief Return size of partition table
         *
         *  @returns size_t - size of partition table
         */
        size_t size() const
        {
            return sz;
        }

        /** @brief Return partition header
         *
         *  @returns const partition_hdr& - const reference to partition header
         */
        const partition_hdr& hdr() const
        {
            return header;
        }

        /** @brief Return partition entries
         *
         *  @returns const std::vector<partition_entry>& - reference to list
         *           of partition entries
         */
        const Entries& entryList() const
        {
            return entries;
        }

        /** @brief Return partition entry corresponding to flash offset
         *
         *  @param[in] offset - flash offset
         *
         *  @returns const partition_entry* - const pointer to partition_entry
         */
        const partition_entry* entry(const off_t offset) const;

    private:
        /** @brief Generates flash partition entries
         *
         *  @returns std::vector<partition_entry> - list of entries
         */
        Entries genEntries();

        /** @brief Generates flash partition header
         */
        void genHeader();

        /** @brief Aligns partition table offsets to block-size (4096 bytes)
         *
         *  @param[in] entries - list of entries
         */
        void align(Entries& entries);

        /** @brief Stores partition entry specifc information (ECC, ReadOnly) in
         *         the table.
         *
         *  @param[in] line - A line of text containing partition information.
         *  @param[in] entry - partition entry
         */
        void applyProperties(const std::string& line,
                             partition_entry& entry);

        /** @brief Size of partition table */
        size_t sz;

        /** @brief Partition table header */
        partition_hdr header;

        /** @brief Pointer to partition entries */
        Entries entries;
};

}
}
}
