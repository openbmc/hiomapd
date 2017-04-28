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
