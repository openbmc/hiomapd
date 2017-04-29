#pragma once

#include "mboxd_flash_partition.hpp"

/** @brief Create partition table
 *
 *  @returns 0 on success, -1 on fail
 */
extern "C" int createPartition();

/** @brief Get partition table size
 *
 *  @returns size_t - partition table size
 */
extern "C" size_t getPartitionSize();

/** @brief Get partition table header
 *
 *  @returns const struct partition_hdr* - pointer to header
 */
extern "C" const struct partition_hdr* getPartitionHeader();

/** @brief Get partition table entries
 *
 *  @returns const struct partition_entry* - pointer to entries
 */
extern "C" const struct partition_entry* getAllPartitionEntries(size_t* sz);

/** @brief Destroy partition table
 *
 *  @returns 0 on success, -1 on fail
 */

extern "C" int destroyPartition();

/** @brief Return partition entry corresponding to flash offset
 *
 *  @param[in] offset - flash offset
 *
 *  @returns const partition_entry* - const pointer to partition_entry
 */
extern "C" const struct partition_entry* getPartitionEntry(const off_t offset);
