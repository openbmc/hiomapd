#pragma once

#ifdef VIRTUAL_PNOR_ENABLED

#include <limits.h>
#include "pnor_partition_defs.h"

struct mbox_context;
struct vpnor_partition_table;

struct vpnor_partition_paths
{
    char ro_loc[PATH_MAX];
};

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Create a virtual PNOR partition table.
 *
 *  @param[in] context - mbox context pointer
 *
 *  This API should be called before calling any other APIs below. If a table
 *  already exists, this function will not do anything further. This function
 *  will not do anything if the context is NULL.
 */
void vpnor_create_partition_table(struct mbox_context *context);


/** @brief Get partition table size, in blocks (1 block = 4KB)
 *
 *  @param[in] context - mbox context pointer
 *
 *  @returns partition table size. 0 if no table exists, or if the
 *           context is NULL.
 */
size_t vpnor_get_partition_table_size(const struct mbox_context *context);


/** @brief Get virtual PNOR partition table with host-compatible byte-ordering
 *
 *  @param[in] context - mbox context pointer
 *
 *  @returns pointer to partition table, NULL if partition table doesn't
 *           exist or if the context is NULL.
 */
const struct pnor_partition_table* vpnor_get_partition_table(
				       const struct mbox_context *context);


/** @brief Get a specific partition, by PNOR offset. The returned
 *         partition is such that the offset lies in that partition's
 *         boundary.
 *
 *  @param[in] context - mbox context pointer
 *  @param[in] offset - PNOR offset
 *
 *  @returns const pointer to pnor_partition, NULL if partition table doesn't
 *           exist or if the context is NULL
 */
const struct pnor_partition* vpnor_get_partition(
				const struct mbox_context *context,
				const size_t offset);


/** @brief Destroy partition table, if it exists.
 *
 *  @param[in] context - mbox context pointer
 */

void vpnor_destroy_partition_table(struct mbox_context *context);

#ifdef __cplusplus
}
#endif

#endif
