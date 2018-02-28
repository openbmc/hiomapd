/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2018 IBM Corp. */
#pragma once

#ifdef VIRTUAL_PNOR_ENABLED

#include <limits.h>
#include "pnor_partition_defs.h"

struct mbox_context;
struct vpnor_partition_table;

struct vpnor_partition_paths
{
    char ro_loc[PATH_MAX];
    char rw_loc[PATH_MAX];
    char prsv_loc[PATH_MAX];
    char patch_loc[PATH_MAX];
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
 *
 *  Returns 0 if the call succeeds, else a negative error code.
 */
int init_vpnor(struct mbox_context *context);

/** @brief Create a virtual PNOR partition table.
 *
 *  @param[in] context - mbox context pointer
 *  @param[in] path - location of the partition file
 *
 *  This API is same as above one but it reads the partition file from
 *  from the given location(path).
 *
 *  Returns 0 if the call succeeds, else a negative error code.
 */

int vpnor_create_partition_table_from_path(struct mbox_context *context,
                                           const char* path);

/** @brief Copy bootloader partition (alongwith TOC) to LPC memory
 *
 *  @param[in] context - mbox context pointer
 *
 *  @returns 0 on success, negative error code on failure
 */
int vpnor_copy_bootloader_partition(const struct mbox_context *context);

/** @brief Destroy partition table, if it exists.
 *
 *  @param[in] context - mbox context pointer
 */
void destroy_vpnor(struct mbox_context *context);

#ifdef __cplusplus
}
#endif

#endif
