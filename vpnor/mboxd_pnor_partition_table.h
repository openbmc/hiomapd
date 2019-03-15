/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2018 IBM Corp. */
#pragma once

#include <limits.h>
#include "pnor_partition_defs.h"
#include "backend.h"

struct mbox_context;
struct vpnor_partition_table;

struct vpnor_partition_paths
{
    char ro_loc[PATH_MAX];
    char rw_loc[PATH_MAX];
    char prsv_loc[PATH_MAX];
    char patch_loc[PATH_MAX];
};

struct vpnor_data {
	struct vpnor_partition_table *vpnor;
	struct vpnor_partition_paths paths;
};

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Populate the path object with the default partition paths
 *
 *  @param[in/out] paths - A paths object in which to store the defaults
 *
 *  Returns 0 if the call succeeds, else a negative error code.
 */
#ifdef VIRTUAL_PNOR_ENABLED
void vpnor_default_paths(struct vpnor_partition_paths *paths);
#else
static inline void vpnor_default_paths(struct vpnor_partition_paths *paths)
{
    memset(paths, 0, sizeof(*paths));
}
#endif

#ifdef VIRTUAL_PNOR_ENABLED
/** @brief Create a virtual PNOR partition table.
 *
 *  @param[in] backend - The backend context pointer
 *  @param[in] paths - A paths object pointer to initialise vpnor
 *
 *  This API should be called before calling any other APIs below. If a table
 *  already exists, this function will not do anything further. This function
 *  will not do anything if the context is NULL.
 *
 *  The content of the paths object is copied out, ownership is retained by the
 *  caller.
 *
 *  Returns 0 if the call succeeds, else a negative error code.
 */

int vpnor_init(struct backend *backend,
	       const struct vpnor_partition_paths *paths);

/** @brief Copy bootloader partition (alongwith TOC) to LPC memory
 *
 *  @param[in] backend - The backend context pointer
 *
 *  @returns 0 on success, negative error code on failure
 */
int vpnor_copy_bootloader_partition(const struct backend *backend, void *buf,
				    uint32_t count);

/** @brief Destroy partition table, if it exists.
 *
 *  @param[in] backend - The backend context pointer
 */
void vpnor_destroy(struct backend *backend);

#ifdef __cplusplus
}
#endif

#endif
