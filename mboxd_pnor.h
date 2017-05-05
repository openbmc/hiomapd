#pragma once

#include <sys/types.h>
#include "mbox.h"

/** @brief Copy the data from the pnor file to the LPC.
 *
 *  @param[in] context - mbox context pointer
 *  @param[in] offset - offset to copy from (bytes)
 *  @param[in] mem - buffer to copy into
 *  @param[in] size - number of bytes to copy
 *
 *  @returns 0 on success otherwise negative error code
 */

#ifdef __cplusplus
extern "C" {
#endif

int copy_pnor(struct mbox_context* context, uint32_t offset,
              void* mem,
              uint32_t size);

#ifdef __cplusplus
}
#endif
