#pragma once

#include <sys/types.h>
#include "mbox.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * copy_flash() - Copy data from the virtual pnor into a provided buffer
 * @context:    The mbox context pointer
 * @offset:     The pnor offset to copy from (bytes)
 * @mem:        The buffer to copy into (must be of atleast 'size' bytes)
 * @size:       The number of bytes to copy
 *
 * Return:      0 on success otherwise negative error code
 */
int copy_flash(struct mbox_context *context, uint32_t offset, void *mem,
               uint32_t size);

#ifdef __cplusplus
}
#endif
