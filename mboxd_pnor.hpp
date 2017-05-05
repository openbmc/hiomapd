#pragma once

#include <sys/types.h>
#include "mbox.h"

extern "C" int copy_pnor(struct mbox_context* context, uint32_t offset,
                         void* mem,
                         uint32_t size);

