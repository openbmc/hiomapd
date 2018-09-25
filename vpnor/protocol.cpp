// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2018 IBM Corp.
#include "config.h"

extern "C" {
#include "mboxd.h"
#include "protocol.h"
#include "vpnor/protocol.h"
}

#include "vpnor/pnor_partition_table.hpp"

/* XXX: Maybe this should be a method on a class? */
static bool vpnor_partition_is_readonly(const pnor_partition &part)
{
    return part.data.user.data[1] & PARTITION_READONLY;
}

typedef int (*create_window_fn)(struct mbox_context *context,
                                struct protocol_create_window *io);

static int generic_vpnor_create_window(struct mbox_context *context,
                                       struct protocol_create_window *io,
                                       create_window_fn create_window)
{
    if (io->req.ro)
    {
        return create_window(context, io);
    }

    /* Only allow write windows on regions mapped by the ToC as writeable */
    size_t offset = io->req.offset;
    offset <<= context->backend->block_size_shift;
    try
    {
        const pnor_partition &part = context->backend->vpnor->table->partition(offset);
        if (vpnor_partition_is_readonly(part))
        {
            return -EPERM;
        }
    }
    catch (const openpower::virtual_pnor::UnmappedOffset &e)
    {
        /*
         * Writes to unmapped areas are not meaningful, so deny the request.
         * This removes the ability for a compromised host to abuse unused
         * space if any data was to be persisted (which it isn't).
         */
        return -EACCES;
    }

    return create_window(context, io);
}

int protocol_v1_vpnor_create_window(struct mbox_context *context,
                                    struct protocol_create_window *io)
{
    return generic_vpnor_create_window(context, io, protocol_v1_create_window);
}

int protocol_v2_vpnor_create_window(struct mbox_context *context,
                                    struct protocol_create_window *io)
{
    return generic_vpnor_create_window(context, io, protocol_v2_create_window);
}
