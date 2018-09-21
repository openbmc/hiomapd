/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2018 IBM Corp. */
#ifndef VPNOR_PROTOCOL_H
#define VPNOR_PROTOCOL_H

#include "protocol.h"

/* Protocol v1 */
int protocol_v1_vpnor_create_window(struct mbox_context *context,
                                    struct protocol_create_window *io);

/* Protocol v2 */
int protocol_v2_vpnor_create_window(struct mbox_context *context,
			            struct protocol_create_window *io);

int protocol_negotiate_version_vpnor(struct mbox_context *context, uint8_t requested);

#endif /* VPNOR_PROTOCOL_H */
