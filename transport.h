/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2018 IBM Corp. */

#ifndef TRANSPORT_H
#define TRANSPORT_H

struct mbox_context;

struct transport_ops {
	int (*set_events)(struct mbox_context *context, uint8_t events);
	int (*clear_events)(struct mbox_context *context, uint8_t events);
};

#endif /* TRANSPORT_H */
