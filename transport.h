/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2018 IBM Corp. */

#ifndef TRANSPORT_H
#define TRANSPORT_H

#include "mbox.h"

struct transport_ops {
	int (*flush_events)(struct mbox_context *context);
};

#endif /* TRANSPORT_H */
