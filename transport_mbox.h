/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2018 IBM Corp. */

#ifndef MBOXD_MSG_H
#define MBOXD_MSG_H

#include "common.h"
#include "mbox.h"

int transport_mbox_dispatch(struct mbox_context *context);
int transport_mbox_init(struct mbox_context *context);
void free_mbox_dev(struct mbox_context *context);

#endif /* MBOXD_MSG_H */
