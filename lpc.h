/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2018 IBM Corp. */

#ifndef LPC_H
#define LPC_H

int lpc_dev_init(struct mbox_context *context);
void free_lpc_dev(struct mbox_context *context);
int point_to_flash(struct mbox_context *context);
int point_to_memory(struct mbox_context *context);
int reset_lpc(struct mbox_context *context);

#endif /* LPC_H */
