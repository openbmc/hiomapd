/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2018 IBM Corp. */

#ifndef MBOXD_MSG_H
#define MBOXD_MSG_H

#include "common.h"
#include "mbox.h"

#define NO_BMC_EVENT			false
#define SET_BMC_EVENT			true

int set_bmc_events(struct mbox_context *context, uint8_t bmc_event,
		   bool write_back);
int clr_bmc_events(struct mbox_context *context, uint8_t bmc_event,
		   bool write_back);
int dispatch_mbox(struct mbox_context *context);
int init_mbox_dev(struct mbox_context *context);
void free_mbox_dev(struct mbox_context *context);

#endif /* MBOXD_MSG_H */
