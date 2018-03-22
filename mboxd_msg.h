/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2018 IBM Corp. */

#ifndef MBOXD_MSG_H
#define MBOXD_MSG_H

#include "common.h"
#include "mbox.h"

/* Estimate as to how long (milliseconds) it takes to access a MB from flash */
#define FLASH_ACCESS_MS_PER_MB		8000

#define NO_BMC_EVENT			false
#define SET_BMC_EVENT			true

struct mbox_msg {
	uint8_t command;
	uint8_t seq;
	uint8_t args[MBOX_ARGS_BYTES];
	uint8_t response;
};

union mbox_regs {
	uint8_t raw[MBOX_REG_BYTES];
	struct mbox_msg msg;
};

int set_bmc_events(struct mbox_context *context, uint8_t bmc_event,
		   bool write_back);
int clr_bmc_events(struct mbox_context *context, uint8_t bmc_event,
		   bool write_back);
int dispatch_mbox(struct mbox_context *context);
int init_mbox_dev(struct mbox_context *context);
void free_mbox_dev(struct mbox_context *context);

#endif /* MBOXD_MSG_H */
