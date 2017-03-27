/*
 * Copyright 2016 IBM
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef MBOXD_MSG_H
#define MBOXD_MSG_H

#define NO_BMC_EVENT	false
#define SET_BMC_EVENT	true

struct mbox_msg {
	uint8_t command;
	uint8_t seq;
	uint8_t args[MBOX_ARGS_BYTES];
	uint8_t response;
};

union mbox_regs {
	char raw[MBOX_REG_BYTES];
	struct mbox_msg msg;
};

int set_bmc_events(struct mbox_context *context, uint8_t bmc_event,
		   bool write_back);
int clr_bmc_events(struct mbox_context *context, uint8_t bmc_event,
		   bool write_back);
int dispatch_mbox(struct mbox_context *context);
int init_mbox_dev(struct mbox_context *context);

#endif /* MBOXD_MSG_H */
