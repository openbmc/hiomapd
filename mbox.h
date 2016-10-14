/* Copyright 2016 IBM
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *
 */

#define MBOX_C_RESET_STATE 0x01
#define MBOX_C_GET_MBOX_INFO 0x02
#define MBOX_C_GET_FLASH_INFO 0x03
#define MBOX_C_READ_WINDOW 0x04
#define MBOX_C_CLOSE_WINDOW 0x05
#define MBOX_C_WRITE_WINDOW 0x06
#define MBOX_C_WRITE_DIRTY 0x07
#define MBOX_C_WRITE_FENCE 0x08
#define MBOX_C_ACK 0x09
#define MBOX_C_COMPLETED_COMMANDS 0x0a

#define MBOX_R_SUCCESS 0x01
#define MBOX_R_PARAM_ERROR 0x02
#define MBOX_R_WRITE_ERROR 0x03
#define MBOX_R_SYSTEM_ERROR 0x4
#define MBOX_R_TIMEOUT 0x05

#define MBOX_HOST_PATH "/dev/aspeed-mbox"
#define MBOX_HOST_TIMEOUT_SEC 1
#define MBOX_DATA_BYTES 11
#define MBOX_REG_BYTES 16
#define MBOX_HOST_BYTE 14
#define MBOX_BMC_BYTE 15

struct mbox_msg {
	uint8_t command;
	uint8_t seq;
	uint8_t data[MBOX_DATA_BYTES];
	uint8_t response;
};

union mbox_regs {
	char raw[MBOX_REG_BYTES];
	struct mbox_msg msg;
};


