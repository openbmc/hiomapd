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

#ifndef MBOX_DBUS_H
#define MBOX_DBUS_H

#define DBUS_NAME		"org.openbmc.mboxd"
#define DOBJ_NAME		"/org/openbmc/mboxd"

/* Commands */
#define DBUS_C_PING		0x00
#define	DBUS_C_STATUS		0x01
#define DBUS_C_RESET		0x02
#define DBUS_C_SUSPEND		0x03
#define DBUS_C_RESUME		0x04
#define DBUS_C_MODIFIED		0x05
#define DBUS_C_KILL		0x06

/* Command Args */
/* Resume */
#define RESUME_NOT_MODIFIED	0x00
#define RESUME_FLASH_MODIFIED	0x01

/* Return Values */
#define DBUS_SUCCESS		0x00 /* Command Succeded */
#define E_DBUS_INTERNAL		0x01 /* Internal DBUS Error */
#define E_DBUS_INVAL		0x02 /* Invalid Command */
#define E_DBUS_REJECTED		0x03 /* Daemon Rejected Request */
#define E_DBUS_HARDWARE		0x04 /* BMC Hardware Error */
#define E_DBUS_NOOP		0x05 /* Operation Would Have No Effect */

/* Response Args */
/* Status */
#define STATUS_ACTIVE		0x00
#define STATUS_SUSPENDED	0x01

struct mbox_dbus_msg {
	uint8_t cmd;
	size_t num_args;
	uint8_t *args;
};

#endif /* MBOX_DBUS_H */
