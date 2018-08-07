/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2018 IBM Corp. */

#ifndef PROTOCOL_H
#define PROTOCOL_H

struct mbox_context;

/*
 * The GET_MBOX_INFO command is special as it can change the interface based on
 * negotiation. As such we need to accommodate all response types
 */
struct protocol_get_info {
	struct {
		uint8_t api_version;
	} req;
	struct {
		uint8_t api_version;
		union {
			struct {
				uint16_t read_window_size;
				uint16_t write_window_size;
			} v1;
			struct {
				uint8_t block_size_shift;
				uint16_t timeout;
			} v2;
		};
	} resp;
};

struct protocol_ops {
	int (*reset)(struct mbox_context *context);
	int (*get_info)(struct mbox_context *context,
			struct protocol_get_info *io);
};

int protocol_init(struct mbox_context *context);
void protocol_free(struct mbox_context *context);

int protocol_negotiate_version(struct mbox_context *context, uint8_t requested);

/* Protocol v1 */
int protocol_v1_reset(struct mbox_context *context);
int protocol_v1_get_info(struct mbox_context *context,
			 struct protocol_get_info *io);

/* Protocol v2 */
int protocol_v2_get_info(struct mbox_context *context,
			 struct protocol_get_info *io);

#endif /* PROTOCOL_H */
