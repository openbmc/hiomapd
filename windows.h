/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2018 IBM Corp. */

#ifndef WINDOWS_H
#define WINDOWS_H

#define WINDOWS_NO_FLUSH	false
#define WINDOWS_WITH_FLUSH	true

#include "mbox.h"

/* Initialisation Functions */
int windows_init(struct mbox_context *context);
void windows_free(struct mbox_context *context);
/* Write From Window Functions */
int window_flush_v1(struct mbox_context *context,
			 uint32_t offset_bytes, uint32_t count_bytes);
int window_flush(struct mbox_context *context, uint32_t offset,
		      uint32_t count, uint8_t type);
/* Window Management Functions */
void windows_alloc_dirty_bytemap(struct mbox_context *context);
int window_set_bytemap(struct mbox_context *context, struct window_context *cur,
		       uint32_t offset, uint32_t size, uint8_t val);
void windows_close_current(struct mbox_context *context, bool set_bmc_event,
			  uint8_t flags);
void reset_window(struct mbox_context *context, struct window_context *window);
void reset_all_windows(struct mbox_context *context, bool set_bmc_event);
struct window_context *find_oldest_window(struct mbox_context *context);
struct window_context *find_largest_window(struct mbox_context *context);
struct window_context *search_windows(struct mbox_context *context,
				      uint32_t offset, bool exact);
int create_map_window(struct mbox_context *context,
		      struct window_context **this_window,
		      uint32_t offset, bool exact);

#endif /* WINDOWS_H */
