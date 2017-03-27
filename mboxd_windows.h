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

#ifndef MBOXD_WINDOWS_H
#define MBOXD_WINDOWS_H

#define NO_FLUSH	false
#define WITH_FLUSH	true

/* Initialisation Functions */
void init_window_state(struct window_context *window, uint32_t size);
int init_window_mem(struct mbox_context *context);
/* Write From Window Functions */
int write_from_window_v1(struct mbox_context *context,
			 uint32_t offset_bytes, uint32_t count_bytes);
int write_from_window(struct mbox_context *context, uint32_t offset,
		      uint32_t count, uint8_t type);
/* Window Management Functions */
void alloc_window_dirty_bytemap(struct mbox_context *context);
int set_window_bytemap(struct mbox_context *context, struct window_context *cur,
		       uint32_t offset, uint32_t size, uint8_t val);
void close_current_window(struct mbox_context *context, bool set_bmc_event,
			  uint8_t flags);
void reset_window(struct mbox_context *context, struct window_context *window);
void reset_all_windows(struct mbox_context *context, bool set_bmc_event);
struct window_context *find_oldest_window(struct mbox_context *context);
struct window_context *search_windows(struct mbox_context *context,
				      uint32_t offset, bool exact);
int create_map_window(struct mbox_context *context,
		      struct window_context **this_window,
		      uint32_t offset, bool exact);

#endif /* MBOXD_WINDOWS_H */
