/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2018 IBM Corp. */

#ifndef MBOXD_DBUS_H
#define MBOXD_DBUS_H

int mboxd_dbus_init(struct mbox_context *context);
void mboxd_dbus_free(struct mbox_context *context);

#endif /* MBOXD_DBUS_H */
