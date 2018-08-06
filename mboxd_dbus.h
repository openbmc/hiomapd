/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2018 IBM Corp. */

#ifndef MBOXD_DBUS_H
#define MBOXD_DBUS_H

#include "dbus.h"
#include "mbox.h"

int mboxd_dbus_init(struct mbox_context *context);
void mboxd_dbus_free(struct mbox_context *context);

int control_legacy_init(struct mbox_context *context);
void control_legacy_free(struct mbox_context *context);

/* Control actions */
int control_ping(struct mbox_context *context);
int control_daemon_state(struct mbox_context *context);
int control_lpc_state(struct mbox_context *context);
int control_reset(struct mbox_context *context);
int control_kill(struct mbox_context *context);
int control_modified(struct mbox_context *context);
int control_suspend(struct mbox_context *context);
int control_resume(struct mbox_context *context, bool modified);

#endif /* MBOXD_DBUS_H */
