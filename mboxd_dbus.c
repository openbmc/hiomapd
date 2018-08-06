// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2018 IBM Corp.

#define _GNU_SOURCE
#include <systemd/sd-bus.h>

#include "common.h"
#include "dbus.h"
#include "mbox.h"
#include "mboxd_dbus.h"

int mboxd_dbus_init(struct mbox_context *context)
{
	int rc;

	rc = sd_bus_default_system(&context->bus);
	if (rc < 0) {
		MSG_ERR("Failed to connect to the system bus: %s\n",
			strerror(-rc));
		return rc;
	}

	rc = control_legacy_init(context);
	if (rc < 0) {
		MSG_ERR("Failed to initialise legacy DBus interface: %s\n",
			strerror(-rc));
		return rc;
	}

	rc = sd_bus_get_fd(context->bus);
	if (rc < 0) {
		MSG_ERR("Failed to get bus fd: %s\n", strerror(-rc));
		return rc;
	}

	context->fds[DBUS_FD].fd = rc;

	return 0;
}

void mboxd_dbus_free(struct mbox_context *context)
{
	control_legacy_free(context);
	sd_bus_unref(context->bus);
}
