// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2018 IBM Corp.
#include "config.h"

#include <errno.h>
#include <systemd/sd-bus.h>

#include "common.h"
#include "dbus.h"
#include "mboxd.h"
#include "protocol.h"
#include "transport.h"

static int transport_dbus_set_events(struct mbox_context *context,
				     uint8_t events)
{
	/* FIXME ! */
	MSG_ERR("%s is unimplemented!\n", __func__);
	return 0;
}

static int transport_dbus_clear_events(struct mbox_context *context,
				       uint8_t events)
{
	/* FIXME ! */
	MSG_ERR("%s is unimplemented!\n", __func__);
	return 0;
}

static const struct transport_ops transport_dbus_ops = {
	.set_events = transport_dbus_set_events,
	.clear_events = transport_dbus_clear_events,
};

static int transport_dbus_get_info(sd_bus_message *m, void *userdata,
					sd_bus_error *ret_error)
{
	struct mbox_context *context = userdata;
	struct protocol_get_info io;
	sd_bus_message *n;
	int rc;

	if (!context) {
		MSG_ERR("DBUS Internal Error\n");
		return -EINVAL;
	}

	rc = sd_bus_message_read_basic(m, 'y', &io.req.api_version);
	if (rc < 0) {
		MSG_ERR("DBUS error reading message: %s\n", strerror(-rc));
		return rc;
	}

	rc = context->protocol->get_info(context, &io);
	if (rc < 0) {
		return rc;
	}

	/* Switch transport to DBus. This is fine as DBus signals are async */
	context->transport = &transport_dbus_ops;
	context->transport->set_events(context, context->bmc_events);

	rc = sd_bus_message_new_method_return(m, &n);
	if (rc < 0) {
		MSG_ERR("sd_bus_message_new_method_return failed: %d\n", rc);
		return rc;
	}

	if (2 != io.resp.api_version) {
		MSG_ERR("Unsupported protocol version for DBus transport: %d\n",
			io.resp.api_version);
		return rc;
	}

	rc = sd_bus_message_append(n, "yyq",
				   io.resp.api_version,
				   io.resp.v2.block_size_shift,
				   io.resp.v2.timeout);
	if (rc < 0) {
		MSG_ERR("sd_bus_message_append failed!\n");
		return rc;
	}

	return sd_bus_send(NULL, n, NULL);
}

static const sd_bus_vtable protocol_unversioned_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_METHOD("GetInfo", "y", "yyq", &transport_dbus_get_info,
		      SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_VTABLE_END
};

static const sd_bus_vtable protocol_v2_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_METHOD("GetInfo", "y", "yyq", &transport_dbus_get_info,
		      SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_VTABLE_END
};

int transport_dbus_init(struct mbox_context *context)
{
	int rc;

	rc = sd_bus_add_object_vtable(context->bus, NULL,
					MBOX_DBUS_OBJECT,
					MBOX_DBUS_PROTOCOL_IFACE,
					protocol_unversioned_vtable,
					context);
	if (rc < 0) {
		return rc;
	}

	rc = sd_bus_add_object_vtable(context->bus, NULL,
					MBOX_DBUS_OBJECT,
	/* TODO: Make this clearer? */	MBOX_DBUS_PROTOCOL_IFACE ".v2",
					protocol_v2_vtable, context);

	return rc;
}

#define __unused __attribute__((unused))
void transport_dbus_free(struct mbox_context *context __unused)
{
	return;
}
