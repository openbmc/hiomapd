// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2018 IBM Corp.
#include "config.h"

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <systemd/sd-bus.h>

#include "common.h"
#include "dbus.h"
#include "mboxd.h"
#include "protocol.h"
#include "transport.h"

static int transport_dbus_property_update(struct mbox_context *context,
					  uint8_t events)
{
	/* Two properties plus a terminating NULL */
	char *props[3] = { 0 };
	int i = 0;

	if (events & BMC_EVENT_FLASH_CTRL_LOST) {
		props[i++] = "FlashControlLost";
	}

	if (events & BMC_EVENT_DAEMON_READY) {
		props[i++] = "DaemonReady";
	}

	return sd_bus_emit_properties_changed_strv(context->bus,
						 MBOX_DBUS_OBJECT,
						 /* FIXME: Hard-coding v2 */
						 MBOX_DBUS_PROTOCOL_IFACE_V2,
						 props);
}

static int transport_dbus_set_events(struct mbox_context *context,
				     uint8_t events)
{
	int rc;

	rc = transport_dbus_property_update(context, events);
	if (rc < 0) {
		return rc;
	}

	/*
	 * Handle signals - edge triggered, only necessary when they're
	 * asserted
	 */
	if (events & BMC_EVENT_WINDOW_RESET) {
		sd_bus_message *m = NULL;

		rc = sd_bus_message_new_signal(context->bus, &m,
					       MBOX_DBUS_OBJECT,
					       /* FIXME: Hard-coding v2 */
					       MBOX_DBUS_PROTOCOL_IFACE_V2,
					       "WindowReset");
		if (rc < 0) {
			return rc;
		}

		rc = sd_bus_send(context->bus, m, NULL);
		if (rc < 0) {
			return rc;
		}
	}

	if (events & BMC_EVENT_REBOOT) {
		sd_bus_message *m = NULL;

		rc = sd_bus_message_new_signal(context->bus, &m,
					       MBOX_DBUS_OBJECT,
					       /* FIXME: Hard-coding v2 */
					       MBOX_DBUS_PROTOCOL_IFACE_V2,
					       "ProtocolReset");
		if (rc < 0) {
			return rc;
		}

		rc = sd_bus_send(context->bus, m, NULL);
		if (rc < 0) {
			return rc;
		}
	}

	return 0;
}

static int transport_dbus_clear_events(struct mbox_context *context,
				       uint8_t events)
{
	/* No need to emit signals for ackable events on clear */
	return transport_dbus_property_update(context, events);
}

static const struct transport_ops transport_dbus_ops = {
	.set_events = transport_dbus_set_events,
	.clear_events = transport_dbus_clear_events,
};

static int transport_dbus_reset(sd_bus_message *m, void *userdata,
				     sd_bus_error *ret_error)
{
	struct mbox_context *context = userdata;
	sd_bus_message *n;
	int rc;

	if (!context) {
		MSG_ERR("DBUS Internal Error\n");
		return -EINVAL;
	}

	rc = context->protocol->reset(context);
	if (rc < 0) {
		return rc;
	}

	rc = sd_bus_message_new_method_return(m, &n);
	if (rc < 0) {
		MSG_ERR("sd_bus_message_new_method_return failed: %d\n", rc);
		return rc;
	}

	return sd_bus_send(NULL, n, NULL);
}

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
	/* A bit messy, but we need the correct event mask */
	protocol_events_set(context, context->bmc_events);

	rc = sd_bus_message_new_method_return(m, &n);
	if (rc < 0) {
		MSG_ERR("sd_bus_message_new_method_return failed: %d\n", rc);
		return rc;
	}

	if (API_VERSION_2 != io.resp.api_version) {
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

static int transport_dbus_ack(sd_bus_message *m, void *userdata,
			      sd_bus_error *ret_error)
{
	struct mbox_context *context = userdata;
	struct protocol_ack io;
	sd_bus_message *n;
	int rc;

	if (!context) {
		MSG_ERR("DBUS Internal Error\n");
		return -EINVAL;
	}

	rc = sd_bus_message_read_basic(m, 'y', &io.req.flags);
	if (rc < 0) {
		MSG_ERR("DBUS error reading message: %s\n", strerror(-rc));
		return rc;
	}

	rc = context->protocol->ack(context, &io);
	if (rc < 0) {
		return rc;
	}

	rc = sd_bus_message_new_method_return(m, &n);
	if (rc < 0) {
		MSG_ERR("sd_bus_message_new_method_return failed: %d\n", rc);
		return rc;
	}

	return sd_bus_send(NULL, n, NULL);
}

static int transport_dbus_get_property(sd_bus *bus,
				       const char *path,
				       const char *interface,
				       const char *property,
				       sd_bus_message *reply,
				       void *userdata,
				       sd_bus_error *ret_error)
{
	struct mbox_context *context = userdata;
	bool value;

	assert(!strcmp(MBOX_DBUS_OBJECT, path));
	assert(!strcmp(MBOX_DBUS_PROTOCOL_IFACE_V2, interface));

	if (!strcmp("FlashControlLost", property)) {
		value = context->bmc_events & BMC_EVENT_FLASH_CTRL_LOST;
	} else if (!strcmp("DaemonReady", property)) {
		value = context->bmc_events & BMC_EVENT_DAEMON_READY;
	} else {
		MSG_ERR("Unknown DBus property: %s\n", property);
		return -EINVAL;
	}

	return sd_bus_message_append(reply, "b", value);
}

static const sd_bus_vtable protocol_unversioned_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_METHOD("Reset", NULL, NULL, &transport_dbus_reset,
		      SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("GetInfo", "y", "yyq", &transport_dbus_get_info,
		      SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("Ack", "y", NULL, &transport_dbus_ack,
		      SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_VTABLE_END
};

static const sd_bus_vtable protocol_v2_vtable[] = {
	SD_BUS_VTABLE_START(0),
	SD_BUS_METHOD("Reset", NULL, NULL, &transport_dbus_reset,
		      SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("GetInfo", "y", "yyq", &transport_dbus_get_info,
		      SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_METHOD("Ack", "y", NULL, &transport_dbus_ack,
		      SD_BUS_VTABLE_UNPRIVILEGED),
	SD_BUS_PROPERTY("FlashControlLost", "b", transport_dbus_get_property,
			0, /* Just a pointer to struct mbox_context */
			SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
	SD_BUS_PROPERTY("DaemonReady", "b", transport_dbus_get_property,
			0, /* Just a pointer to struct mbox_context */
			SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
	SD_BUS_SIGNAL("ProtocolReset", NULL, 0),
	SD_BUS_SIGNAL("WindowReset", NULL, 0),
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
					MBOX_DBUS_PROTOCOL_IFACE_V2,
					protocol_v2_vtable, context);

	return rc;
}

#define __unused __attribute__((unused))
void transport_dbus_free(struct mbox_context *context __unused)
{
	return;
}
