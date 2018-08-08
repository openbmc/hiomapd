// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2018 IBM Corp.
#include <errno.h>
#include <stdlib.h>

#include "dbus.h"
#include "mbox.h"
#include "mboxd_flash.h"
#include "mboxd_lpc.h"
#include "mboxd_msg.h"
#include "mboxd_windows.h"

int control_ping(struct mbox_context *context)
{
	return 0;
}

int control_daemon_state(struct mbox_context *context)
{
	return (context->state & STATE_SUSPENDED) ?
		DAEMON_STATE_SUSPENDED : DAEMON_STATE_ACTIVE;
}

int control_lpc_state(struct mbox_context *context)
{
	if ((context->state & MAPS_MEM) && !(context->state & MAPS_FLASH)) {
		return LPC_STATE_MEM;
	} else if (!(context->state & MAPS_MEM) &&
		   (context->state & MAPS_FLASH)) {
		return LPC_STATE_FLASH;
	}

	return LPC_STATE_INVALID;
}

int control_reset(struct mbox_context *context)
{
	int rc;

	/* We don't let the host access flash if the daemon is suspened */
	if (context->state & STATE_SUSPENDED) {
		return -EBUSY;
	}

	/*
	 * This will close (and flush) the current window and reset the lpc bus
	 * mapping back to flash, or memory in case we're using a virtual pnor.
	 * Better set the bmc event to notify the host of this.
	 */
	reset_all_windows(context, SET_BMC_EVENT);
	rc = reset_lpc(context);
	if (rc < 0) {
		return rc;
	}

	return 0;
}

int control_kill(struct mbox_context *context)
{
	context->terminate = 1;

	MSG_INFO("DBUS Kill - Exiting...\n");

	return 0;
}

int control_modified(struct mbox_context *context)
{
	/* Flash has been modified - can no longer trust our erased bytemap */
	set_flash_bytemap(context, 0, context->flash_size, FLASH_DIRTY);

	/* Force daemon to reload all windows -> Set BMC event to notify host */
	reset_all_windows(context, SET_BMC_EVENT);

	return 0;
}

int control_suspend(struct mbox_context *context)
{
	int rc;

	if (context->state & STATE_SUSPENDED) {
		/* Already Suspended */
		return 0;
	}

	/* Nothing to check - Just set the bit to notify the host */
	rc = set_bmc_events(context, BMC_EVENT_FLASH_CTRL_LOST, SET_BMC_EVENT);
	if (rc < 0) {
		return rc;
	}

	context->state |= STATE_SUSPENDED;

	return rc;
}

int control_resume(struct mbox_context *context, bool modified)
{
	int rc;

	if (!(context->state & STATE_SUSPENDED)) {
		/* We weren't suspended... */
		return 0;
	}

	if (modified) {
		/* Call the flash modified handler */
		control_modified(context);
	}

	/* Clear the bit and send the BMC Event to the host */
	rc = clr_bmc_events(context, BMC_EVENT_FLASH_CTRL_LOST, SET_BMC_EVENT);
	if (rc < 0) {
		return rc;
	}
	context->state &= ~STATE_SUSPENDED;

	return rc;
}
