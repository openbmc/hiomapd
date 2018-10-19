// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2018 IBM Corp.

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/signalfd.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>
#include <systemd/sd-bus.h>

#include "config.h"
#include "mboxd.h"
#include "common.h"
#include "dbus.h"
#include "control_dbus.h"
#include "backend.h"
#include "lpc.h"
#include "transport_mbox.h"
#include "transport_dbus.h"
#include "windows.h"
#include "vpnor/mboxd_pnor_partition_table.h"

const char* USAGE =
	"\nUsage: %s [-V | --version] [-h | --help] [-v[v] | --verbose] [-s | --syslog]\n"
	"\t\t[-n | --window-num <num>]\n"
	"\t\t[-w | --window-size <size>M]\n"
	"\t\t-f | --flash <size>[K|M]\n"
#ifdef VIRTUAL_PNOR_ENABLED
	"\t\t-s | --source <vpnor|path>\n\n"
#else
	"\t\t-s | --source <path>\n\n"
#endif
	"\t-v | --verbose\t\tBe [more] verbose\n"
	"\t-s | --syslog\t\tLog output to syslog (pointless without -v)\n"
	"\t-n | --window-num\tThe number of windows\n"
	"\t\t\t\t(default: fill the reserved memory region)\n"
	"\t-w | --window-size\tThe window size (power of 2) in MB\n"
	"\t\t\t\t(default: 1MB)\n"
	"\t-f | --flash\t\tSize of flash in [K|M] bytes\n\n";

static int dbus_init(struct mbox_context *context)
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

	rc = control_dbus_init(context);
	if (rc < 0) {
		MSG_ERR("Failed to initialise DBus control interface: %s\n",
			strerror(-rc));
		return rc;
	}

	rc = transport_dbus_init(context);
	if (rc < 0) {
		MSG_ERR("Failed to initialise DBus protocol interface: %s\n",
			strerror(-rc));
		return rc;
	}

	rc = sd_bus_request_name(context->bus, MBOX_DBUS_NAME,
				 SD_BUS_NAME_ALLOW_REPLACEMENT |
				 SD_BUS_NAME_REPLACE_EXISTING);
	if (rc < 0) {
		MSG_ERR("Failed to request DBus name: %s\n", strerror(-rc));
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

static void dbus_free(struct mbox_context *context)
{
	transport_dbus_free(context);
	control_dbus_free(context);
	control_legacy_free(context);
	sd_bus_unref(context->bus);
}

static int poll_loop(struct mbox_context *context)
{
	int rc = 0, i;

	/* Set POLLIN on polling file descriptors */
	for (i = 0; i < POLL_FDS; i++) {
		context->fds[i].events = POLLIN;
	}

	while (1) {
		rc = poll(context->fds, POLL_FDS, -1);

		if (rc < 0) { /* Error */
			MSG_ERR("Error from poll(): %s\n", strerror(errno));
			break; /* This should mean we clean up nicely */
		}

		/* Event on Polled File Descriptor - Handle It */
		if (context->fds[SIG_FD].revents & POLLIN) { /* Signal */
			struct signalfd_siginfo info = { 0 };

			rc = read(context->fds[SIG_FD].fd, (void *) &info,
				  sizeof(info));
			if (rc != sizeof(info)) {
				MSG_ERR("Error reading signal event: %s\n",
					strerror(errno));
			}

			MSG_DBG("Received signal: %d\n", info.ssi_signo);
			switch (info.ssi_signo) {
			case SIGINT:
			case SIGTERM:
				MSG_INFO("Caught Signal - Exiting...\n");
				context->terminate = true;
				break;
			case SIGHUP:
				/* Host didn't request reset -> Notify it */
				if (windows_reset_all(context)) {
				       rc = protocol_events_set(context,
						     BMC_EVENT_WINDOW_RESET);
				       if (rc < 0) {
					      MSG_ERR("Failed to notify host of reset, expect host-side corruption\n");
					      break;
				       }
				}
				rc = context->backend->lpc_reset(context);
				if (rc < 0) {
					MSG_ERR("WARNING: Failed to point the "
						"LPC bus back to flash on "
						"SIGHUP\nIf the host requires "
						"this expect problems...\n");
				}
				break;
			default:
				MSG_ERR("Unhandled Signal: %d\n",
					info.ssi_signo);
				break;
			}
		}
		if (context->fds[DBUS_FD].revents & POLLIN) { /* DBUS */
			while ((rc = sd_bus_process(context->bus, NULL)) > 0) {
				MSG_DBG("DBUS Event\n");
			}
			if (rc < 0) {
				MSG_ERR("Error handling DBUS event: %s\n",
						strerror(-rc));
			}
		}
		if (context->terminate) {
			break; /* This should mean we clean up nicely */
		}
		if (context->fds[MBOX_FD].revents & POLLIN) { /* MBOX */
			MSG_DBG("MBOX Event\n");
			rc = transport_mbox_dispatch(context);
			if (rc < 0) {
				MSG_ERR("Error handling MBOX event\n");
			}
		}
	}

	/* Best to reset windows and the lpc mapping for safety */
	/* Host didn't request reset -> Notify it */
	if (windows_reset_all(context)) {
	       rc = protocol_events_set(context, BMC_EVENT_WINDOW_RESET);
	       if (rc < 0) {
		      MSG_ERR("Failed to notify host of reset, expect host-side corruption\n");
		      return rc;
	       }
	}
	rc = context->backend->lpc_reset(context);
	/* Not much we can do if this fails */
	if (rc < 0) {
		MSG_ERR("WARNING: Failed to point the LPC bus back to flash\n"
			"If the host requires this expect problems...\n");
	}

	return rc;
}

static int init_signals(struct mbox_context *context, sigset_t *set)
{
	int rc;

	/* Block SIGHUPs, SIGTERMs and SIGINTs */
	sigemptyset(set);
	sigaddset(set, SIGHUP);
	sigaddset(set, SIGINT);
	sigaddset(set, SIGTERM);
	rc = sigprocmask(SIG_BLOCK, set, NULL);
	if (rc < 0) {
		MSG_ERR("Failed to set SIG_BLOCK mask %s\n", strerror(errno));
		return rc;
	}

	/* Get Signal File Descriptor */
	rc = signalfd(-1, set, SFD_NONBLOCK);
	if (rc < 0) {
		MSG_ERR("Failed to get signalfd %s\n", strerror(errno));
		return rc;
	}

	context->fds[SIG_FD].fd = rc;
	return 0;
}

static void usage(const char *name)
{
	printf(USAGE, name);
}

static bool parse_cmdline(int argc, char **argv,
			  struct mbox_context *context)
{
	char *endptr;
	int opt;

	static const struct option long_options[] = {
		{ "flash",		required_argument,	0, 'f' },
		{ "backend",		required_argument,	0, 'b' },
		{ "window-size",	optional_argument,	0, 'w' },
		{ "window-num",		optional_argument,	0, 'n' },
		{ "verbose",		no_argument,		0, 'v' },
		{ "syslog",		no_argument,		0, 's' },
		{ "version",		no_argument,		0, 'V' },
		{ "help",		no_argument,		0, 'h' },
		{ 0,			0,			0, 0   }
	};

	verbosity = MBOX_LOG_NONE;
	mbox_vlog = &mbox_log_console;

	context->current = NULL; /* No current window */

	while ((opt = getopt_long(argc, argv, "f:b:w::n::vsVh", long_options, NULL))
			!= -1) {
		switch (opt) {
		case 0:
			break;
		case 'f':
			context->flash_size = strtol(optarg, &endptr, 10);
			if (optarg == endptr) {
				fprintf(stderr, "Unparseable flash size\n");
				return false;
			}
			switch (*endptr) {
			case '\0':
				break;
			case 'M':
				context->flash_size <<= 10;
			case 'K':
				context->flash_size <<= 10;
				break;
			default:
				fprintf(stderr, "Unknown units '%c'\n",
					*endptr);
				return false;
			}
			break;
		case 'b':
			context->filename = strdup(optarg);
			break;
		case 'n':
			context->windows.num = strtol(argv[optind], &endptr,
						      10);
			if (optarg == endptr || *endptr != '\0') {
				fprintf(stderr, "Unparseable window num\n");
				return false;
			}
			break;
		case 'w':
			context->windows.default_size = strtol(argv[optind],
							       &endptr, 10);
			context->windows.default_size <<= 20; /* Given in MB */
			if (optarg == endptr || (*endptr != '\0' &&
						 *endptr != 'M')) {
				fprintf(stderr, "Unparseable window size\n");
				return false;
			}
			if (!is_power_of_2(context->windows.default_size)) {
				fprintf(stderr, "Window size not power of 2\n");
				return false;
			}
			break;
		case 'v':
			verbosity++;
			break;
		case 's':
			/* Avoid a double openlog() */
			if (mbox_vlog != &vsyslog) {
				openlog(PREFIX, LOG_ODELAY, LOG_DAEMON);
				mbox_vlog = &vsyslog;
			}
			break;
		case 'V':
			printf("%s V%s\n", THIS_NAME, PACKAGE_VERSION);
			exit(0);
		case 'h':
			return false; /* This will print the usage message */
		default:
			return false;
		}
	}

	if (!context->filename) {
#ifdef VIRTUAL_PNOR_ENABLED
		// VPNOR is compiled in, default to vpnor it not otherwise selected
		context->filename = strdup("vpnor");
#else
		context->filename = get_dev_mtd();
#endif
	}
	if (!context->flash_size) {
		fprintf(stderr, "Must specify a non-zero flash size\n");
		return false;
	}

	MSG_INFO("Flash size: 0x%.8x\n", context->flash_size);

	if (verbosity) {
		MSG_INFO("%s logging\n", verbosity == MBOX_LOG_DEBUG ? "Debug" :
					"Verbose");
	}

	return true;
}

int backend_init(struct mbox_context *context)
{
	int rc;

#ifdef VIRTUAL_PNOR_ENABLED
	rc = probe_vpnor_backed_flash(context);
	if(rc)
	{
		rc = probe_mtd_backed_flash(context);
	}
#else
	rc = probe_mtd_backed_flash(context);
#endif

	if (rc) {
		if(context->filename) {
			fprintf(stderr, "Unable to determine backing store for file: %s\n",
				context->filename);
		}
		else
		{
			fprintf(stderr, "No backing store found\n");
		}
	}
	else {
		assert(context->backend && "Backend pointer not set by probe routine");
		assert(context->backend->init);
		assert(context->backend->free);
		assert(context->backend->write);
		assert(context->backend->erase);
		assert(context->backend->copy);
		assert(context->backend->set_bytemap);
		assert(context->backend->lpc_reset);

		rc = context->backend->init(context);
	}  
	
	return rc;
}

int main(int argc, char **argv)
{
	struct mbox_context *context;
	char *name = argv[0];
	sigset_t set;
	int rc, i;

	context = calloc(1, sizeof(*context));
	if (!context) {
		fprintf(stderr, "Memory allocation failed\n");
		exit(1);
	}

	if (!parse_cmdline(argc, argv, context)) {
		usage(name);
		free(context);
		exit(0);
	}

	for (i = 0; i < TOTAL_FDS; i++) {
		context->fds[i].fd = -1;
	}

	MSG_INFO("Starting Daemon\n");

	rc = init_signals(context, &set);
	if (rc) {
		goto finish;
	}

	rc = backend_init(context);
	if (rc) {
		goto finish;
	}

	rc = protocol_init(context);
	if (rc) {
		goto finish;
	}

	rc = transport_mbox_init(context);
	if (rc) {
		goto finish;
	}

	rc = lpc_dev_init(context);
	if (rc) {
		goto finish;
	}

	/* We've found the reserved memory region -> we can assign to windows */
	rc = windows_init(context);
	if (rc) {
		goto finish;
	}

	rc = dbus_init(context);
	if (rc) {
		goto finish;
	}

	/* Set the LPC bus mapping */
	rc = context->backend->lpc_reset(context);
	if (rc) {
		MSG_ERR("LPC configuration failed, RESET required: %d\n", rc);
	}

	rc = protocol_events_set(context, BMC_EVENT_DAEMON_READY);
	if (rc) {
		goto finish;
	}

	MSG_INFO("Entering Polling Loop\n");
	rc = poll_loop(context);

	MSG_INFO("Exiting Poll Loop: %d\n", rc);

finish:
	MSG_INFO("Daemon Exiting...\n");
	protocol_events_clear(context, BMC_EVENT_DAEMON_READY);

#ifdef VIRTUAL_PNOR_ENABLED
	destroy_vpnor(context);
#endif
	dbus_free(context);
	if(context->backend && context->backend->free) {
		context->backend->free(context);
	}
	lpc_dev_free(context);
	transport_mbox_free(context);
	windows_free(context);
	protocol_free(context);
	if(context->filename) {
		free(context->filename);
	}
	free(context);

	return rc;
}
