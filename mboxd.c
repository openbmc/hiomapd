/*
 * Mailbox Daemon Implementation
 *
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

#include "mbox.h"
#include "common.h"
#include "dbus.h"
#include "mboxd_dbus.h"
#include "mboxd_flash.h"
#include "mboxd_lpc.h"
#include "mboxd_msg.h"
#include "mboxd_windows.h"

#define USAGE \
"\nUsage: %s [--version] [-h | --help] [-v[v] | --verbose] [-s | --syslog]\n" \
"\t\t-n | --window-num <num>\n" \
"\t\t-w | --window-size <size>M\n" \
"\t\t-f | --flash <size>[K|M]\n\n" \
"\t-v | --verbose\t\tBe [more] verbose\n" \
"\t-s | --syslog\t\tLog output to syslog (pointless without -v)\n" \
"\t-n | --window-num\tThe number of windows\n" \
"\t-w | --window-size\tThe window size (power of 2) in MB\n" \
"\t-f | --flash\t\tSize of flash in [K|M] bytes\n\n"

#define POLL_TIMEOUT_MS		1000

#define MSG_OUT(f_, ...)	do { if (verbosity >= MBOX_LOG_DEBUG) { \
				    mbox_log(LOG_INFO, f_, ##__VA_ARGS__); } \
				} while (0)
#define MSG_ERR(f_, ...)	do { if (verbosity >= MBOX_LOG_VERBOSE) { \
				    mbox_log(LOG_ERR, f_, ##__VA_ARGS__); } \
				} while (0)

static int poll_loop(struct mbox_context *context)
{
	int rc = 0, i;

	/* Set POLLIN on polling file descriptors */
	for (i = 0; i < POLL_FDS; i++) {
		context->fds[i].events = POLLIN;
	}

	while (1) {
		rc = poll(context->fds, POLL_FDS, POLL_TIMEOUT_MS);

		if (!rc) { /* Timeout */
			continue;
		}
		if (rc < 0) { /* Error */
			MSG_ERR("Error from poll(): %s\n", strerror(errno));
			rc = -errno;
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

			switch (info.ssi_signo) {
			case SIGINT:
			case SIGTERM:
				MSG_OUT("Caught Signal - Exiting...\n");
				context->terminate = true;
				break;
			case SIGHUP:
				/* Host didn't request reset -> Notify it */
				reset_all_windows(context, SET_BMC_EVENT);
				rc = point_to_flash(context);
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
			while ((rc = sd_bus_process(context->bus, NULL)) > 0);
			if (rc < 0) {
				MSG_ERR("Error handling DBUS event: %s\n",
						strerror(-rc));
			}
		}
		if (context->terminate) {
			break; /* This should mean we clean up nicely */
		}
		if (context->fds[MBOX_FD].revents & POLLIN) { /* MBOX */
			rc = dispatch_mbox(context);
			if (rc < 0) {
				MSG_ERR("Error handling MBOX event\n");
			}
		}
	}

	/* Best to reset windows and point back to flash for safety */
	/* Host didn't request reset -> Notify it */
	reset_all_windows(context, SET_BMC_EVENT);
	rc = point_to_flash(context);
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
	int opt, i;

	static const struct option long_options[] = {
		{ "flash",		required_argument,	0, 'f' },
		{ "window-size",	optional_argument,	0, 'w' },
		{ "window-num",		optional_argument,	0, 'n' },
		{ "verbose",		no_argument,		0, 'v' },
		{ "syslog",		no_argument,		0, 's' },
		{ "version",		no_argument,		0, 'z' },
		{ "help",		no_argument,		0, 'h' },
		{ 0,			0,			0, 0   }
	};

	verbosity = MBOX_LOG_NONE;
	mbox_vlog = &mbox_log_console;

	/* Default to 1 window of size flash_size */
	context->windows.default_size = context->flash_size;
	context->windows.num = 1;
	context->current = NULL; /* No current window */

	while ((opt = getopt_long(argc, argv, "f:w::n::vsh", long_options, NULL))
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
		case 'z':
			printf("%s v%d.%.2d\n", THIS_NAME, API_MAX_VERSION,
						SUB_VERSION);
			exit(0);
		case 'h':
			return false; /* This will print the usage message */
		default:
			return false;
		}
	}

	if (!context->flash_size) {
		fprintf(stderr, "Must specify a non-zero flash size\n");
		return false;
	}

	if (!context->windows.num) {
		fprintf(stderr, "Must specify a non-zero number of windows\n"
				"If unsure - select 4 (-n 4)\n");
		return false;
	}

	if (!context->windows.default_size) {
		fprintf(stderr, "Must specify a non-zero window size\n"
				"If unsure - select 1M (-w 1)\n");
		return false;
	}

	MSG_OUT("Flash size: 0x%.8x\n", context->flash_size);
	MSG_OUT("Number of Windows: %d\n", context->windows.num);
	MSG_OUT("Window size: 0x%.8x\n", context->windows.default_size);

	context->windows.window = calloc(context->windows.num,
					 sizeof(*context->windows.window));

	for (i = 0; i < context->windows.num; i++) {
		init_window_state(&context->windows.window[i],
				  context->windows.default_size);
	}

	if (verbosity) {
		MSG_OUT("%s logging\n", verbosity == MBOX_LOG_DEBUG ? "Debug" :
					"Verbose");
	}

	return true;
}

int main(int argc, char **argv)
{
	struct mbox_context *context;
	char *name = argv[0];
	sigset_t set;
	int rc, i;

	context = calloc(1, sizeof(*context));

	if (!parse_cmdline(argc, argv, context)) {
		usage(name);
		exit(0);
	}

	for (i = 0; i < TOTAL_FDS; i++) {
		context->fds[i].fd = -1;
	}

	MSG_OUT("Starting Daemon\n");

	rc = init_signals(context, &set);
	if (rc) {
		goto finish;
	}

	rc = init_mbox_dev(context);
	if (rc) {
		goto finish;
	}

	rc = init_lpc_dev(context);
	if (rc) {
		goto finish;
	}

	/* We've found the reserved memory region -> we can assign to windows */
	rc = init_window_mem(context);
	if (rc) {
		goto finish;
	}

	rc = init_flash_dev(context);
	if (rc) {
		goto finish;
	}

	rc = init_dbus_dev(context);
	if (rc) {
		goto finish;
	}

	/* Set the LPC bus mapping to point to the physical flash device */
	rc = point_to_flash(context);
	if (rc) {
		goto finish;
	}

	rc = set_bmc_events(context, BMC_EVENT_DAEMON_READY, SET_BMC_EVENT);
	if (rc) {
		goto finish;
	}

	MSG_OUT("Entering Polling Loop\n");
	rc = poll_loop(context);

	MSG_OUT("Exiting Poll Loop: %d\n", rc);

finish:
	MSG_OUT("Daemon Exiting...\n");
	clr_bmc_events(context, BMC_EVENT_DAEMON_READY, SET_BMC_EVENT);

	sd_bus_unref(context->bus);

	free(context->flash_bmap);
	if (context->mem) {
		munmap(context->mem, context->mem_size);
	}
	for (i = 0; i < TOTAL_FDS; i++) {
		close(context->fds[i].fd);
	}
	for (i = 0; i < context->windows.num; i++) {
		free(context->windows.window[i].dirty_bmap);
	}
	free(context->windows.window);
	free(context);

	return rc;
}
