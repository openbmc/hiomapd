Copyright 2016 IBM

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Intro

This document describes the reference mailbox control program contained in this
repository.

The mailbox control program is a program which can be used to generate dbus
messages to control the operation of the mailbox daemon.

## Files

The mailbox control program is implemented entirely in the mboxctl.c file.

## Operation

### Invocation

The mailbox control program is invoked with a command and any arguments which
that command takes.

### Sending Command

The appropriate dbus message is then generated and sent on the dbus.

### Receiving Commands

After sending a command mboxctl then waits for a response from the daemon on
the dbus and processes the response.

A message is printed to convey the response provided by the daemon. It mboxctl
is run in silent mode then no output is generated and the exit code reflects
the response.

## DBUS Protocol

### Commands

```
0x00: Ping	- Ping the daemon
		- Args: NONE
		- Resp: NONE
0x01: Status	- Get the daemon status
		- Args: NONE
		- Resp[0]: Daemon Status:
				0x00 - Active
				0x01 - Suspended
0x02: Reset	- Reset the daemon (same as the reset mbox command)
		- Args: NONE
		- Resp: NONE
0x03: Suspend	- Suspend the daemon
			- Allow the BMC to manage concurrent flash access
			- The daemon will return BUSY to mbox window commands
			- Will return NOOP when deamon already suspended
		- Args: NONE
		- Resp: NONE
0x04: Resume	- Resume the daemon
			- Will return NOOP when daemon not suspended
		- Args[0]: Flash Modified:
				0x00 - Not Modified (daemon won't clear cache)
				0x01 - Modified (daemon will clear its cache)
		- Resp: NONE
0x05: Modified	- Tell the daemon its data source has been modified
			- Causes the daemon to clear its cache
		- Args: NONE
		- Resp: NONE
0x06: Kill	- Terminates the daemon
		- Args: NONE
		- Resp: NONE
0x07: State	- Query the state of the lpc mapping
		- Args: NONE
		- Resp[0]: LPC Bus Mapping State:
				0x00 - Invalid (implies internal daemon error)
				0x01 - Flash (LPC bus maps flash)
				0x02 - Memory (LPC bus maps reserved memory)
```

### Return Values

```
0x00: Success	- Command succeeded
0x01: Internal	- Internal DBUS Error
0x02: Invalid	- Invalid command or parameters
0x03: Rejected	- Daemon rejected the request
			- If this occurs on a suspend command then the BMC must
			  not access the flash device until a suspend command
			  succeeds
0x04: Hardware	- BMC Hardware Error
0x05: NOOP	- The dbus command would have no effect on the daemon
```
