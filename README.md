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

This document describes a protocol for host to BMC communication via the
mailbox registers present on the Aspeed 2400 and 2500 chips.
This protocol is specifically designed to allow a host to request and manage
access to the flash with the specifics of how the host is required to control
this described below.

## Version

Both version 1 and version 2 of the protocol are described below with version 2
specificities represented with V2 in brackets - (V2).

## Problem Overview

"mbox" is the name we use to represent a protocol we have established between
the host and the BMC via the Aspeed mailbox registers. This protocol is used
for the host to control the flash.

Prior to the mbox protocol, the host uses a backdoor into the BMC address space
(the iLPC-to-AHB bridge) to directly manipulate the BMCs own flash controller.

This is not sustainable for a number of reasons. The main ones are:

1. Every piece of the host software stack that needs flash access (HostBoot,
   OCC, OPAL, ...) has to have a complete driver for the flash controller,
   update it on each BMC generation, have all the quirks for all the flash
   chips supported etc... We have 3 copies on the host already in addition to
   the one in the BMC itself.

2. There are serious issues of access conflicts to that controller between the
   host and the BMC.

3. It's very hard to support "BMC reboots" when doing that

4. It's slow

5. Last but probably most important, having that backdoor open is a security
   risk. It means the host can access any address on the BMC internal bus and
   implant malware in the BMC itself. So if the host is a "bare metal" shared
   system in some kind of data center, not only the host flash needs to be
   reflashed when switching from one customer to another, but the entire BMC
   flash too as nothing can be trusted. So we want to disable it.

To address all these, we have implemented a new mechanism that we call mbox.

When using this mechanism, the BMC is solely responsible for directly accessing
the flash controller. All flash erase and write operations are performed by the
BMC and the BMC only. (We can allow direct reads from flash under some
circumstances but we tend to prefer going via memory).

The host uses the mailbox registers to send "commands" to the BMC, which
responds via the same mechanism. Those commands allow the host to control a
"window" (which is the LPC -> AHB FW space mapping) that is either a read
window or a write window onto the flash.

When set for writing, the BMC makes the window point to a chunk of RAM instead.
When the host "commits" a change (via MBOX), then the BMC can perform the
actual flashing from the data in the RAM window.

The idea is to have the LPC FW space be routed to an active "window".  That
window can be a read or a write window. The commands allow to control which
window and which offset into the flash it maps.

* A read window can be a direct window to the flash controller space (ie.
  0x3000\_0000) or it can be a window to a RAM image of a flash. It doesn't have
  to be the full size of the flash per protocol (commands can be use to "slide"
  it to various parts of the flash) but if its set to map the actual flash
  controller space at 0x3000\_0000, it's probably simpler to make it the full
  flash. The host makes no assumption, it's your choice what to provide. The
  simplest implementation is to just route to the flash read/only.

* A write window has to be a chunk of BMC memory. The minimum size is not
  defined in the spec, but it should be at least one block (4k for now but it
  should support larger block sizes in the future). When the BMC receive the
  command to map the write window at a given offset of the flash, the BMC should
  copy that portion of the flash into a reserved memory buffer, and modify the
  LPC mapping to point to that buffer.

The host can then write to that window directly (updating the BMC memory) and
send a command to "commit" those updates to flash.

Finally there is a `RESET_STATE`. It's the state in which the bootloader in the
SEEPROM of the POWER9 chip will find what it needs to load HostBoot. The
details are still being ironed out: either mapping the full flash read only or
reset to a "window" that is either at the bottom or top of the flash. The
current implementation resets to point to the full flash.

## Where is the code?

The mbox userspace is available [on GitHub](https://github.com/openbmc/mboxbridge)
This is Apache licensed but we are keen to see any enhancements you may have.

The kernel driver is still in the process of being upstreamed but can be found
in the OpenBMC Linux kernel staging tree:

https://github.com/openbmc/linux/commit/85770a7d1caa6a1fa1a291c33dfe46e05755a2ef

## Building

The autotools of this requires the autoconf-archive package for your
system

## The Hardware

The Aspeed mailbox consists of 16 (8 bit) data registers see Layout for their
use. Mailbox interrupt enabling, masking and triggering is done using a pair
of control registers, one accessible by the host the other by the BMC.
Interrupts can also be raised per write to each data register, for BMC and
host. Write tiggered interrupts are configured using two 8 bit registers where
each bit represents a data register and if an interrupt should fire on write.
Two 8 bit registers are present to act as a mask for write triggered
interrupts.

### Layout

```
Byte 0: COMMAND
Byte 1: Sequence
Byte 2-12: Arguments
Byte 13: Response code
Byte 14: Host controlled status reg
Byte 15: BMC controlled status reg
```

## Low Level Protocol Flow

What we essentially have is a set of registers which either the host or BMC can
write to in order to communicate to the other which will respond in some way.
There are 3 basic types of communication.

1. Commands sent from the Host to the BMC
2. Responses sent from the BMC to the Host in response to commands
3. Asyncronous events raised by the BMC

### General Use

Messages usually originate from the host to the BMC. There are special
cases for a back channel for the BMC to pass new information to the
host which will be discussed later.

To initiate a request the host must set a command code (see
Commands) into mailbox data register 0. It is also the hosts
responsibility to generate a unique sequence number into mailbox
register 1. After this any command specific data should be written
(see Layout). The host must then generate an interrupt to the BMC by
using bit 0 of its control register and wait for an interrupt on the
response register. Generating an interrupt automatically sets bit 7 of the
corresponding control register. This bit can be used to poll for
messages.

On receiving an interrupt (or polling on bit 7 of its Control
Register) the BMC should read the message from the general registers
of the mailbox and perform the necessary action before responding. On
responding the BMC must ensure that the sequence number is the same as
the one in the request from the host. The BMC must also ensure that
mailbox data regsiter 13 is a valid response code (see Responses). The
BMC should then use its control register to generate an interrupt for
the host to notify it of a response.

### Asynchronous BMC to Host Events

BMC to host communication is also possible for notification of events
from the BMC. This requires that the host have interrupts enabled on
mailbox data register 15 (or otherwise poll on bit 7 of mailbox status
register 1). On receiving such a notification the host should read
mailbox data register 15 to determine the event code which was set by the
BMC (see BMC Event notifications in Commands for detail). Events which can
be acknowledged by the host should be to let the BMC know that the host
has taken the appropriate action in response to the event.

## High Level Protocol Flow

When a host wants to communicate with the BMC via the mbox protocol the first
thing it should do it call MBOX_GET_INFO in order to establish the protocol
version which each understands. Before this the only other commands which are
allowed are RESET_STATE and BMC_EVENT_ACK.

After this the host can open and close windows with the CREATE_READ_WINDOW,
CREATE_WRITE_WINDOW and CLOSE_WINDOW commands. Creating a window is how the
host requests access to a section of flash. It is worth noting that the host
can only ever have one window that it is accessing at a time - hence forth
referred to as the active window.

When the active window is a write window the host can perform MARK_WRITE_DIRTY,
MARK_WRITE_ERASED and WRITE_FLUSH commands to control which parts of and when
changes are reflected back to flash.

The BMC can raise asynchronous events with the host to communicate a change in
state.

### Version Negotiation

Given that a majority of command and response arguments are specified as a
multiple of block size it is necessary for the host and daemon to agree on a
protocol version as this determines the block size. In V1 it is hard coded at
4K and in V2 the daemon chooses and specifies this to the host as a response
argument to MBOX_GET_INFO. Thus the host must always call MBOX_GET_INFO before
any other command which specifies an argument in block size.

The host must tell the daemon the highest protocol level which it supports. The
daemon will then respond with a protocol level. If the host doesn't understand
the protocol level specified by the daemon then it must not continue to
communicate with the daemon. Otherwise the protocol level specified by the
daemon is taken to be the protocol level used for further communication and can
only be changed by another call to MBOX_GET_INFO. The daemon should use the
request from the host to influence its protocol version choice.

### Window Management

In order to access flash contents the host must request a window be opened at
the flash offset it would like to access. The host may give a hint as to how
much data it would like to access or otherwise set this argument to zero. The
daemon must respond with the lpc bus address to access this window and the
window size. The host must not access past the end of the active window.

There is only ever one active window which is the window created by the most
recent CREATE_READ_WINDOW or CREATE_WRITE_WINDOW call which succeeded. Even
though there are two types of windows there can still only be one active window
irrespective of type. A host must not write to a read window. A host may read
from a write window and the daemon must guarantee that the window reflects what
the host has written there.

A window can be closed by calling CLOSE_WINDOW in which case there is no active
window and the host must not access the window after it has been closed.
If the host closes an active write window then the daemon must perform an
implicit flush. If the host tries to open a new window with an already active
window then the active window is closed (and implicitly flushed if it was a
write window), if the new window is successfully opened then that is the new
active window or if it fails then there is no active window and the previous
active window must no longer be accessed.

The host must not access an lpc address other than that which is contained by
the active window. The host must not use write management functions (see below)
if the active window is a read window or if there is no active window.

### Write Management

The BMC has no method for intercepting writes that occur over the LPC bus. Thus
the host must explicitly notify the daemon of where and when a write has
occured. The host must use the MARK_WRITE_DIRTY command to tell the host where
within the write window it has modified. The host may also use the
MARK_WRITE_ERASED command to erase large parts of the active window without the
need to write 0xFF individually. The daemon must ensure that if the host
reads from an area it has erased that it sees 0xFF. Any part of the active
window marked dirty or erased is only marked for the lifetime of the current
active write window and does not persist if the active window is closed either
implicitly or explicitly by the host or the daemon. The daemon may at any time
or must on a call to WRITE_FLUSH flush the changes which it has been notified
about back to the flash at which point the dirty or erased marking is cleared
for the active window. The host must not assume that any changes have been
written to flash unless an explicit flush call was successful, a close of an
active write window was successful or a create window command with an active
write window was successful - otherwise consistency between the flash and memory
contents cannot be guaranteed.

The host is not required to perform an erase before a write command and the
daemon must ensure that a write performs as expected - that is if an erase is
required before a write then the daemon must perform this itself.

### BMC Events

The BMC can raise events with the host asynchronously to communicate to the
host a change in state which it should take notice of. The host should (if
possible for the given event) acknowledge it to inform the BMC it has been
received.

If the BMC raises a BMC Reboot event then the host must reperform version
negotiation. If the BMC raises a BMC Windows Reset event then the host must
assume that there is no longer an active window - that is if there was an
active window it has been closed by the daemon and if it was a write window
then the host must not assume that it was flushed unless a previous explicit
flush call was successful.

The BMC may require access to the flash and should set the BMC Flash Control
Lost event when accessing the flash behind the daemons back. When this event is
set the host must assume that the contents of the active window could be
inconsistent with the contents of flash.

## Protocol Definition

### Commands

```
RESET_STATE          0x01
GET_MBOX_INFO        0x02
GET_FLASH_INFO       0x03
CREATE_READ_WINDOW   0x04
CLOSE_WINDOW         0x05
CREATE_WRITE_WINDOW  0x06
MARK_WRITE_DIRTY     0x07
WRITE_FLUSH          0x08
BMC_EVENT_ACK        0x09
MARK_WRITE_ERASED    0x0a	(V2)
```

### Sequence

The host must ensure a unique sequence number at the start of a
command/response pair. The BMC must ensure the responses to
a particular message contain the same sequence number that was in the
command request from the host.

### Responses

```
SUCCESS		1
PARAM_ERROR	2
WRITE_ERROR	3
SYSTEM_ERROR	4
TIMEOUT		5
BUSY		6	(V2)
WINDOW_ERROR	7	(V2)
```

#### Description:

SUCCESS		- Command completed successfully

PARAM_ERROR	- Error with parameters supplied or command invalid

WRITE_ERROR	- Error writing to the backing file system

SYSTEM_ERROR	- Error in BMC performing system action

TIMEOUT		- Timeout in performing action

BUSY		- Daemon in suspended state (currently unable to access flash)
		- Retry again later

WINDOW_ERROR	- Command not valid for active window or no active window
		- Try opening an appropriate window and retrying the command

### Information
- All multibyte messages are LSB first (little endian)
- All responses must have a valid return code in byte 13


### Commands in detail

Note in V1 block size is hard coded to 4K, in V2 it is variable and must be
queried with GET_MBOX_INFO.
Sizes and addresses are specified in either bytes - (bytes)
					 or blocks - (blocks)
Sizes and addresses specified in blocks must be converted to bytes by
multiplying by the block size.
```
Command:
	RESET_STATE
	Implemented in Versions:
		V1, V2
	Arguments:
		-
	Response:
		-
	Notes:
		This command is designed to inform the BMC that it should put
		host LPC mapping back in a state where the SBE will be able to
		use it. Currently this means pointing back to BMC flash
		pre mailbox protocol. Final behavour is still TBD.

Command:
	GET_MBOX_INFO
	Implemented in Versions:
		V1, V2
	Arguments:
		V1:
		Args 0: API version

		V2:
		Args 0: API version

	Response:
		V1:
		Args 0: API version
		Args 1-2: default read window size (blocks)
		Args 3-4: default write window size (blocks)

		V2:
		Args 0: API version
		Args 1-2: default read window size (blocks)
		Args 3-4: default write window size (blocks)
		Args 5: Block size as power of two (encoded as a shift)

Command:
	GET_FLASH_INFO
	Implemented in Versions:
		V1, V2
	Arguments:
		-
	Response:
		V1:
		Args 0-3: Flash size (bytes)
		Args 4-7: Erase granule (bytes)

		V2:
		Args 0-1: Flash size (blocks)
		Args 2-3: Erase granule (blocks)

Command:
	CREATE_{READ/WRITE}_WINDOW
	Implemented in Versions:
		V1, V2
	Arguments:
		V1:
		Args 0-1: Window location as offset into flash (blocks)

		V2:
		Args 0-1: Window location as offset into flash (blocks)
		Args 2-3: Requested window size (blocks)

	Response:
		V1:
		Args 0-1: LPC bus address of window (blocks)

		V2:
		Args 0-1: LPC bus address of window (blocks)
		Args 2-3: Actual window size (blocks)
	Notes:
		Window location is always given as an offset into flash as
		taken from the start of flash - that is it is an absolute
		address.

		LPC bus address is always given from the start of the LPC
		address space - that is it is an absolute address.

		The requested window size is only a hint. The response
		indicates the actual size of the window. The BMC may
		want to use the requested size to pre-load the remainder
		of the request. The host must not access past the end of the
		active window.

		The requested window size may be zero. In this case the
		BMC is free to create any sized window but it must contain
		atleast the first block of data requested by the host. A large
		window is of course preferred and should correspond to
		the default size returned in the GET_MBOX_INFO command.

		If this command returns successfully then the window which the
		host requested is the active window. If it fails then there is
		no active window.

Command:
	CLOSE_WINDOW
	Implemented in Versions:
		V1, V2
	Arguments:
		V1:
		-

		V2:
		Args 0: Flags
	Response:
		-
	Notes:
		Closes the active window. Any further access to the LPC bus
		address specified to address the previously active window will
		have undefined effects. If the active window is a
		write window then the BMC must perform an implicit flush.

		The Flags argument allows the host to provide some
		hints to the daemon. Defined Values:
			0x01 - Short Lifetime:
				The window is unlikely to be accessed
				anytime again in the near future. The effect of
				this will depend on daemon implementation. In
				the event that the daemon performs some caching
				the daemon should mark data contained in a
				window closed with this flag as first to be
				evicted from the cache.

Command:
	MARK_WRITE_DIRTY
	Implemented in Versions:
		V1, V2
	Arguments:
		V1:
		Args 0-1: Flash offset to mark from base of flash (blocks)
		Args 2-5: Number to mark dirty at offset (bytes)

		V2:
		Args 0-1: Window offset to mark (blocks)
		Args 2-3: Number to mark dirty at offset (blocks)

	Response:
		-
	Notes:
		The BMC has no method for intercepting writes that
		occur over the LPC bus. The host must explicitly notify
		the daemon of where and when a write has occured so it
		can be flushed to backing storage.

		Offsets are given as an absolute (either into flash (V1) or the
		active window (V2)) and a zero offset refers to the first
		block. If the offset + number exceeds the size of the active
		window then the command must not succeed.

Command
	WRITE_FLUSH
	Implemented in Versions:
		V1, V2
	Arguments:
		V1:
		Args 0-1: Flash offset to mark from base of flash (blocks)
		Args 2-5: Number to mark dirty at offset (bytes)

		V2:
		-

	Response:
		-
	Notes:
		Flushes any dirty/erased blocks in the active window to
		the backing storage.

		In V1 this can also be used to mark parts of the flash
		dirty and flush in a single command. In V2 the explicit
		mark dirty command must be used before a call to flush
		since there are no longer any arguments. If the offset + number
		exceeds the size of the active window then the command must not
		succeed.


Command:
	BMC_EVENT_ACK
	Implemented in Versions:
		V1, V2
	Arguments:
		Args 0:	Bits in the BMC status byte (mailbox data
			register 15) to ack
	Response:
		*clears the bits in mailbox data register 15*
	Notes:
		The host should use this command to acknowledge BMC events
		supplied in mailbox register 15.

Command:
	MARK_WRITE_ERASED
	Implemented in Versions:
		V2
	Arguments:
		V2:
		Args 0-1: Window offset to erase (blocks)
		Args 2-3: Number to erase at offset (blocks)
	Response:
		-
	Notes:
		This command allows the host to erase a large area
		without the need to individually write 0xFF
		repetitively.

		Offset is the offset within the active window to start erasing
		from (zero refers to the first block of the active window) and
		number is the number of blocks of the active window to erase
		starting at offset. If the offset + number exceeds the size of
		the active window then the command must not succeed.
```

### BMC Events in Detail:

If the BMC needs to tell the host something then it simply
writes to Byte 15. The host should have interrupts enabled
on that register, or otherwise be polling it.

#### Bit Definitions:

Events which should be ACKed:
```
0x01: BMC Reboot
0x02: BMC Windows Reset (V2)
```

Events which cannot be ACKed (BMC will clear when no longer
applicable):
```
0x40: BMC Flash Control Lost (V2)
0x80: BMC MBOX Daemon Ready (V2)
```

#### Event Description:

Events which should be ACKed:
The host should acknowledge these events with BMC_EVENT_ACK to
let the BMC know that they have been received and understood.
```
0x01 - BMC Reboot:
	Used to inform the host that a BMC reboot has occured.
	The host must perform protocol verison negotiation again and
	must assume it has no active window. The host must not assume
	that any commands which didn't return success succeeded.
0x02 - BMC Windows Reset: (V2)
	The host must assume that its active window has been closed and
	that it no longer has an active window. The host is not
	required to perform protocol version negotiation again. The
	host must not assume that any commands which didn't return success
	succeeded.
```

Events which cannot be ACKed:
These events cannot be acknowledged by the host and a call to
BMC_EVENT_ACK with these bits set will have no effect. The BMC
will clear these bits when they are no longer applicable.
```
0x40 - BMC Flash Control Lost: (V2)
	The daemon has been suspended and thus no longer
	controls access to the flash (most likely because some
	other process on the BMC required direct access to the
	flash and has suspended the daemon to preclude
	concurrent access).
	The daemon will clear this bit itself when it regains
	control of the flash (the host isn't able to clear it
	through an acknowledge command).
	The host must not assume that the contents of the active window
	correctly reflect the contents of flash while this bit is set.
0x80 - BMC MBOX Daemon Ready: (V2)
	Used to inform the host that the daemon is ready to
	accept command requests. The host isn't able to clear
	this bit through an acknowledge command, the daemon will
	clear it before it terminates (assuming it didn't
	terminate unexpectedly).
	While the host should not expect a response while this bit is
	not set.
	Note that this bit being set it not a guarantee that the daemon
	will respond as it or the BMC may have crashed without clearing
	it.
```
