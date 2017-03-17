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

# Intro
This is a protocol description using the mailbox registers on
Aspeed 2400/2500 chips for host to BMC communication.

### Version

Description that follows if Version 2 (V2) of the protocol.

### Problem Overview

"mbox" is the name we use to represent a protocol we have established between
the host and the BMC via the Aspeed mailbox registers. This protocol is used
for the host to control the flash.

Prior to the mbox protocol, the host uses a backdoor into the BMC address space
(the iLPC-to-AHB bridge) to directly manipulate the BMC own flash controller.

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

When using that mechanism, the BMC is sole responsible for directly accessing
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

### Where is the code?

The mbox userspace is available [on GitHub](https://github.com/openbmc/mboxbridge)
This is Apache licensed but we are keen to see any enhancements you may have.

The kernel driver is still in the process of being upstreamed but can be found
in the OpenBMC Linux kernel staging tree:

https://github.com/openbmc/linux/commit/85770a7d1caa6a1fa1a291c33dfe46e05755a2ef

### The Hardware
The Aspeed mailbox consists of 16 (8 bit) data registers see Layout for their
use. Mailbox interrupt enabling, masking and triggering is done using a pair
of control registers, one accessible by the host the other by the BMC.
Interrupts can also be raised per write to each data register, for BMC and
host. Write tiggered interrupts are configured using two 8 bit registers where
each bit represents a data register and if an interrupt should fire on write.
Two 8 bit registers are present to act as a mask for write triggered
interrupts.

### Low Level Protocol Flow
The protocol itself consists of:
```
1. Commands sent from the Host to the BMC
2. Responses sent from the BMC to the Host
3. Asyncronous events raised by the BMC
```

### General use
Messages usually originate from the host to the BMC. There are special
cases for a back channel for the BMC to pass new information to the
host which will be discussed later.

To initiate a request the host must set a command code (see
Commands) into mailbox data register 0. It is also the hosts
responsibility to generate a unique sequence number into mailbox
register 1. After this any command specific data should be written
(see Layout). The host must then generate an interrupt to the BMC by
using bit 0 of its control register and wait for an interrupt in the
response. Generating an interrupt automatically sets bit 7 of the
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

### BMC to host
BMC to host communication is also possible for notification of events
from the BMC. This requires that the host have interrupts enabled on
mailbox data register 15 (or otherwise poll on bit 7 of mailbox status
register 1). On receiving such a notification the host should read
mailbox data register 15 to determine the event code was set by the
BMC (see BMC Event notifications in Commands for detail). After
performing the necessary action the host should send a BMC_EVENT_ACK
message to the BMC with which bit it has actioned.

### Building
The autotools of this requires the autoconf-archive package for your
system

---

## Layout
```
Byte 0: COMMAND
Byte 1: Sequence
Byte 2-12: Arguments
Byte 13: Response code
Byte 14: Host controlled status reg
Byte 15: BMC controlled status reg
```
## Commands
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
MARK_WRITE_ERASED    0x0a
```
## Sequence
Unique message sequence number to be allocated by the host at the
start of a command/response pair. The BMC must ensure the responses to
a particular message contain the same sequence number that was in the
request from the host.

## Responses
```
SUCCESS		1
PARAM_ERROR	2
WRITE_ERROR	3
SYSTEM_ERROR	4
TIMEOUT		5
BUSY		6
WINDOW_ERROR	7
WINDOW_CLOSED	8

Description:

SUCCESS		- Command completed successfully

PARAM_ERROR	- Error with parameters supplied
		- Command failed but system state otherwise unchanged

WRITE_ERROR	- Error writing to the backing file system
		- Command failed but system state otherwise unchanged

SYSTEM_ERROR	- Error in BMC performing some system action
		- Command failed but system state otherwise unchanged

TIMEOUT		- Timeout in performing action
		- Command failed but system state otherwise unchanged

BUSY		- Daemon in suspended state (currently unable to access flash)
		- Command failed but system state otherwise unchanged
		- Retry again later

WINDOW_ERROR	- Command not valid for current window or no current window
		- Command failed but system state otherwise unchanged
		- Try opening a window and retrying the command

WINDOW_CLOSED	- Current window has been closed by the daemon
		- Command failed and system state reset (all windows closed and
		  any changes not successfully flushed lost. Window may no
		  longer be accessed)
		- NOTE: this doesn't indicate the successful completion of a
		  close window command this means that the window was closed by
		  the daemon and no implicit flush was performed. A close
		  window command only successfully completed on return of
		  SUCCESS.

```

## Information
- All multibyte messages are LSB first(little endian)
- All responses must have a valid return code in byte 13

Only one window can be open at once.

### High Level Protocol Flow
The commands from the Host fall into rougly three categories:
```
1. Informational
2. Window management
3. Write handling
```
The active "window" refers to the part of the LPC FW space that has defined
contents. The Host cannot make any assumptions about the contents of the FW
space outside of the window and the Host must not write to a window that has
been opened for reading. The exact behaviour of accessing outside the window is
explictly undefined by the protocol to allow some flexibility in how the BMC
implements the protocol.

Informational commands are used by the host to determine information about the
mbox deamon itself (what version of the protocol it implements, block size), as
well as information about the backing storage (total size and erase granule).
There is also an EVENT_ACK command for the host to acknowledge an asynchronous
event raised by the BMC to the host.

Window management commands are used to open, mark dirty, flush and close a
window. A window is first opened with a CREATE_[READ/WRITE]_WINDOW command with
a flash offset of what the window should contain and an indicative size. The
daemon will then respond with the lpc bus address to access this window and the
actual size mapped. The daemon is free to ignore the requested size and can
return any window which maps at least the first block of flash requested by the
host (the size is more of a hint as to what the host will access in the future
so the daemon could for example preload some of this). Since the daemon doesn't
know when a write window has been modified MARK_WRITE_DIRTY must be called to
tell the daemon when the window contents have been modified. In V2 of the
protocol a MARK_WRITE_ERASED command is added to allow the host to request a
range of the window be erased and this was added to prevent the need to write
all 0xFF to every byte to erase a large block. It is not necessary to erase a
region before writing it, it is up to the daemon to ensure that if flash is the
backing storage method that a write command will behave as expected (which may
include erasing the flash before writing). The daemon may like to track which
parts of flash are already erased so it doesn't have to erase before writing if
the region is known to be already erased. The daemon is then free to flush
these changes (erase and/or write) to backing storage at any time, or is
required to when an explicit call to WRITE_FLUSH is made. A CLOSE_WINDOW command
or opening a new window with one already opened will cause an implicit flush and
then close the existing window, even if opening the new window fails.

NOTE: Writes/Mark Dirty/Mark Erased/Flush commands may only be performed on an
open write window and should return WINDOW_ERROR if no window or a read window
is the currently active window.

### Commands in detail
In V2 of the protocol all sizes are a multiple of block size. Block size is
variable and must be determined by the host through a call to GET_MBOX_INFO.
In V1 of the protocol block size was hard coded as 4K.
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
			Args 1-2: default read window size as number of blocks
			Args 3-4: default write window size as number of block

			V2:
			Args 0: API version
			Args 1-2: default read window size as number of blocks
			Args 3-4: default write window size as number of block
			Args 5: Block size as power of two.

	Command:
		GET_FLASH_INFO
		Implemented in Versions:
			V1, V2
		Arguments:
			-
		Response:
			V1:
			Args 0-3: Flash size in bytes
			Args 4-7: Erase granule in bytes

			V2:
			Args 0-1: Flash size in number of blocks
			Args 2-3: Erase granule in number of blocks

	Command:
		CREATE_[READ/WRITE]_WINDOW
		Implemented in Versions:
			V1, V2
		Arguments:
			V1:
			Args 0-1: Read window offset as number of blocks

			V2:
			Args 0-1: Read window offset as number of blocks
			Args 2-3: Requested read window size in blocks

		Response:
			V1:
			Args 0-1: Start block of this window on the LPC bus

			V2:
			Args 0-1: Start block of this window on the LPC bus
			Args 2-3: Actual size of the window in blocks
		Notes:
			Requested offset is the offset within the flash, always
			specified from zero.
			Response offset is where flash at the requested offset
			is mapped on the LPC bus as viewed from the host.

			The requested window size is only a hint. The response
			indicates the actual size of the window. The BMC may
			want to use the requested size to pre-load the remainder
			of the request

			The requested window size may be zero. In this case the
			BMC is free to create any window which contains at least
			the first block of data requested by the host. A large
			window is of course preferred and should correspond to
			the default size returned in the GET_MBOX_INFO command.

			The format of the CREATE_{READ,WRITE}_WINDOW commands
			are identical.

	Command:
		CLOSE_WINDOW
		Implemented in Versions:
			V1, V2
		Arguments:
			Args 0: Flags
		Response:
			-
		Notes:
			Close active window. Any further access to the LPC bus
			address specified to address this window will have
			undefined effects. This should not be called without a
			currently active window. If the active window is a
			write window then an implicit flush is performed.

			The Flags argument allows the host to provide some
			hints to the daemon. Valid values:
				0x01 - Short Lifetime.
					The window is unlikely to be accessed
					anytime again in the near future.

	Command:
		MARK_WRITE_DIRTY
		Implemented in Versions:
			V1, V2
		Arguments:
			V1:
			Args 0-1: Where within flash as number of blocks
			Args 2-5: Number of dirty bytes

			V2:
			Args 0-1: Where within window as number of blocks
			Args 2-3: Number of dirty blocks

		Response:
			-
		Notes:
			The BMC has no method for intercepting writes that
			occur over the LPC bus. The host must explicitly notify
			the daemon of where and when a write has occured so it
			can be flushed to backing storage.

			Where within the flash/window is the index of the first
			dirty block within the flash/window to mark dirty - zero
			refers to the first block of the mapping.

			After a block has been marked dirty it may at any time
			be flushed to backing storage, or only on a FLUSH/CLOSE
			command at the daemons discretion.

			A dirty of an erased block (see MARK_WRITE_ERASED
			below) will disregard the erase and maintain the data
			in the dirty block.

			Only valid with a currently open write window.

	Command
		WRITE_FLUSH
		Implemented in Versions:
			V1, V2
		Arguments:
			V1:
			Args 0-1: Where within flash as number of blocks
			Args 2-5: Number of dirty bytes

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
			since there are no longer any arguments.

			This is called implicity whenever a window is closed
			(which also occurs when opening a window with one
			 already currently active).

			Only valid with a currently open write window.

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
			The host will use this command to acknowledge BMC events
			supplied in mailbox register 15.

	Command:
		MARK_WRITE_ERASED
		Implemented in Versions:
			V2
		Arguments:
			V2:
			Args 0-1: Where within window as number of blocks
			Args 2-3: Number of erased blocks
		Response:
			-
		Notes:
			This command allows the host to erase a large area
			without the need to individually write 0xFF
			repetitively.

			Where within the window is the index of the first
			erased block within the window - zero refers to the
			first block of the mapping.

			After a block has been marked erased it may at any time
			be flushed to backing storage, or only on a FLUSH/CLOSE
			command at the daemons discretion.

			An erase of a block previously marked dirty will
			discard any data and just erase the block.

			Only valid with a currently open write window.

	BMC notifications:
		If the BMC needs to tell the host something then it simply
		writes to Byte 15. The host should have interrupts enabled
		on that register, or otherwise be polling it.

		Bit Definitions:
		0x01: BMC Reboot
		0x02: BMC Window Reset
		0x04: BMC Flash Control Lost

		0x01 - BMC Reboot:
			Used to inform the host that a BMC reboot has occured.
			The host should assume a total loss of system state.
			All and any commands which didn't return SUCCESS should 
			be assumed to have failed, any data has been lost and
			the host should reopen any windows and rewrite all data
			which it doesn't know to have succeeded.
			The host shouldn't access any previous windows and
			should open a new window before continuing.
			The daemon can be assumed to be in the reset state and
			doesn't know the protocol version or any other system
			state.
			The host should acknowledge this event and then call
			GET_MBOX_INFO.
		0x02 - BMC Window Reset:
			The state of the flash has been changed and as such the
			consistency between the state of data in flash and
			memory cannot be guaranteed (because the daemon has
			been resumed after being suspended because something
			else accessed the flash for example). The current window
			has been closed by the BMC and any commands which didn't
			return SUCCESS should be assumed to have failed, any
			data has been lost and the host should reopen any
			windows and rewrite all data which it doesn't know to
			have succeeded.
			The host shouldn't access any previous windows and
			should open a new window before continuing.
			The daemon can be assumed to be in a polling state and
			remembers which protocol version was being used.
			The host should acknowledge this event and then open a
			new window.
		0x04 - BMC Flash Control Lost:
			The daemon has been suspended and thus no longer
			controls access to the flash (most likely because some
			other process on the BMC required direct access to the
			flash and has suspended the daemon to preclude
			concurrent access). The host shouldn't access the
			current window, commands should return BUSY or
			WINDOW_CLOSED.
```
