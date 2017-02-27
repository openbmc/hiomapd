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
RESET_STATE          1
GET_MBOX_INFO        2
GET_FLASH_INFO       3
CREATE_READ_WINDOW   4
CLOSE_WINDOW         5
CREATE_WRITE_WINDOW  6
MARK_WRITE_DIRTY     7
WRITE_FLUSH          8
BMC_EVENT_ACK        9
```
## Sequence
Unique message sequence number to be allocated by the host at the
start of a command/response pair. The BMC must ensure the responses to
a particular message contain the same sequence number that was in the
request from the host.

## Responses
```
SUCCESS       1
PARAM_ERROR   2
WRITE_ERROR   3
SYSTEM_ERROR  4
TIMEOUT       5
```

## Information
- All multibyte messages are LSB first(little endian)
- All responses must have a valid return code in byte 13

Only one window can be open at once.

### Commands in detail
```
	Command:
		RESET_STATE
		Data:
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
		Arguements:
			Args 0: API version

		Response:
			Args 0: API version
			Args 1-2: read window size as number of blocks
			Args 3-4: write window size as number of block
			Args 5: Block size as power of two.


	Command:
		CLOSE_WINDOW
		Arguments:
			-
		Response:
			-
		Notes:
			Close active window. Renders the LPC mapping unusable.


	Command:
		GET_FLASH_INFO
		Arguments:
			-
		Response:
			Args 0-3: Flash size in bytes
			Args 4-7: Erase granule in bytes


	Command:
		CREATE_READ_WINDOW
		Arguments:
			Args 0-1: Read window offset as number of blocks
		Respons:
			Args 0-1: Read window position as number of blocks
		Notes:
			Offset is the offset within the flash, always specified
			  from zero.
			Position is where flash at the requested offset is mapped
			  on the LPC bus as viewed from the host.


	Command:
		CREATE_WRITE_WINDOW
		ARguments:
			Args 0-1: Write window offset as number of blocks
		Response:
			Args 0-1: Write window position as number of blocks
		Notes:
			Offset is the offset within the flash, always specified
			  from zero.
			Position is where flash at the requested offset is mapped
			  on the LPC bus as viewed from the host.


	Command:
		MARK_WRITE_DIRTY
		Data:
			Data 0-1: Where within window as number of blocks
			Data 2-5: Number of dirty bytes
		Response:
			-
		Notes:
			Where within the window is the index of the first dirty
			block within the window - zero refers to the first block of
			the mapping.
			This command marks bytes as dirty but does not nessesarily
			flush them to flash. It is expected that this command will
			respond quickly without actually performing a write to the
			backing store.


	Command
		WRITE_FLUSH
		Data:
			Data 0-1: Where within window as number of blocks
			Data 2-5: Number of dirty bytes
		Response:
			-
		Notes:
			Where within the window is the index of the first dirty
			block within the window - zero refers to the first block of
			the mapping.
			Number of dirty bytes can be zero, this would result in
			writing all bytes previously marked as dirty.
			This command will block untill all dirty bytes have been
			written to the backing store.


	Command:
		BMC_EVENT_ACK
		Data:
			Bits in the BMC status byte (mailbox data register 15) to ack
		Response:
			*clears the bits in mailbox data register 15*
			-
		Notes:
			The host will use this command to acknowledge BMC events
			supplied in mailbox register 15.


	BMC notifications:
		If the BMC needs to tell the host something then it simply
		writes to Byte 15. The host should have interrupts enabled
		on that register, or otherwise be polling it.
		 -[bit 0] BMC reboot. A BMC reboot informs the host that its
		  windows/dirty bytes/in flight commands will be lost and it
		  should attempt to reopen windows and rewrite any data it had
		  not flushed.
		Futhur details TBD
```
