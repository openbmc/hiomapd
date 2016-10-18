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
The autotools of this requires the autotools-archive package for your
system

---

Notes on messages:

## Layout
```
Byte 0: COMMAND
Byte 1: Sequence
Byte 2-12: Data
Byte 13: Response code
Byte 14: Host controlled status reg
Byte 15: BMC controlled status reg
```
## Commands
```
RESET_STATE
GET_MBOX_INFO
GET_FLASH_INFO
READ_WINDOW
CLOSE_WINDOW
WRITE_WINDOW
WRITE_DIRTY
WRITE_FENCE
COMPLETED_COMMANDS
ACK
```
## Sequence
Unique message sequence number

## Responses
```
SUCCESS
PARAM_ERROR
WRITE_ERROR
SYSTEM_ERROR
TIMEOUT
```

## Information
- Interrupts via control regs
- Block size 4K
- All multibyte messages are little endian

### Commands in detail
```
	Command:
		RESET_STATE
	Data:
		-
	Response:
		-

	Command:
		GET_MBOX_INFO
	Data:
		Data 0: API version
	Response:
		Data 0: API version
		Data 1-2: read window size in blk size
		Data 3-4: write window size in blk size

	Command:
		CLOSE_WINDOW
		Data:
			-
		Response:
			-
	Command:
		GET_FLASH_INFO
		Data:
			-
		Response:
			Data 0-3: Flash size
			Data 4-7: Erase granule

	Command:
		READ_WINDOW
		Data:
			Data 0-1: Read window offset in blk size
		Response:
			Data 0-1: Read window pos in blk size

	Command:
		WRITE_WINDOW
		Data:
			Data 0-1: Write window offset in blk size
		Response:
			Data 0-1: Write window pos in blk size

	Command:
		WRITE_DIRTY
		Data:
			Data 0-1: Offset within window in blk size
			Data 2-5: Number of dirty bytes
		Response:
			-

	Command
		WRITE_FENCE
		Data:
			Data 0-1: Offset within window in blk size
			Data 2-5: Number of dirty bytes
		Response:
			-

	Command:
		ACK
		Data:
			Bits in the BMC reg to ack
		Response:
			*clears the bits*
			-

	Command:
		COMPLETED_COMMANDS
		Data:
			-
		Response:
			Data 0: Number of seq numbers to follow
			Data 1-N: Completed sequence numbers

	BMC notifications:
		If the BMC needs to tell the host something then it simply
		writes to Byte 15. The host should have interrupts enabled
		on that register, or otherwise be checking it regularly.
		 - BMC reboot
		 - Command complete
		   The host should issue a command complete request to find
		   out the sequence numbers to commands which have completed
```
