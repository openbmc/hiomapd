#include "config.h"

extern "C" {
#include "mbox.h"
#include "mboxd_msg.h"
};

#include "vpnor/mboxd_msg.hpp"

// clang-format off
const mboxd_mbox_handler vpnor_mbox_handlers[NUM_MBOX_CMDS] =
{
	mbox_handle_reset,
	mbox_handle_mbox_info,
	mbox_handle_flash_info,
	mbox_handle_read_window,
	mbox_handle_close_window,
	mbox_handle_write_window,
	mbox_handle_dirty_window,
	mbox_handle_flush_window,
	mbox_handle_ack,
	mbox_handle_erase_window
};
// clang-format on
