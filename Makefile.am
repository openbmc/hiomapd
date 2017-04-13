ACLOCAL_AMFLAGS = -I m4
sbin_PROGRAMS = mboxd mboxctl

mboxd_SOURCES = mboxd.c common.c mboxd_dbus.c mboxd_flash.c mboxd_lpc.c mboxd_msg.c mboxd_windows.c mtd.c
mboxd_LDFLAGS = $(LIBSYSTEMD_LIBS)
mboxd_CFLAGS = $(LIBSYSTEMD_CFLAGS)

mboxctl_SOURCES = mboxctl.c
mboxctl_LDFLAGS = $(LIBSYSTEMD_LIBS)
mboxctl_CFLAGS = $(LIBSYSTEMD_CFLAGS)

@CODE_COVERAGE_RULES@

AM_LIBS = $(CODE_COVERAGE_LIBS)
AM_CPPFLAGS = $(CODE_COVERAGE_CPPFLAGS)
AM_CFLAGS = $(CODE_COVERAGE_CFLAGS)

test_sanity_SOURCES = test/sanity.c

test_copy_flash_SOURCES = test/copy_flash.c mboxd_flash.c common.c mtd.c test/tmpf.c

test_erase_flash_SOURCES = test/erase_flash.c mboxd_flash.c common.c test/tmpf.c

test_write_flash_SOURCES = test/write_flash.c mboxd_flash.c common.c test/tmpf.c

TEST_MBOX_SRCS = mboxd_msg.c mboxd_windows.c mboxd_lpc.c mboxd_flash.c common.c
TEST_MOCK_SRCS = test/tmpf.c test/mbox.c test/system.c

test_get_mbox_info_v2_SOURCES = test/get_mbox_info_v2.c \
				$(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)

test_reset_state_SOURCES = test/reset_state.c \
			   $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)

test_get_flash_info_v2_SOURCES = test/get_flash_info_v2.c \
				 $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)

test_create_read_window_v2_SOURCES = test/create_read_window_v2.c \
				     $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)

test_create_write_window_v2_SOURCES = test/create_write_window_v2.c \
				      $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)

test_close_window_v2_SOURCES = test/close_window_v2.c \
			       $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)

test_mark_write_dirty_v2_SOURCES = test/mark_write_dirty_v2.c \
				   $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)

test_write_flush_v2_SOURCES = test/write_flush_v2.c \
			      $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)

test_mark_write_erased_v2_SOURCES = test/mark_write_erased_v2.c \
				    $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)

test_bmc_event_ack_v2_SOURCES = test/bmc_event_ack_v2.c \
				$(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)

test_create_oversize_window_SOURCES = test/create_oversize_window.c \
				      $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)

test_create_zero_size_window_SOURCES = test/create_zero_size_window.c \
				       $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)

test_implicit_flush_SOURCES = test/implicit_flush.c \
			     $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)

test_request_high_version_SOURCES = test/request_high_version.c \
			     $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)

test_request_low_version_SOURCES = test/request_low_version.c \
			     $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)

test_mark_read_dirty_SOURCES = test/mark_read_dirty.c \
			     $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)

check_PROGRAMS = test/sanity \
		 test/copy_flash \
		 test/erase_flash \
		 test/write_flash \
		 test/get_mbox_info_v2 \
		 test/reset_state \
		 test/get_flash_info_v2 \
		 test/create_read_window_v2 \
		 test/create_write_window_v2 \
		 test/close_window_v2 \
		 test/mark_write_dirty_v2 \
		 test/write_flush_v2 \
		 test/mark_write_erased_v2 \
		 test/bmc_event_ack_v2 \
		 test/create_oversize_window \
		 test/create_zero_size_window \
		 test/implicit_flush \
		 test/request_high_version \
		 test/request_low_version \
		 test/mark_read_dirty 

TESTS = $(check_PROGRAMS)
