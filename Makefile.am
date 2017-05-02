ACLOCAL_AMFLAGS = -I m4
sbin_PROGRAMS = mboxd mboxctl

mboxd_SOURCES = \
	mboxd.c \
	common.c \
	mboxd_dbus.c \
	mboxd_flash.c \
	mboxd_lpc.c \
	mboxd_msg.c \
	mboxd_windows.c \
	mtd.c

if VIRTUAL_PNOR_ENABLED
mboxd_SOURCES += pnor_partition_table.cpp mboxd_pnor_partition_table.cpp
endif

mboxd_LDFLAGS = $(LIBSYSTEMD_LIBS) -lstdc++fs
if VIRTUAL_PNOR_ENABLED
mboxd_LDFLAGS += -lstdc++fs
endif
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

TEST_MBOX_SRCS = \
	mboxd_msg.c \
	mboxd_windows.c \
	mboxd_lpc.c \
	mboxd_flash.c \
	common.c
if VIRTUAL_PNOR_ENABLED
TEST_MBOX_SRCS += pnor_partition_table.cpp mboxd_pnor_partition_table.cpp
endif
TEST_MOCK_SRCS = test/tmpf.c test/mbox.c test/system.c

test_get_mbox_info_v2_SOURCES = test/get_mbox_info_v2.c \
				$(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)
if VIRTUAL_PNOR_ENABLED
test_get_mbox_info_v2_LDFLAGS = -lstdc++fs
endif

test_reset_state_SOURCES = test/reset_state.c \
			   $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)
if VIRTUAL_PNOR_ENABLED
test_reset_state_LDFLAGS = -lstdc++fs
endif

test_get_flash_info_v2_SOURCES = test/get_flash_info_v2.c \
				 $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)
if VIRTUAL_PNOR_ENABLED
test_get_flash_info_v2_LDFLAGS = -lstdc++fs
endif

test_create_read_window_v2_SOURCES = test/create_read_window_v2.c \
				     $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)
if VIRTUAL_PNOR_ENABLED
test_create_read_window_v2_LDFLAGS = -lstdc++fs
endif

test_create_write_window_v2_SOURCES = test/create_write_window_v2.c \
				      $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)
if VIRTUAL_PNOR_ENABLED
test_create_write_window_v2_LDFLAGS = -lstdc++fs
endif

test_close_window_v2_SOURCES = test/close_window_v2.c \
			       $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)
if VIRTUAL_PNOR_ENABLED
test_close_window_v2_LDFLAGS = -lstdc++fs
endif

test_mark_write_dirty_v2_SOURCES = test/mark_write_dirty_v2.c \
				   $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)
if VIRTUAL_PNOR_ENABLED
test_mark_write_dirty_v2_LDFLAGS = -lstdc++fs
endif

test_write_flush_v2_SOURCES = test/write_flush_v2.c \
			      $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)
if VIRTUAL_PNOR_ENABLED
test_write_flush_v2_LDFLAGS = -lstdc++fs
endif

test_mark_write_erased_v2_SOURCES = test/mark_write_erased_v2.c \
				    $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)
if VIRTUAL_PNOR_ENABLED
test_mark_write_erased_v2_LDFLAGS = -lstdc++fs
endif

test_bmc_event_ack_v2_SOURCES = test/bmc_event_ack_v2.c \
				$(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)
if VIRTUAL_PNOR_ENABLED
test_bmc_event_ack_v2_LDFLAGS = -lstdc++fs
endif

test_create_oversize_window_SOURCES = test/create_oversize_window.c \
				      $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)
if VIRTUAL_PNOR_ENABLED
test_create_oversize_window_LDFLAGS = -lstdc++fs
endif

test_create_zero_size_window_SOURCES = test/create_zero_size_window.c \
				       $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)
if VIRTUAL_PNOR_ENABLED
test_create_zero_size_window_LDFLAGS = -lstdc++fs
endif

test_implicit_flush_SOURCES = test/implicit_flush.c \
			     $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)
if VIRTUAL_PNOR_ENABLED
test_implicit_flush_LDFLAGS = -lstdc++fs
endif

test_request_high_version_SOURCES = test/request_high_version.c \
			     $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)
if VIRTUAL_PNOR_ENABLED
test_request_high_version_LDFLAGS = -lstdc++fs
endif

test_request_low_version_SOURCES = test/request_low_version.c \
			     $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)
if VIRTUAL_PNOR_ENABLED
test_request_low_version_LDFLAGS = -lstdc++fs
endif

test_mark_read_dirty_SOURCES = test/mark_read_dirty.c \
			     $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)
if VIRTUAL_PNOR_ENABLED
test_mark_read_dirty_LDFLAGS = -lstdc++fs
endif

test_read_window_write_flush_SOURCES = test/read_window_write_flush.c \
			     $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)
if VIRTUAL_PNOR_ENABLED
test_read_window_write_flush_LDFLAGS = -lstdc++fs
endif

test_read_window_mark_write_erased_SOURCES = test/read_window_mark_write_erased.c \
			     $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)
if VIRTUAL_PNOR_ENABLED
test_read_window_mark_write_erased_LDFLAGS = -lstdc++fs
endif

test_write_window_dirty_erase_SOURCES = test/write_window_dirty_erase.c \
			     $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)
if VIRTUAL_PNOR_ENABLED
test_write_window_dirty_erase_LDFLAGS = -lstdc++fs
endif

test_invalid_command_SOURCES = test/invalid_command.c \
			     $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)
if VIRTUAL_PNOR_ENABLED
test_invalid_command_LDFLAGS = -lstdc++fs
endif

test_read_window_cycle_SOURCES = test/read_window_cycle.c \
			     $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)
if VIRTUAL_PNOR_ENABLED
test_read_window_cycle_LDFLAGS = -lstdc++fs
endif

test_sequence_numbers_SOURCES = test/sequence_numbers.c \
			     $(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)
if VIRTUAL_PNOR_ENABLED
test_sequence_numbers_LDFLAGS = -lstdc++fs
endif

test_get_mbox_info_v2_timeout_SOURCES = test/get_mbox_info_v2_timeout.c \
					$(TEST_MBOX_SRCS) $(TEST_MOCK_SRCS)
if VIRTUAL_PNOR_ENABLED
test_get_mbox_info_v2_timeout_LDFLAGS = -lstdc++fs
endif

if VIRTUAL_PNOR_ENABLED
test_create_pnor_partition_table_SOURCES = \
	test/create_pnor_partition_table.cpp \
	common.c \
	pnor_partition_table.cpp
test_create_pnor_partition_table_LDFLAGS = -lstdc++fs
endif

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
		 test/mark_read_dirty \
		 test/read_window_write_flush \
		 test/read_window_mark_write_erased \
		 test/write_window_dirty_erase \
		 test/invalid_command \
		 test/read_window_cycle \
		 test/sequence_numbers \
		 test/get_mbox_info_v2_timeout
if VIRTUAL_PNOR_ENABLED
check_PROGRAMS += test/create_pnor_partition_table
endif

TESTS = $(check_PROGRAMS)
