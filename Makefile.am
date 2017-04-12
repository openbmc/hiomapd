ACLOCAL_AMFLAGS = -I m4
sbin_PROGRAMS = mboxd mboxctl

mboxd_SOURCES = mboxd.c common.c mboxd_dbus.c mboxd_flash.c mboxd_lpc.c mboxd_msg.c mboxd_windows.c mtd.c
mboxd_LDFLAGS = $(LIBSYSTEMD_LIBS)
mboxd_CFLAGS = $(LIBSYSTEMD_CFLAGS)

mboxctl_SOURCES = mboxctl.c
mboxctl_LDFLAGS = $(LIBSYSTEMD_LIBS)
mboxctl_CFLAGS = $(LIBSYSTEMD_CFLAGS)

test_copy_flash_SOURCES = test/copy_flash.c mboxd_flash.c common.c mtd.c test/tmpf.c
test_erase_flash_SOURCES = test/erase_flash.c mboxd_flash.c common.c test/tmpf.c
test_write_flash_SOURCES = test/write_flash.c mboxd_flash.c common.c test/tmpf.c

check_PROGRAMS = test/copy_flash test/erase_flash test/write_flash

TESTS = $(check_PROGRAMS)
