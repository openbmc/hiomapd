ACLOCAL_AMFLAGS = -I m4
sbin_PROGRAMS = mboxd mboxctl

mboxd_SOURCES = \
	mboxd.c \
	common.c \
	mboxd_dbus.c \
	mboxd_lpc.c \
	mboxd_msg.c \
	mboxd_windows.c \
	mtd.c
mboxd_LDFLAGS = $(LIBSYSTEMD_LIBS)
mboxd_CFLAGS = $(LIBSYSTEMD_CFLAGS)

if VIRTUAL_PNOR_ENABLED
mboxd_SOURCES += pnor_partition_table.cpp \
	mboxd_pnor_partition_table.cpp \
	mboxd_flash_virtual.cpp \
	pnor_partition.cpp \
	mboxd_lpc_virtual.cpp

mboxd_LDFLAGS += -lstdc++fs \
	$(SDBUSPLUS_LIBS) \
	$(PHOSPHOR_LOGGING_LIBS) \
	$(PHOSPHOR_DBUS_INTERFACES_LIBS)
else
mboxd_SOURCES += mboxd_flash_physical.c \
	mboxd_lpc_physical.c
endif

mboxctl_SOURCES = mboxctl.c
mboxctl_LDFLAGS = $(LIBSYSTEMD_LIBS)
mboxctl_CFLAGS = $(LIBSYSTEMD_CFLAGS)

@CODE_COVERAGE_RULES@

check_PROGRAMS =
XFAIL_TESTS =

include test/Makefile.am.include
include test/vpnor/Makefile.am.include

TESTS = $(check_PROGRAMS)
