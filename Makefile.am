ACLOCAL_AMFLAGS = -I m4
sbin_PROGRAMS = mboxd mboxctl

mboxd_SOURCES = \
	mboxd.c \
	common.c \
	control.c \
	control_legacy.c \
	control_dbus.c \
	lpc.c \
	protocol.c \
	transport_dbus.c \
	transport_mbox.c \
	windows.c \
	mtd.c
mboxd_LDFLAGS = $(LIBSYSTEMD_LIBS)
mboxd_CFLAGS = $(LIBSYSTEMD_CFLAGS)

if VIRTUAL_PNOR_ENABLED
include vpnor/Makefile.am.include
else
mboxd_SOURCES += flash.c \
	lpc_reset.c \
	protocol_negotiate_version.c
endif

mboxctl_SOURCES = mboxctl.c
mboxctl_LDFLAGS = $(LIBSYSTEMD_LIBS)
mboxctl_CFLAGS = $(LIBSYSTEMD_CFLAGS)

@CODE_COVERAGE_RULES@

check_PROGRAMS =
XFAIL_TESTS =

AM_LIBS = $(CODE_COVERAGE_LIBS)
AM_CPPFLAGS = $(CODE_COVERAGE_CPPFLAGS) -UNDEBUG
AM_CFLAGS = $(CODE_COVERAGE_CFLAGS)
AM_CXXFLAGS = $(CODE_COVERAGE_CXXFLAGS)

include test/Makefile.am.include
include vpnor/test/Makefile.am.include

TESTS = $(check_PROGRAMS)

cscope.files: clean-cscope cscopelist-unique

cscopelist-unique: cscopelist
	sort -u cscope.files > cscope.files.u && mv cscope.files.u cscope.files
