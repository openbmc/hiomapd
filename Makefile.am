ACLOCAL_AMFLAGS = -I m4
sbin_PROGRAMS = mboxd

mboxd_SOURCES = mboxd.c common.c mboxd_dbus.c mboxd_flash.c mboxd_lpc.c mboxd_msg.c mboxd_windows.c
mboxd_LDFLAGS = $(LIBSYSTEMD_LIBS)
mboxd_CFLAGS = $(LIBSYSTEMD_CFLAGS)
