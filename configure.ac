# Initialization
AC_PREREQ([2.69])
AC_INIT([mboxd], [2.2.0], [https://github.com/openbmc/mboxbridge/issues])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([subdir-objects -Wall foreign dist-xz])
AM_SILENT_RULES([yes])
AC_CONFIG_MACRO_DIRS([m4])

# Checks for programs.
AC_PROG_CC
AM_PROG_AR
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for header files.
AC_CHECK_HEADER(linux/aspeed-lpc-ctrl.h,[HAVE_UAPI_LINUX_LPC_CTRL_H=""],[HAVE_UAPI_LINUX_LPC_CTRL_H="-I linux/aspeed-lpc-ctrl.h"])
AS_IF([test "$HAVE_UAPI_LINUX_LPC_CTRL_H" != ""],
    AC_MSG_WARN([Could not find linux/aspeed-lpc-ctrl.h: Attempting to download locally for building from https://git.kernel.org/pub/scm/linux/kernel/git/gregkh/char-misc.git/plain/include/uapi/linux/aspeed-lpc-ctrl.h?h=char-misc-next])
    AC_SUBST([BT_BMC_DL],[`test ! -f linux/aspeed-lpc-ctrl.h && mkdir -p linux && wget --quiet https://git.kernel.org/pub/scm/linux/kernel/git/gregkh/char-misc.git/plain/include/uapi/linux/aspeed-lpc-ctrl.h?h=char-misc-next -O linux/aspeed-lpc-ctrl.h`])
)

# Checks for typedefs, structures, and compiler characteristics.
AX_APPEND_COMPILE_FLAGS([-fpic -Wall], [CFLAGS])

# Checks for library functions.
LT_INIT # Removes 'unrecognized options: --with-libtool-sysroot'

AC_ARG_ENABLE([oe-sdk],
    AS_HELP_STRING([--enable-oe-sdk], [Link testcases absolutely against OE SDK so they can be ran within it.])
)
AC_ARG_VAR(OECORE_TARGET_SYSROOT,
    [Path to the OE SDK SYSROOT])
AS_IF([test "x$enable_oe_sdk" == "xyes"],
    AS_IF([test "x$OECORE_TARGET_SYSROOT" == "x"],
          AC_MSG_ERROR([OECORE_TARGET_SYSROOT must be set with --enable-oe-sdk])
    )
    AC_MSG_NOTICE([Enabling OE-SDK at $OECORE_TARGET_SYSROOT])
    [
        testcase_flags="-Wl,-rpath,\${OECORE_TARGET_SYSROOT}/lib"
        testcase_flags="${testcase_flags} -Wl,-rpath,\${OECORE_TARGET_SYSROOT}/usr/lib"
        testcase_flags="${testcase_flags} -Wl,-dynamic-linker,`find \${OECORE_TARGET_SYSROOT}/lib/ld-*.so | sort -r -n | head -n1`"
    ]
    AC_SUBST([OESDK_TESTCASE_FLAGS], [$testcase_flags])
)

AX_CODE_COVERAGE

PKG_CHECK_MODULES(LIBSYSTEMD, libsystemd, , AC_MSG_ERROR([libsytemd not found]))
AC_SUBST([LIBSYSTEMD_CFLAGS])
AC_SUBST([LIBSYSTEMD_LIBS])

# Create configured output
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
