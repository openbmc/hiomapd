#!/bin/sh

AUTOCONF_FILES="Makefile.in aclocal.m4 ar-lib autom4te.cache compile \
        config.guess config.h.in config.sub configure depcomp install-sh \
        ltmain.sh missing *libtool test-driver"

case $1 in
    clean)
        test -f Makefile && make maintainer-clean
        test -d linux && find linux -type d -empty | xargs -r rm -rf
        for file in ${AUTOCONF_FILES}; do
            find -name "$file" | xargs -r rm -rf
        done
        exit 0
        ;;
esac

autoreconf -i

case $1 in
    dev)
        ./configure \
            CPPFLAGS="-UNDEBUG" \
            CFLAGS="-fsanitize=address -fsanitize=leak -fsanitize=undefined -Wall -Werror" \
            --enable-code-coverage
        ;;
    *)
        echo 'Run "./configure ${CONFIGURE_FLAGS} && make"'
        ;;
esac
