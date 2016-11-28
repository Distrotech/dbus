#!/bin/sh

# Copyright © 2015-2016 Collabora Ltd.
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

set -e
set -x

if [ -z "$dbus_ci_variant" ]; then
	dbus_ci_variant=production
fi

if [ -z "$dbus_ci_host" ]; then
	dbus_ci_host=native
fi

if [ -z "$dbus_ci_buildsys" ]; then
	dbus_ci_buildsys=autotools
fi

if [ -z "$dbus_ci_parallel" ]; then
	dbus_ci_parallel=1
fi

dbus_test=yes
dbus_test_fatal=yes

NOCONFIGURE=1 ./autogen.sh

srcdir="$(pwd)"
mkdir ci-build-${dbus_ci_variant}-${dbus_ci_host}
cd ci-build-${dbus_ci_variant}-${dbus_ci_host}

make="make -j${dbus_ci_parallel} V=1 VERBOSE=1"

case "$dbus_ci_host" in
	(mingw)
		mirror=http://sourceforge.net/projects/msys2/files/REPOS/MINGW/i686/
		mingw="$(pwd)/mingw32"
		install -d "${mingw}"
		export PKG_CONFIG_LIBDIR="${mingw}/lib/pkgconfig"
		export PKG_CONFIG_PATH=
		export PKG_CONFIG="pkg-config --define-variable=prefix=${mingw}"
		unset CC
		unset CXX
		for pkg in \
			expat-2.1.0-6 \
			gcc-libs-5.2.0-4 \
			gettext-0.19.6-1 \
			glib2-2.46.1-1 \
			libffi-3.2.1-3 \
			zlib-1.2.8-9 \
			; do
			wget ${mirror}/mingw-w64-i686-${pkg}-any.pkg.tar.xz
			tar -xvf mingw-w64-i686-${pkg}-any.pkg.tar.xz
		done
		export TMPDIR=/tmp
		;;
esac

case "$dbus_ci_buildsys" in
	(autotools)
		case "$dbus_ci_variant" in
			(debug)
				# Full developer/debug build.
				set _ "$@"
				set "$@" --enable-developer --enable-tests
				shift
				# The test coverage for OOM-safety is too
				# verbose to be useful on travis-ci.
				export DBUS_TEST_MALLOC_FAILURES=0
				;;

			(reduced)
				# A smaller configuration than normal, with
				# various features disabled; this emulates
				# an older system or one that does not have
				# all the optional libraries.
				set _ "$@"
				# No LSMs (the production build has both)
				set "$@" --disable-selinux --disable-apparmor
				# No inotify (we will use dnotify)
				set "$@" --disable-inotify
				# No epoll or kqueue (we will use poll)
				set "$@" --disable-epoll --disable-kqueue
				# No special init system support
				set "$@" --disable-launchd --disable-systemd
				# No libaudit or valgrind
				set "$@" --disable-libaudit --without-valgrind
				shift
				;;

			(legacy)
				# An unrealistically cut-down configuration,
				# to check that it compiles and works.
				set _ "$@"
				# Disable native atomic operations on Unix
				# (armv4, as used as the baseline for Debian
				# armel, is one architecture that really
				# doesn't have them)
				set "$@" dbus_cv_sync_sub_and_fetch=no
				# No epoll, kqueue or poll (we will fall back
				# to select, even on Unix where we would
				# usually at least have poll)
				set "$@" --disable-epoll --disable-kqueue
				set "$@" CPPFLAGS=-DBROKEN_POLL=1
				# Enable SELinux and AppArmor but not
				# libaudit - that configuration has sometimes
				# failed
				set "$@" --enable-selinux --enable-apparmor
				set "$@" --disable-libaudit --without-valgrind
				# No directory monitoring at all
				set "$@" --disable-inotify --disable-dnotify
				# No special init system support
				set "$@" --disable-launchd --disable-systemd
				# No X11 autolaunching
				set "$@" --disable-x11-autolaunch
				shift
				;;

			(*)
				;;
		esac

		case "$dbus_ci_host" in
			(mingw)
				set _ "$@"
				set "$@" --build="$(build-aux/config.guess)"
				set "$@" --host=i686-w64-mingw32
				set "$@" LDFLAGS=-L"${mingw}/lib"
				set "$@" CPPFLAGS=-I"${mingw}/include"
				set "$@" CFLAGS=-static-libgcc
				set "$@" CXXFLAGS=-static-libgcc
				# don't run tests yet, Wine needs Xvfb and
				# more msys2 libraries
				dbus_test=
				# don't "make install" system-wide
				dbus_ci_sudo=
				shift
				;;
		esac

		../configure \
			--enable-installed-tests \
			--enable-maintainer-mode \
			--enable-modular-tests \
			--with-glib \
			"$@"

		${make}
		[ -z "$dbus_test" ] || ${make} check || [ -z "$dbus_test_fatal" ]
		cat test/test-suite.log || :
		[ -z "$dbus_test" ] || ${make} distcheck || \
			[ -z "$dbus_test_fatal" ]

		${make} install DESTDIR=$(pwd)/DESTDIR
		( cd DESTDIR && find . )

		if [ -n "$dbus_ci_sudo" ] && [ -n "$dbus_test" ]; then
			sudo ${make} install
			LD_LIBRARY_PATH=/usr/local/lib ${make} installcheck || \
				[ -z "$dbus_test_fatal" ]
			cat test/test-suite.log || :

			# re-run them with gnome-desktop-testing
			env LD_LIBRARY_PATH=/usr/local/lib \
			gnome-desktop-testing-runner -d /usr/local/share dbus/ || \
				[ -z "$dbus_test_fatal" ]

			# these tests benefit from being re-run as root
			sudo env LD_LIBRARY_PATH=/usr/local/lib \
			gnome-desktop-testing-runner -d /usr/local/share \
				dbus/test-uid-permissions_with_config.test || \
				[ -z "$dbus_test_fatal" ]
		fi
		;;

	(cmake)
		case "$dbus_ci_host" in
			(mingw)
				set _ "$@"
				set "$@" -D CMAKE_TOOLCHAIN_FILE="${srcdir}/cmake/i686-w64-mingw32.cmake"
				set "$@" -D CMAKE_PREFIX_PATH="${mingw}"
				set "$@" -D CMAKE_INCLUDE_PATH="${mingw}/include"
				set "$@" -D CMAKE_LIBRARY_PATH="${mingw}/lib"
				set "$@" -D EXPAT_LIBRARY="${mingw}/lib/libexpat.dll.a"
				set "$@" -D GLIB2_LIBRARIES="${mingw}/lib/libglib-2.0.dll.a"
				set "$@" -D GOBJECT_LIBRARIES="${mingw}/lib/libgobject-2.0.dll.a"
				set "$@" -D GIO_LIBRARIES="${mingw}/lib/libgio-2.0.dll.a"
				shift
				# don't run tests yet, Wine needs Xvfb and more
				# msys2 libraries
				dbus_test=
				;;
		esac

		cmake "$@" ../cmake

		${make}
		# The test coverage for OOM-safety is too verbose to be useful on
		# travis-ci.
		export DBUS_TEST_MALLOC_FAILURES=0
		[ -z "$dbus_test" ] || ctest -VV || [ -z "$dbus_test_fatal" ]
		${make} install DESTDIR=$(pwd)/DESTDIR
		( cd DESTDIR && find . )
		;;
esac
