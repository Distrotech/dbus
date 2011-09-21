## the "name-test" subdir in fact contains a bunch of tests now that need a temporary bus 
## to be running to do stuff with. The directory should be renamed.
## We want to build the current directory first to pick up the testutils lib
SUBDIRS= . name-test 
DIST_SUBDIRS=name-test

AM_CPPFLAGS = \
	-I$(top_srcdir) \
	$(GLIB_CFLAGS) \
	$(DBUS_GLIB_CFLAGS) \
	$(NULL)

# improve backtraces from test stuff
AM_LDFLAGS = @R_DYNAMIC_LDFLAG@

static_cppflags = \
	$(AM_CPPFLAGS) \
	-DDBUS_STATIC_BUILD \
	$(NULL)

libdbus_testutils_la_CPPFLAGS = \
	$(static_cppflags)
libdbus_testutils_la_SOURCES = \
	test-utils.c \
	test-utils.h \
	$(NULL)
libdbus_testutils_la_LIBADD = \
	$(top_builddir)/dbus/libdbus-internal.la \
	$(NULL)

noinst_LTLIBRARIES = libdbus-testutils.la

if DBUS_BUILD_TESTS
## break-loader removed for now
## most of these binaries are used in tests but are not themselves tests
TEST_BINARIES = \
	shell-test \
	spawn-test \
	test-exit \
	test-names \
	test-segfault \
	test-service \
	test-shell-service \
	test-sleep-forever \
	$(NULL)

## these are the things to run in make check (i.e. they are actual tests)
## (binaries in here must also be in TEST_BINARIES)
TESTS = \
	shell-test \
	$(NULL)

## These are conceptually part of directories that come earlier in SUBDIRS
## order, but we don't want to run them til we arrive in this directory,
## since they depend on stuff from this directory
TESTS += \
	../bus/bus-test$(EXEEXT) \
	../bus/bus-test-system$(EXEEXT) \
	../dbus/dbus-test$(EXEEXT) \
	$(NULL)

if DBUS_UNIX
TESTS += ../bus/bus-test-launch-helper$(EXEEXT)
endif

else !DBUS_BUILD_TESTS

TEST_BINARIES=
TESTS=

endif !DBUS_BUILD_TESTS

noinst_PROGRAMS= $(TEST_BINARIES)

test_service_CPPFLAGS = $(static_cppflags)
test_service_LDADD = libdbus-testutils.la
test_names_CPPFLAGS = $(static_cppflags)
test_names_LDADD = libdbus-testutils.la
## break_loader_CPPFLAGS = $(static_cppflags)
## break_loader_LDADD = $(top_builddir)/dbus/libdbus-internal.la
test_shell_service_CPPFLAGS = $(static_cppflags)
test_shell_service_LDADD = libdbus-testutils.la
shell_test_CPPFLAGS = $(static_cppflags)
shell_test_LDADD = libdbus-testutils.la
spawn_test_CPPFLAGS = $(static_cppflags)
spawn_test_LDADD = $(top_builddir)/dbus/libdbus-internal.la

test_refs_SOURCES = internals/refs.c
test_refs_CPPFLAGS = $(static_cppflags)
test_refs_LDADD = libdbus-testutils.la $(GLIB_LIBS)

test_syslog_SOURCES = internals/syslog.c
test_syslog_CPPFLAGS = $(static_cppflags)
test_syslog_LDADD = libdbus-testutils.la $(GLIB_LIBS)

EXTRA_DIST = dbus-test-runner

testexecdir = $(libdir)/dbus-1.0/test

testexec_PROGRAMS =

installable_tests = \
	test-corrupt \
	test-dbus-daemon \
	test-dbus-daemon-eavesdrop \
	test-loopback \
	test-marshal \
	test-refs \
	test-relay \
	test-syslog \
	$(NULL)

installcheck_tests =
installcheck_environment = \
	DBUS_TEST_DAEMON=$(DESTDIR)$(DBUS_DAEMONDIR)/dbus-daemon$(EXEEXT) \
	DBUS_TEST_SYSCONFDIR=$(DESTDIR)$(sysconfdir)

TESTS_ENVIRONMENT = \
	DBUS_BLOCK_ON_ABORT=1 \
	DBUS_FATAL_WARNINGS=1 \
	DBUS_TEST_DAEMON=@abs_top_builddir@/bus/dbus-daemon$(EXEEXT) \
	DBUS_TEST_DATA=@abs_top_builddir@/test/data \
	DBUS_TEST_HOMEDIR=@abs_top_builddir@/dbus \
	$(NULL)

test_corrupt_SOURCES = corrupt.c
test_corrupt_LDADD = $(top_builddir)/dbus/libdbus-1.la \
    $(GLIB_LIBS) \
    $(DBUS_GLIB_LIBS)

test_loopback_SOURCES = loopback.c
test_loopback_LDADD = $(top_builddir)/dbus/libdbus-1.la \
    $(GLIB_LIBS) \
    $(DBUS_GLIB_LIBS)

test_relay_SOURCES = relay.c
test_relay_LDADD = $(top_builddir)/dbus/libdbus-1.la \
    $(GLIB_LIBS) \
    $(DBUS_GLIB_LIBS)

test_dbus_daemon_SOURCES = dbus-daemon.c
test_dbus_daemon_LDADD = $(top_builddir)/dbus/libdbus-1.la \
    $(GLIB_LIBS) \
    $(DBUS_GLIB_LIBS)

test_dbus_daemon_eavesdrop_SOURCES = dbus-daemon-eavesdrop.c
test_dbus_daemon_eavesdrop_CPPFLAGS = $(GLIB_CFLAGS) $(DBUS_GLIB_CFLAGS)
test_dbus_daemon_eavesdrop_LDFLAGS = @R_DYNAMIC_LDFLAG@
test_dbus_daemon_eavesdrop_LDADD = $(top_builddir)/dbus/libdbus-1.la \
    $(GLIB_LIBS) \
    $(DBUS_GLIB_LIBS)

test_marshal_SOURCES = marshal.c
test_marshal_LDADD = $(top_builddir)/dbus/libdbus-1.la \
    $(GLIB_LIBS) \
    $(DBUS_GLIB_LIBS)

if DBUS_ENABLE_MODULAR_TESTS
TESTS += $(installable_tests)
installcheck_tests += $(installable_tests)

if DBUS_ENABLE_INSTALLED_TESTS
  testexec_PROGRAMS += $(installable_tests)
else !DBUS_ENABLE_INSTALLED_TESTS
  noinst_PROGRAMS += $(installable_tests)
endif !DBUS_ENABLE_INSTALLED_TESTS

endif DBUS_ENABLE_MODULAR_TESTS

# If we're installing the tests into a DESTDIR we can't run them
# again using the installed copy, because we don't know how to
# do a portable equivalent of setting LD_LIBRARY_PATH.
installcheck-local:
	$(MAKE) check-TESTS TESTS='$$(installcheck_tests)' \
		TESTS_ENVIRONMENT='$$(installcheck_environment)'
if DBUS_ENABLE_INSTALLED_TESTS
	test -n "$(DESTDIR)" || \
	$(installcheck_environment) \
		$(srcdir)/dbus-test-runner \
		$(testexecdir) \
		$(testexec_PROGRAMS)
endif DBUS_ENABLE_INSTALLED_TESTS

## keep these in creation order, i.e. uppermost dirs first 
TESTDIRS=					\
	data					\
	data/valid-messages			\
	data/invalid-messages			\
	data/incomplete-messages		\
	data/auth				\
	data/sha-1				\
	data/valid-config-files			\
	data/valid-config-files-system		\
	data/valid-config-files/basic.d		\
	data/valid-config-files/session.d	\
	data/valid-config-files/system.d	\
	data/valid-service-files		\
	data/valid-service-files-system		\
	data/invalid-service-files-system	\
	data/invalid-config-files		\
	data/invalid-config-files-system	\
	data/equiv-config-files			\
	data/equiv-config-files/basic		\
	data/equiv-config-files/basic/basic.d	\
	data/equiv-config-files/entities	\
	data/equiv-config-files/entities/basic.d


FIND_TESTS=find . -type f -a \( -name "*.message" -o -name "*.message-raw" -o -name "*.auth-script" -o -name "*.sha1" -o -name "*.txt" -o -name "*.conf" -o -name "*.service" \)

dist-hook:
	for D in $(TESTDIRS); do						\
		test -d $(distdir)/$$D || mkdir $(distdir)/$$D || exit 1 ;	\
	done ;									\
	FILES=`(cd $(srcdir) && $(FIND_TESTS) -o -name "*.in" -a -not -name Makefile.in | grep -Ev "(.svn|CVS)" )` ;					\
        for F in $$FILES; do							\
		B=`basename $$F`; \
		if test -e $$F.in; then \
			echo "-- Skipping file $$F (.in version exists)"; \
		elif test "x$$B" = xrun-with-tmp-session-bus.conf; then \
			echo "-- Skipping file $$F (generated)"; \
		elif test -e "$(top_srcdir)/bus/$$B"; then \
			echo "-- Skipping file $$F (from /bus/)"; \
		else \
			echo '-- Disting file '$$F ; \
			cp -f $(srcdir)/$$F $(distdir)/$$F || exit 1; \
		fi; \
	done

## copy tests to builddir so that generated tests and static tests 
## are all in one place.
all-local:
	$(AM_V_at)for D in $(TESTDIRS); do								\
		test -d $(top_builddir)/test/$$D || mkdir $(top_builddir)/test/$$D || exit 1 ;	\
	done ;											\
	if ! (test $(srcdir) = . || test $(srcdir) -ef .) ; then								\
		FILES=`(cd $(srcdir) && $(FIND_TESTS) | grep -Ev "(.svn|CVS)" )` ;					\
	        for F in $$FILES; do								\
			SRC=$(srcdir)/$$F ;							\
			DEST=$(top_builddir)/test/$$F ;						\
	                echo '-- Copying test file '$$F ;					\
			cp $$SRC $$DEST || exit 1 ;						\
			chmod u+w $$DEST || exit 1 ;						\
		done ;										\
	else											\
		echo '-- No need to copy test data as srcdir = builddir' ;			\
	fi ;											\
	echo '-- Copying' $(top_builddir)/bus/*.conf 'to test directory' ;			\
	cp $(top_builddir)/bus/*.conf $(top_builddir)/test/data/valid-config-files || exit 1 ;  \
	chmod u+w $(top_builddir)/test/data/valid-config-files/*.conf || exit 1

## this doesn't clean generated test data files when srcdir=builddir
clean-local:
	if test $(srcdir) != . ; then					\
		FILES=`(cd $(top_builddir)/test && $(FIND_TESTS) | grep -Ev "(.svn|CVS)" )` ;	\
	        for F in $$FILES; do					\
			DEST=$(top_builddir)/test/$$F ;			\
	                echo '-- Deleting test file '$$F ;		\
			rm $$DEST || exit 1 ;				\
		done ;							\
		REVERSEDIRS= ;						\
		for D in $(TESTDIRS); do				\
			REVERSEDIRS="$$D $$REVERSEDIRS" ;		\
		done ;							\
		for D in $$REVERSEDIRS; do				\
			rmdir $(top_builddir)/test/$$D || 		\
				test ! -d $(top_builddir)/test/$$D ||	\
				exit 1 ;	\
		done ;							\
	fi
