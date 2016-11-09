## the "name-test" subdir in fact contains a bunch of tests now that need a temporary bus 
## to be running to do stuff with. The directory should be renamed.
## We want to build the current directory first to pick up the testutils lib
SUBDIRS= . name-test 
DIST_SUBDIRS=name-test

CLEANFILES =
EXTRA_DIST =

AM_CPPFLAGS = \
	-I$(top_srcdir) \
	$(DBUS_STATIC_BUILD_CPPFLAGS) \
	-DDBUS_COMPILATION \
	$(GLIB_CFLAGS) \
	$(NULL)

# improve backtraces from test stuff
AM_LDFLAGS = @R_DYNAMIC_LDFLAG@

noinst_LTLIBRARIES = libdbus-testutils.la

libdbus_testutils_la_SOURCES = \
	test-utils.c \
	test-utils.h \
	$(NULL)

if DBUS_WITH_GLIB
libdbus_testutils_la_SOURCES += \
	test-utils-glib.c \
	test-utils-glib.h \
	$(NULL)
endif

libdbus_testutils_la_LIBADD = \
	$(top_builddir)/dbus/libdbus-1.la \
	$(top_builddir)/dbus/libdbus-internal.la \
	$(NULL)

TEST_EXTENSIONS = .sh

LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) $(top_srcdir)/build-aux/tap-driver.sh
LOG_COMPILER = $(srcdir)/glib-tap-test.sh
SH_LOG_DRIVER = $(LOG_DRIVER)
SH_LOG_COMPILER = $(SHELL)
EXTRA_DIST += glib-tap-test.sh
EXTRA_DIST += tap-test.sh.in

TESTS =

if DBUS_ENABLE_EMBEDDED_TESTS
## break-loader removed for now
## these binaries are used in tests but are not themselves tests
TEST_BINARIES = \
	test-spawn \
	test-exit \
	test-names \
	test-segfault \
	test-service \
	test-shell-service \
	test-sleep-forever \
	$(NULL)

## These are conceptually part of directories that come earlier in SUBDIRS
## order, but we don't want to run them til we arrive in this directory,
## since they depend on stuff from this directory. We wrap them in a
## simple shell script to get TAP output.

wrap_bus_tests = test-bus.sh
wrap_dbus_tests = test-dbus.sh

if DBUS_UNIX
wrap_bus_tests += test-bus-launch-helper.sh
wrap_bus_tests += test-bus-system.sh
endif

TESTS += $(wrap_bus_tests) $(wrap_dbus_tests)
CLEANFILES += $(wrap_bus_tests) $(wrap_dbus_tests)

$(wrap_bus_tests): test-bus%.sh: ../bus/test-bus%$(EXEEXT) tap-test.sh.in Makefile
	sed -e 's![@]RUN[@]!$<!' \
		< $(srcdir)/tap-test.sh.in > $@

$(wrap_dbus_tests): test-dbus%.sh: ../dbus/test-dbus%$(EXEEXT) tap-test.sh.in Makefile
	sed -e 's![@]RUN[@]!$<!' \
		< $(srcdir)/tap-test.sh.in > $@

else !DBUS_ENABLE_EMBEDDED_TESTS

TEST_BINARIES=

endif !DBUS_ENABLE_EMBEDDED_TESTS

noinst_PROGRAMS= $(TEST_BINARIES)

test_service_LDADD = libdbus-testutils.la
test_names_LDADD = libdbus-testutils.la
## break_loader_LDADD = $(top_builddir)/dbus/libdbus-internal.la
test_shell_service_LDADD = libdbus-testutils.la
test_shell_SOURCES = shell-test.c
test_shell_LDADD = libdbus-testutils.la
test_spawn_SOURCES = spawn-test.c
test_spawn_LDADD = $(top_builddir)/dbus/libdbus-internal.la

test_printf_SOURCES = internals/printf.c
test_printf_LDADD = $(top_builddir)/dbus/libdbus-internal.la

test_refs_SOURCES = internals/refs.c
test_refs_LDADD = libdbus-testutils.la $(GLIB_LIBS)

test_syslog_SOURCES = internals/syslog.c
test_syslog_LDADD = libdbus-testutils.la $(GLIB_LIBS)

manual_dir_iter_SOURCES = manual-dir-iter.c
manual_dir_iter_LDADD = $(top_builddir)/dbus/libdbus-internal.la

manual_paths_SOURCES = manual-paths.c
manual_paths_LDADD = $(top_builddir)/dbus/libdbus-internal.la

manual_tcp_SOURCES = manual-tcp.c
manual_tcp_LDADD = $(top_builddir)/dbus/libdbus-internal.la

EXTRA_DIST += dbus-test-runner

testexecdir = $(libexecdir)/installed-tests/dbus
testmetadir = $(datadir)/installed-tests/dbus

dist_testexec_SCRIPTS =
testexec_PROGRAMS =
testmeta_DATA =

installable_tests = \
	test-shell \
	test-printf \
	$(NULL)
installable_manual_tests = \
	manual-dir-iter \
	manual-tcp \
	$(NULL)
dist_installable_test_scripts = \
	$(NULL)

if DBUS_WIN
installable_manual_tests += manual-paths
endif

if DBUS_WITH_GLIB
installable_tests += \
	test-corrupt \
	test-dbus-daemon \
	test-dbus-daemon-eavesdrop \
	test-fdpass \
	test-monitor \
	test-loopback \
	test-marshal \
	test-refs \
	test-relay \
	test-syntax \
	test-syslog \
	test-uid-permissions \
	$(NULL)

if DBUS_UNIX
installable_tests += \
	test-sd-activation \
	$(NULL)

dist_installable_test_scripts += \
	test-dbus-daemon-fork.sh \
	$(NULL)

# Testing dbus-launch relies on special code in that binary.
if DBUS_ENABLE_EMBEDDED_TESTS
dist_installable_test_scripts += \
	test-dbus-launch-eval.sh \
	$(NULL)

if DBUS_ENABLE_X11_AUTOLAUNCH
dist_installable_test_scripts += \
	test-dbus-launch-x11.sh \
	$(NULL)
endif DBUS_ENABLE_X11_AUTOLAUNCH
endif DBUS_ENABLE_EMBEDDED_TESTS

endif DBUS_UNIX

installable_manual_tests += \
	manual-authz \
	$(NULL)
endif DBUS_WITH_GLIB

installable_test_meta = \
	$(dist_installable_test_scripts:=.test) \
	$(installable_tests:=.test) \
	$(NULL)
installable_test_meta_with_config = \
	$(dist_installable_test_scripts:=_with_config.test) \
	$(installable_tests:=_with_config.test) \
	$(NULL)

installcheck_tests =
installcheck_environment = \
	export XDG_RUNTIME_DIR=@abs_top_builddir@/test/XDG_RUNTIME_DIR; \
	export DBUS_TEST_DAEMON=$(DESTDIR)$(DBUS_DAEMONDIR)/dbus-daemon$(EXEEXT); \
	export DBUS_TEST_DBUS_LAUNCH=$(DESTDIR)$(bindir)/dbus-launch$(EXEEXT); \
	export DBUS_TEST_DBUS_MONITOR=$(DESTDIR)$(bindir)/dbus-monitor$(EXEEXT); \
	export DBUS_TEST_DBUS_SEND=$(DESTDIR)$(bindir)/dbus-send$(EXEEXT); \
	export DBUS_TEST_HOMEDIR=@abs_top_builddir@/dbus; \
	export DBUS_TEST_DATADIR=$(DESTDIR)$(datadir); \
	${NULL}

AM_TESTS_ENVIRONMENT = \
	export XDG_RUNTIME_DIR=@abs_top_builddir@/test/XDG_RUNTIME_DIR; \
	export DBUS_FATAL_WARNINGS=1; \
	export DBUS_TEST_DAEMON=@abs_top_builddir@/bus/dbus-daemon$(EXEEXT); \
	export DBUS_TEST_DBUS_LAUNCH=@abs_top_builddir@/tools/dbus-launch$(EXEEXT); \
	export DBUS_TEST_DBUS_MONITOR=@abs_top_builddir@/tools/dbus-monitor$(EXEEXT); \
	export DBUS_TEST_DBUS_SEND=@abs_top_builddir@/tools/dbus-send$(EXEEXT); \
	export DBUS_TEST_DATA=@abs_top_builddir@/test/data; \
	export DBUS_TEST_HOMEDIR=@abs_top_builddir@/dbus; \
	$(NULL)

manual_authz_SOURCES = manual-authz.c
manual_authz_LDADD = \
    libdbus-testutils.la \
    $(GLIB_LIBS) \
    $(NULL)

test_corrupt_SOURCES = corrupt.c
test_corrupt_LDADD = \
    libdbus-testutils.la \
    $(GLIB_LIBS) \
    $(NULL)

test_loopback_SOURCES = loopback.c
test_loopback_LDADD = \
    libdbus-testutils.la \
    $(GLIB_LIBS) \
    $(NULL)

test_relay_SOURCES = relay.c
test_relay_LDADD = \
    libdbus-testutils.la \
    $(GLIB_LIBS) \
    $(NULL)

test_dbus_daemon_SOURCES = dbus-daemon.c
test_dbus_daemon_LDADD = \
    libdbus-testutils.la \
    $(GLIB_LIBS) \
    $(NULL)

test_dbus_daemon_eavesdrop_SOURCES = dbus-daemon-eavesdrop.c
test_dbus_daemon_eavesdrop_LDADD = \
    libdbus-testutils.la \
    $(GLIB_LIBS) \
    $(NULL)

if DBUS_UNIX
test_sd_activation_SOURCES = \
    sd-activation.c \
    $(NULL)
test_sd_activation_LDADD = \
    libdbus-testutils.la \
    $(GLIB_LIBS) \
    $(NULL)
endif

test_marshal_SOURCES = marshal.c
test_marshal_LDADD = \
    libdbus-testutils.la \
    $(GLIB_LIBS) \
    $(NULL)

test_monitor_SOURCES = \
    monitor.c \
    $(NULL)
test_monitor_LDADD = \
    libdbus-testutils.la \
    $(GLIB_LIBS) \
    $(NULL)

test_syntax_SOURCES = syntax.c
test_syntax_LDADD = \
    libdbus-testutils.la \
    $(GLIB_LIBS) \
    $(NULL)

test_uid_permissions_SOURCES = \
    uid-permissions.c \
    $(NULL)
test_uid_permissions_LDADD = \
    libdbus-testutils.la \
    $(GLIB_LIBS) \
    $(NULL)

test_fdpass_SOURCES = \
    fdpass.c \
    $(NULL)
test_fdpass_LDADD = \
    libdbus-testutils.la \
    $(GLIB_LIBS) \
    $(NULL)

TESTS += $(dist_installable_test_scripts)
installcheck_tests += $(dist_installable_test_scripts)

if DBUS_ENABLE_MODULAR_TESTS
TESTS += $(installable_tests)
installcheck_tests += $(installable_tests)

if DBUS_ENABLE_INSTALLED_TESTS
  testexec_PROGRAMS += $(installable_tests) $(installable_manual_tests)
  dist_testexec_SCRIPTS += $(dist_installable_test_scripts)

  testmeta_DATA += $(installable_test_meta)
  testmeta_DATA += $(installable_test_meta_with_config)
else !DBUS_ENABLE_INSTALLED_TESTS
  noinst_PROGRAMS += $(installable_tests) $(installable_manual_tests)
endif !DBUS_ENABLE_INSTALLED_TESTS

endif DBUS_ENABLE_MODULAR_TESTS

# If we're installing the tests into a DESTDIR we can't run them
# again using the installed copy, because we don't know how to
# do a portable equivalent of setting LD_LIBRARY_PATH.
installcheck-local:
	$(MAKE) check-TESTS TESTS='$$(installcheck_tests)' \
		AM_TESTS_ENVIRONMENT='$$(installcheck_environment)'
if DBUS_ENABLE_INSTALLED_TESTS
	test -n "$(DESTDIR)" || { \
	$(installcheck_environment) \
		$(srcdir)/dbus-test-runner \
		$(testexecdir) \
		$(installable_tests); }
endif DBUS_ENABLE_INSTALLED_TESTS

in_data = \
	data/valid-config-files-system/debug-allow-all-fail.conf.in \
	data/valid-config-files-system/debug-allow-all-pass.conf.in \
	data/valid-config-files/debug-allow-all-sha1.conf.in \
	data/valid-config-files/debug-allow-all.conf.in \
	data/valid-config-files/finite-timeout.conf.in \
	data/valid-config-files/forbidding.conf.in \
	data/valid-config-files/incoming-limit.conf.in \
	data/valid-config-files/multi-user.conf.in \
	data/valid-config-files/systemd-activation.conf.in \
	data/invalid-service-files-system/org.freedesktop.DBus.TestSuiteNoExec.service.in \
	data/invalid-service-files-system/org.freedesktop.DBus.TestSuiteNoService.service.in \
	data/invalid-service-files-system/org.freedesktop.DBus.TestSuiteNoUser.service.in \
	data/valid-service-files-system/org.freedesktop.DBus.TestSuiteEchoService.service.in \
	data/valid-service-files-system/org.freedesktop.DBus.TestSuiteSegfaultService.service.in \
	data/valid-service-files-system/org.freedesktop.DBus.TestSuiteShellEchoServiceFail.service.in \
	data/valid-service-files-system/org.freedesktop.DBus.TestSuiteShellEchoServiceSuccess.service.in \
	data/valid-service-files/org.freedesktop.DBus.TestSuite.PrivServer.service.in \
	data/valid-service-files/org.freedesktop.DBus.TestSuiteEchoService.service.in \
	data/valid-service-files/org.freedesktop.DBus.TestSuiteForkingEchoService.service.in \
	data/valid-service-files/org.freedesktop.DBus.TestSuiteSegfaultService.service.in \
	data/valid-service-files/org.freedesktop.DBus.TestSuiteShellEchoServiceFail.service.in \
	data/valid-service-files/org.freedesktop.DBus.TestSuiteShellEchoServiceSuccess.service.in \
	$(NULL)

EXTRA_DIST += $(in_data)

static_data = \
	name-test/tmp-session-like-system.conf \
	data/auth/anonymous-client-successful.auth-script \
	data/auth/anonymous-server-successful.auth-script \
	data/auth/cancel.auth-script \
	data/auth/client-out-of-mechanisms.auth-script \
	data/auth/external-failed.auth-script \
	data/auth/external-root.auth-script \
	data/auth/external-silly.auth-script \
	data/auth/external-successful.auth-script \
	data/auth/extra-bytes.auth-script \
	data/auth/fail-after-n-attempts.auth-script \
	data/auth/fallback.auth-script \
	data/auth/invalid-command-client.auth-script \
	data/auth/invalid-command.auth-script \
	data/auth/invalid-hex-encoding.auth-script \
	data/auth/mechanisms.auth-script \
	data/equiv-config-files/basic/basic-1.conf \
	data/equiv-config-files/basic/basic-2.conf \
	data/equiv-config-files/basic/basic.d/basic.conf \
	data/equiv-config-files/entities/basic.d/basic.conf \
	data/equiv-config-files/entities/entities-1.conf \
	data/equiv-config-files/entities/entities-2.conf \
	data/incomplete-messages/missing-body.message \
	data/invalid-config-files/badselinux-1.conf \
	data/invalid-config-files/badselinux-2.conf \
	data/invalid-config-files/circular-1.conf \
	data/invalid-config-files/circular-2.conf \
	data/invalid-config-files/circular-3.conf \
	data/invalid-config-files/not-well-formed.conf \
	data/invalid-config-files/truncated-file.conf \
	data/invalid-messages/array-of-nil.message \
	data/invalid-messages/array-with-mixed-types.message \
	data/invalid-messages/bad-boolean-array.message \
	data/invalid-messages/bad-boolean.message \
	data/invalid-messages/bad-endian.message \
	data/invalid-messages/bad-header-field-alignment.message \
	data/invalid-messages/boolean-has-no-value.message-raw \
	data/invalid-messages/local-namespace.message \
	data/invalid-messages/no-dot-in-name.message \
	data/invalid-messages/not-nul-header-padding.message \
	data/invalid-messages/overlong-name.message \
	data/invalid-messages/too-little-header-padding.message \
	data/invalid-messages/too-much-header-padding-by-far.message \
	data/invalid-messages/too-much-header-padding.message \
	data/invalid-messages/too-short-dict.message \
	data/sha-1/Readme.txt \
	data/sha-1/bit-hashes.sha1 \
	data/sha-1/bit-messages.sha1 \
	data/sha-1/byte-hashes.sha1 \
	data/sha-1/byte-messages.sha1 \
	data/systemd-activation/com.example.SystemdActivatable1.service \
	data/systemd-activation/com.example.SystemdActivatable2.service \
	data/systemd-activation/com.example.SystemdActivatable3.service \
	data/systemd-activation/org.freedesktop.systemd1.service \
	data/valid-config-files/basic.conf \
	data/valid-config-files/basic.d/basic.conf \
	data/valid-config-files/entities.conf \
	data/valid-config-files/listen-unix-runtime.conf \
	data/valid-config-files/many-rules.conf \
	data/valid-config-files-system/system.d/test.conf \
	data/valid-messages/array-of-array-of-uint32.message \
	data/valid-messages/dict-simple.message \
	data/valid-messages/dict.message \
	data/valid-messages/emptiness.message \
	data/valid-messages/lots-of-arguments.message \
	data/valid-messages/no-padding.message \
	data/valid-messages/opposite-endian.message \
	data/valid-messages/recursive-types.message \
	data/valid-messages/simplest-manual.message \
	data/valid-messages/simplest.message \
	data/valid-messages/standard-acquire-service.message \
	data/valid-messages/standard-hello.message \
	data/valid-messages/standard-list-services.message \
	data/valid-messages/standard-service-exists.message \
	data/valid-messages/unknown-header-field.message \
	$(NULL)

EXTRA_DIST += $(static_data)

## copy tests to builddir so that generated tests and static tests
## are all in one place.
all-local: copy-config-local uninstalled-config-local
	@:

copy-config-local:
	$(AM_V_at)$(MKDIR_P) data/valid-config-files/session.d
	$(AM_V_GEN)set -e; \
	if test $(srcdir) = . || test $(srcdir) -ef .; then \
		echo '-- No need to copy test data as srcdir = builddir'; \
	else \
		for F in $(static_data); do \
			$(MKDIR_P) "$${F%/*}"; \
			rm -f "$$F"; \
			cp $(srcdir)/"$$F" "$$F"; \
		done; \
	fi

uninstalled-config-local:
	$(AM_V_GEN)set -e; \
	for F in $(in_data); do \
		$(MKDIR_P) "$${F%/*}"; \
		sed \
			-e 's,[@]DBUS_TEST_DATA[@],@abs_builddir@/data,' \
			-e 's,[@]DBUS_TEST_EXEC[@],@abs_builddir@,' \
			-e 's,[@]EXEEXT[@],$(EXEEXT),' \
			-e 's,[@]TEST_LAUNCH_HELPER_BINARY[@],@abs_top_builddir@/bus/dbus-daemon-launch-helper-test$(EXEEXT),' \
			-e 's,[@]TEST_LISTEN[@],$(TEST_LISTEN),' \
			< $(srcdir)/"$$F" > "$${F%.in}"; \
	done

installable-config-local:
if DBUS_ENABLE_INSTALLED_TESTS
	$(AM_V_GEN)set -e; \
	for F in $(in_data); do \
		$(MKDIR_P) "installable/$${F%/*}"; \
		sed \
			-e 's,[@]DBUS_TEST_DATA[@],$(testexecdir)/data,' \
			-e 's,[@]DBUS_TEST_EXEC[@],$(testexecdir),' \
			-e 's,[@]EXEEXT[@],$(EXEEXT),' \
			-e 's,[@]TEST_LAUNCH_HELPER_BINARY[@],/bin/false,' \
			-e 's,[@]TEST_LISTEN[@],$(TEST_LISTEN),' \
			< $(srcdir)/"$$F" > "installable/$${F%.in}"; \
	done
else
	@:
endif


install-data-local: install-config-local
	@:

install-config-local: installable-config-local
if DBUS_ENABLE_INSTALLED_TESTS
	$(AM_V_GEN)set -e; \
	for F in $(static_data); do \
		install -d "$(DESTDIR)$(testexecdir)/$${F%/*}"; \
		install -m644 "$(srcdir)/$$F" "$(DESTDIR)$(testexecdir)/$$F"; \
	done; \
	for F in $(in_data); do \
		install -d "$(DESTDIR)$(testexecdir)/$${F%/*}"; \
		install -m644 "installable/$${F%.in}" "$(DESTDIR)$(testexecdir)/$${F%.in}"; \
	done
	ln -nfs $(datadir)/dbus-1/session.conf $(DESTDIR)$(testexecdir)/data/valid-config-files/session.conf
	ln -nfs $(datadir)/dbus-1/system.conf $(DESTDIR)$(testexecdir)/data/valid-config-files-system/system.conf
else
	@:
endif

## this doesn't clean most copied test data files when srcdir=builddir
clean-local:
	$(AM_V_at)if test $(srcdir) = . || test $(srcdir) -ef .; then \
		echo '-- No need to clean test data as srcdir = builddir'; \
	else \
		rm -f $(static_data); \
		for F in $(in_data); do \
			rm -f "$${F%.in}"; \
		done; \
	fi

imported_data = \
	data/valid-config-files/session.conf \
	data/valid-config-files-system/system.conf \
	$(NULL)

noinst_DATA = $(imported_data)
CLEANFILES += \
	$(noinst_DATA) \
	XDG_RUNTIME_DIR \
	installable \
	$(NULL)

data/valid-config-files/session.conf: $(top_builddir)/bus/session.conf
	$(AM_V_at)$(MKDIR_P) data/valid-config-files
	$(AM_V_GEN)cp $< $@

data/valid-config-files-system/system.conf: $(top_builddir)/bus/system.conf
	$(AM_V_at)$(MKDIR_P) data/valid-config-files-system
	$(AM_V_GEN)cp $< $@

$(installable_test_meta): %.test: %$(EXEEXT) Makefile
	$(AM_V_GEN) ( \
		echo '[Test]'; \
		echo 'Type=session'; \
		echo 'Output=TAP'; \
		echo 'Exec=env $(testexecdir)/$* --tap'; \
	) > $@.tmp && mv $@.tmp $@

$(installable_test_meta_with_config): %_with_config.test: %$(EXEEXT) Makefile
	$(AM_V_GEN) ( \
		echo '[Test]'; \
		echo 'Type=session'; \
		echo 'Output=TAP'; \
		echo 'Exec=env DBUS_TEST_DATA=$(testexecdir)/data $(testexecdir)/$* --tap'; \
	) > $@.tmp && mv $@.tmp $@
