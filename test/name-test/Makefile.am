# Everything in this directory is statically-linked to libdbus-internal
AM_CPPFLAGS = \
	-I$(top_srcdir) \
	-DDBUS_COMPILATION \
	-DDBUS_STATIC_BUILD \
	$(NULL)

# if assertions are enabled, improve backtraces
AM_LDFLAGS = @R_DYNAMIC_LDFLAG@

## note that TESTS has special meaning (stuff to use in make check)
## so if adding tests not to be run in make check, don't add them to 
## TESTS
if DBUS_BUILD_TESTS
TESTS_ENVIRONMENT=DBUS_TOP_BUILDDIR=@abs_top_builddir@ DBUS_TOP_SRCDIR=@abs_top_srcdir@
TESTS=run-test.sh run-test-systemserver.sh
else
TESTS=
endif

EXTRA_DIST=run-test.sh run-test-systemserver.sh test-wait-for-echo.py test-activation-forking.py

if DBUS_BUILD_TESTS

## we use noinst_PROGRAMS not check_PROGRAMS for TESTS so that we
## build even when not doing "make check"
noinst_PROGRAMS=test-pending-call-dispatch test-pending-call-timeout test-threads-init test-ids test-shutdown test-privserver test-privserver-client test-autolaunch

test_pending_call_dispatch_SOURCES =		\
	test-pending-call-dispatch.c

test_pending_call_dispatch_LDADD=$(top_builddir)/dbus/libdbus-internal.la

test_pending_call_timeout_SOURCES =		\
	test-pending-call-timeout.c

test_pending_call_timeout_LDADD=$(top_builddir)/dbus/libdbus-internal.la

test_threads_init_SOURCES =            \
	test-threads-init.c

test_threads_init_LDADD=$(top_builddir)/dbus/libdbus-internal.la

test_ids_SOURCES =            \
	test-ids.c

test_ids_LDADD=$(top_builddir)/dbus/libdbus-internal.la

test_shutdown_SOURCES =            \
	test-shutdown.c

test_shutdown_CFLAGS=
test_shutdown_LDADD=../libdbus-testutils.la

test_privserver_SOURCES =            \
	test-privserver.c

test_privserver_CFLAGS=
test_privserver_LDADD=../libdbus-testutils.la

test_privserver_client_SOURCES =            \
	test-privserver-client.c

test_privserver_client_CFLAGS=
test_privserver_client_LDADD=../libdbus-testutils.la

test_autolaunch_SOURCES =            \
	test-autolaunch.c

test_autolaunch_CFLAGS=
test_autolaunch_LDADD=../libdbus-testutils.la

endif
