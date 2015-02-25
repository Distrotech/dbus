AM_CPPFLAGS = \
	-I$(top_srcdir) \
	$(DBUS_STATIC_BUILD_CPPFLAGS) \
	$(DBUS_X_CFLAGS) \
	-DDBUS_COMPILATION \
	-DDBUS_MACHINE_UUID_FILE=\""$(localstatedir)/lib/dbus/machine-id"\" \
	$(NULL)

# if assertions are enabled, improve backtraces
AM_LDFLAGS = @R_DYNAMIC_LDFLAG@

bin_PROGRAMS = \
	dbus-launch \
	dbus-monitor \
	dbus-send \
	dbus-test-tool \
	dbus-update-activation-environment \
	$(NULL)

if DBUS_UNIX
bin_PROGRAMS += \
	dbus-cleanup-sockets \
	dbus-run-session \
	dbus-uuidgen \
	$(NULL)
endif

dbus_send_SOURCES=				\
	dbus-print-message.c			\
	dbus-print-message.h			\
	dbus-send.c \
	tool-common.c \
	tool-common.h \
	$(NULL)

dbus_monitor_SOURCES = \
	dbus-monitor.c \
	dbus-print-message.c \
	dbus-print-message.h \
	tool-common.c \
	tool-common.h \
	$(NULL)

if DBUS_WIN
dbus_launch_SOURCES=				\
	dbus-launch-win.c			\
	dbus-launch.h
else
dbus_launch_SOURCES=				\
	dbus-launch.c				\
	dbus-launch-x11.c			\
	dbus-launch.h \
	tool-common.c \
	tool-common.h \
	$(NULL)
dbus_launch_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	$(NULL)
dbus_launch_LDADD = \
	$(top_builddir)/dbus/libdbus-1.la \
	$(DBUS_X_LIBS) \
	$(NULL)

dbus_run_session_SOURCES =			\
	dbus-run-session.c

dbus_run_session_LDADD = \
	$(top_builddir)/dbus/libdbus-1.la \
	$(NULL)
endif

dbus_cleanup_sockets_SOURCES=			\
	dbus-cleanup-sockets.c

dbus_uuidgen_SOURCES=				\
	dbus-uuidgen.c

dbus_send_LDADD = \
	$(top_builddir)/dbus/libdbus-1.la \
	$(NULL)

dbus_monitor_LDADD = \
	$(top_builddir)/dbus/libdbus-1.la \
	$(NETWORK_libs) \
	$(NULL)

dbus_uuidgen_LDADD = \
	$(top_builddir)/dbus/libdbus-1.la \
	$(NULL)

examplesdir = ${docdir}/examples
dist_examples_SCRIPTS = \
	GetAllMatchRules.py \
	$(NULL)

dbus_test_tool_SOURCES = \
	dbus-echo.c \
	dbus-spam.c \
	tool-common.c \
	tool-common.h \
	test-tool.c \
	test-tool.h \
	$(NULL)
dbus_test_tool_LDADD = $(top_builddir)/dbus/libdbus-1.la

dbus_update_activation_environment_SOURCES = \
	dbus-update-activation-environment.c \
	tool-common.c \
	tool-common.h \
	$(NULL)
dbus_update_activation_environment_LDADD = $(top_builddir)/dbus/libdbus-1.la

EXTRA_DIST = run-with-tmp-session-bus.sh strtoll.c strtoull.c
CLEANFILES = 				\
	run-with-tmp-session-bus.conf

# create the /var/lib/dbus directory for dbus-uuidgen
install-data-local:
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/dbus

installcheck-local:
	test -d $(DESTDIR)$(localstatedir)/lib/dbus
