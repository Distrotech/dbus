/* Utility functions for tests that rely on GLib
 *
 * Copyright © 2010-2011 Nokia Corporation
 * Copyright © 2013-2015 Collabora Ltd.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <config.h>
#include "test-utils-glib.h"

#include <string.h>

#ifdef DBUS_WIN
# include <io.h>
# include <windows.h>
#else
# include <signal.h>
# include <unistd.h>
# include <sys/types.h>
#endif

#include <glib.h>
#include <glib/gstdio.h>

#include <dbus/dbus.h>

void
_test_assert_no_error (const DBusError *e,
    const char *file,
    int line)
{
  if (G_UNLIKELY (dbus_error_is_set (e)))
    g_error ("%s:%d: expected success but got error: %s: %s",
        file, line, e->name, e->message);
}

static gchar *
spawn_dbus_daemon (const gchar *binary,
    const gchar *configuration,
    GPid *daemon_pid)
{
  GError *error = NULL;
  GString *address;
  gint address_fd;
  const gchar *const argv[] = {
      binary,
      configuration,
      "--nofork",
      "--print-address=1", /* stdout */
      NULL
  };

  g_spawn_async_with_pipes (NULL, /* working directory */
      (gchar **) argv, /* g_s_a_w_p() is not const-correct :-( */
      NULL, /* envp */
      G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_SEARCH_PATH,
      NULL, /* child_setup */
      NULL, /* user data */
      daemon_pid,
      NULL, /* child's stdin = /dev/null */
      &address_fd,
      NULL, /* child's stderr = our stderr */
      &error);
  g_assert_no_error (error);

  address = g_string_new (NULL);

  /* polling until the dbus-daemon writes out its address is a bit stupid,
   * but at least it's simple, unlike dbus-launch... in principle we could
   * use select() here, but life's too short */
  while (1)
    {
      gssize bytes;
      gchar buf[4096];
      gchar *newline;

      bytes = read (address_fd, buf, sizeof (buf));

      if (bytes > 0)
        g_string_append_len (address, buf, bytes);

      newline = strchr (address->str, '\n');

      if (newline != NULL)
        {
          if ((newline > address->str) && ('\r' == newline[-1]))
            newline -= 1;
          g_string_truncate (address, newline - address->str);
          break;
        }

      g_usleep (G_USEC_PER_SEC / 10);
    }

  g_close (address_fd, NULL);

  return g_string_free (address, FALSE);
}

gchar *
test_get_dbus_daemon (const gchar *config_file,
                      GPid        *daemon_pid)
{
  gchar *dbus_daemon;
  gchar *arg;
  gchar *address;

  if (config_file != NULL)
    {
      if (g_getenv ("DBUS_TEST_DAEMON_ADDRESS") != NULL)
        {
          g_message ("SKIP: cannot use DBUS_TEST_DAEMON_ADDRESS for "
              "unusally-configured dbus-daemon");
          return NULL;
        }

      if (g_getenv ("DBUS_TEST_DATA") == NULL)
        {
          g_message ("SKIP: set DBUS_TEST_DATA to a directory containing %s",
              config_file);
          return NULL;
        }

      arg = g_strdup_printf (
          "--config-file=%s/%s",
          g_getenv ("DBUS_TEST_DATA"), config_file);
    }
  else if (g_getenv ("DBUS_TEST_SYSCONFDIR") != NULL)
    {
      arg = g_strdup_printf ("--config-file=%s/dbus-1/session.conf",
          g_getenv ("DBUS_TEST_SYSCONFDIR"));
    }
  else if (g_getenv ("DBUS_TEST_DATA") != NULL)
    {
      arg = g_strdup_printf (
          "--config-file=%s/valid-config-files/session.conf",
          g_getenv ("DBUS_TEST_DATA"));
    }
  else
    {
      arg = g_strdup ("--session");
    }

  dbus_daemon = g_strdup (g_getenv ("DBUS_TEST_DAEMON"));

  if (dbus_daemon == NULL)
    dbus_daemon = g_strdup ("dbus-daemon");

  if (g_getenv ("DBUS_TEST_DAEMON_ADDRESS") != NULL)
    {
      address = g_strdup (g_getenv ("DBUS_TEST_DAEMON_ADDRESS"));
    }
  else
    {
      address = spawn_dbus_daemon (dbus_daemon, arg, daemon_pid);
    }

  g_free (dbus_daemon);
  g_free (arg);
  return address;
}

DBusConnection *
test_connect_to_bus (TestMainContext *ctx,
    const gchar *address)
{
  DBusConnection *conn;
  DBusError error = DBUS_ERROR_INIT;
  dbus_bool_t ok;

  conn = dbus_connection_open_private (address, &error);
  test_assert_no_error (&error);
  g_assert (conn != NULL);

  ok = dbus_bus_register (conn, &error);
  test_assert_no_error (&error);
  g_assert (ok);
  g_assert (dbus_bus_get_unique_name (conn) != NULL);

  test_connection_setup (ctx, conn);
  return conn;
}

void
test_kill_pid (GPid pid)
{
#ifdef DBUS_WIN
  if (pid != NULL)
    TerminateProcess (pid, 1);
#else
  if (pid > 0)
    kill (pid, SIGTERM);
#endif
}
