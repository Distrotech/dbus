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
# include <errno.h>
# include <signal.h>
# include <unistd.h>
# include <sys/types.h>
# include <pwd.h>
#endif

#include <glib.h>
#include <glib/gstdio.h>

#include <dbus/dbus.h>

#ifdef G_OS_WIN
# define isatty(x) _isatty(x)
#endif

void
_test_assert_no_error (const DBusError *e,
    const char *file,
    int line)
{
  if (G_UNLIKELY (dbus_error_is_set (e)))
    g_error ("%s:%d: expected success but got error: %s: %s",
        file, line, e->name, e->message);
}

#ifdef DBUS_UNIX
static void
child_setup (gpointer user_data)
{
  const struct passwd *pwd = user_data;
  uid_t uid = geteuid ();

  if (pwd == NULL || (pwd->pw_uid == uid && getuid () == uid))
    return;

  if (uid != 0)
    g_error ("not currently euid 0: %lu", (unsigned long) uid);

  if (setuid (pwd->pw_uid) != 0)
    g_error ("could not setuid (%lu): %s",
        (unsigned long) pwd->pw_uid, g_strerror (errno));

  uid = getuid ();

  if (uid != pwd->pw_uid)
    g_error ("after successful setuid (%lu) my uid is %ld",
        (unsigned long) pwd->pw_uid, (unsigned long) uid);

  uid = geteuid ();

  if (uid != pwd->pw_uid)
    g_error ("after successful setuid (%lu) my euid is %ld",
        (unsigned long) pwd->pw_uid, (unsigned long) uid);
}
#endif

static gchar *
spawn_dbus_daemon (const gchar *binary,
    const gchar *configuration,
    const gchar *listen_address,
    TestUser user,
    GPid *daemon_pid)
{
  GError *error = NULL;
  GString *address;
  gint address_fd;
  GPtrArray *argv;
#ifdef DBUS_UNIX
  const struct passwd *pwd = NULL;
#endif

  if (user != TEST_USER_ME)
    {
#ifdef DBUS_UNIX
      if (getuid () != 0)
        {
          g_test_skip ("cannot use alternative uid when not uid 0");
          return NULL;
        }

      switch (user)
        {
          case TEST_USER_ROOT:
            break;

          case TEST_USER_MESSAGEBUS:
            pwd = getpwnam (DBUS_USER);

            if (pwd == NULL)
              {
                gchar *message = g_strdup_printf ("user '%s' does not exist",
                    DBUS_USER);

                g_test_skip (message);
                g_free (message);
                return NULL;
              }

            break;

          case TEST_USER_OTHER:
            pwd = getpwnam (DBUS_TEST_USER);

            if (pwd == NULL)
              {
                gchar *message = g_strdup_printf ("user '%s' does not exist",
                    DBUS_TEST_USER);

                g_test_skip (message);
                g_free (message);
                return NULL;
              }

            break;

          default:
            g_assert_not_reached ();
        }
#else
      g_test_skip ("cannot use alternative uid on Windows");
      return NULL;
#endif
    }

  argv = g_ptr_array_new_with_free_func (g_free);
  g_ptr_array_add (argv, g_strdup (binary));
  g_ptr_array_add (argv, g_strdup (configuration));
  g_ptr_array_add (argv, g_strdup ("--nofork"));
  g_ptr_array_add (argv, g_strdup ("--print-address=1")); /* stdout */

  if (listen_address != NULL)
    g_ptr_array_add (argv, g_strdup (listen_address));

#ifdef DBUS_UNIX
  g_ptr_array_add (argv, g_strdup ("--systemd-activation"));
#endif

  g_ptr_array_add (argv, NULL);

  g_spawn_async_with_pipes (NULL, /* working directory */
      (gchar **) argv->pdata,
      NULL, /* envp */
      G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_SEARCH_PATH,
#ifdef DBUS_UNIX
      child_setup, (gpointer) pwd,
#else
      NULL, NULL,
#endif
      daemon_pid,
      NULL, /* child's stdin = /dev/null */
      &address_fd,
      NULL, /* child's stderr = our stderr */
      &error);
  g_assert_no_error (error);

  g_ptr_array_free (argv, TRUE);

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
                      TestUser     user,
                      GPid        *daemon_pid)
{
  gchar *dbus_daemon;
  gchar *arg;
  const gchar *listen_address = NULL;
  gchar *address;

  /* we often have to override this because on Windows, the default may be
   * autolaunch:, which is globally-scoped and hence unsuitable for
   * regression tests */
  listen_address = "--address=" TEST_LISTEN;

  if (config_file != NULL)
    {

      if (g_getenv ("DBUS_TEST_DATA") == NULL)
        {
          g_test_message ("set DBUS_TEST_DATA to a directory containing %s",
              config_file);
          g_test_skip ("DBUS_TEST_DATA not set");
          return NULL;
        }

      arg = g_strdup_printf (
          "--config-file=%s/%s",
          g_getenv ("DBUS_TEST_DATA"), config_file);

      /* The configuration file is expected to give a suitable address,
       * do not override it */
      listen_address = NULL;
    }
  else if (g_getenv ("DBUS_TEST_DATADIR") != NULL)
    {
      arg = g_strdup_printf ("--config-file=%s/dbus-1/session.conf",
          g_getenv ("DBUS_TEST_DATADIR"));
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
      if (config_file != NULL || user != TEST_USER_ME)
        {
          g_test_skip ("cannot use DBUS_TEST_DAEMON_ADDRESS for "
              "unusally-configured dbus-daemon");
          address = NULL;
        }
      else
        {
          address = g_strdup (g_getenv ("DBUS_TEST_DAEMON_ADDRESS"));
        }
    }
  else
    {
      address = spawn_dbus_daemon (dbus_daemon, arg,
          listen_address, user, daemon_pid);
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

DBusConnection *
test_connect_to_bus_as_user (TestMainContext *ctx,
    const char *address,
    TestUser user)
{
  /* For now we only do tests like this on Linux, because I don't know how
   * safe this use of setresuid() is on other platforms */
#if defined(HAVE_GETRESUID) && defined(HAVE_SETRESUID) && defined(__linux__)
  uid_t ruid, euid, suid;
  const struct passwd *pwd;
  DBusConnection *conn;
  const char *username;

  switch (user)
    {
      case TEST_USER_ME:
        return test_connect_to_bus (ctx, address);

      case TEST_USER_ROOT:
        username = "root";
        break;

      case TEST_USER_MESSAGEBUS:
        username = DBUS_USER;
        break;

      case TEST_USER_OTHER:
        username = DBUS_TEST_USER;
        break;

      default:
        g_return_val_if_reached (NULL);
    }

  if (getresuid (&ruid, &euid, &suid) != 0)
    g_error ("getresuid: %s", g_strerror (errno));

  if (ruid != 0 || euid != 0 || suid != 0)
    {
      g_test_message ("not uid 0 (ruid=%ld euid=%ld suid=%ld)",
          (unsigned long) ruid, (unsigned long) euid, (unsigned long) suid);
      g_test_skip ("not uid 0");
      return NULL;
    }

  pwd = getpwnam (username);

  if (pwd == NULL)
    {
      g_test_message ("getpwnam(\"%s\"): %s", username, g_strerror (errno));
      g_test_skip ("not uid 0");
      return NULL;
    }

  /* Impersonate the desired user while we connect to the bus.
   * This should work, because we're root. */
  if (setresuid (pwd->pw_uid, pwd->pw_uid, 0) != 0)
    g_error ("setresuid(%ld, (same), 0): %s",
        (unsigned long) pwd->pw_uid, g_strerror (errno));

  conn = test_connect_to_bus (ctx, address);

  /* go back to our saved uid */
  if (setresuid (0, 0, 0) != 0)
    g_error ("setresuid(0, 0, 0): %s", g_strerror (errno));

  return conn;

#else

  switch (user)
    {
      case TEST_USER_ME:
        return test_connect_to_bus (ctx, address);

      default:
        g_test_skip ("setresuid() not available, or unsure about "
            "credentials-passing semantics on this platform");
        return NULL;
    }

#endif
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

static gboolean
time_out (gpointer data)
{
  g_error ("timed out");
  return FALSE;
}

#ifdef G_OS_UNIX
static void
wrap_abort (int signal)
{
  abort ();
}
#endif

void
test_init (int *argcp, char ***argvp)
{
  g_test_init (argcp, argvp, NULL);
  g_test_bug_base ("https://bugs.freedesktop.org/show_bug.cgi?id=");

  /* Prevent tests from hanging forever. This is intended to be long enough
   * that any reasonable regression test on any reasonable hardware would
   * have finished. */
#define TIMEOUT 60

  g_timeout_add_seconds (TIMEOUT, time_out, NULL);
#ifdef G_OS_UNIX
  /* The GLib main loop might not be running (we don't use it in every
   * test). Die with SIGALRM shortly after if necessary. */
  alarm (TIMEOUT + 10);

  /* Get a core dump from the SIGALRM. */
    {
      struct sigaction act = { };

      act.sa_handler = wrap_abort;

      sigaction (SIGALRM, &act, NULL);
    }
#endif
}

void
test_progress (char symbol)
{
  if (g_test_verbose () && isatty (1))
    g_print ("%c", symbol);
}
