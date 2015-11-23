/* Unit tests for systemd activation.
 *
 * Copyright © 2010-2011 Nokia Corporation
 * Copyright © 2015 Collabora Ltd.
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

#include <string.h>

#include "test-utils-glib.h"

typedef struct {
    TestMainContext *ctx;
    DBusError e;
    GError *ge;

    gchar *address;
    GPid daemon_pid;

    DBusConnection *caller;
    const char *caller_name;
    DBusConnection *systemd;
    const char *systemd_name;
    DBusMessage *systemd_message;
    DBusConnection *activated;
    const char *activated_name;
    DBusMessage *activated_message;
} Fixture;

/* this is a macro so it gets the right line number */
#define assert_signal(m, \
    sender, path, iface, member, signature, \
    destination) \
do { \
  g_assert_cmpstr (dbus_message_type_to_string (dbus_message_get_type (m)), \
      ==, dbus_message_type_to_string (DBUS_MESSAGE_TYPE_SIGNAL)); \
  g_assert_cmpstr (dbus_message_get_sender (m), ==, sender); \
  g_assert_cmpstr (dbus_message_get_destination (m), ==, destination); \
  g_assert_cmpstr (dbus_message_get_path (m), ==, path); \
  g_assert_cmpstr (dbus_message_get_interface (m), ==, iface); \
  g_assert_cmpstr (dbus_message_get_member (m), ==, member); \
  g_assert_cmpstr (dbus_message_get_signature (m), ==, signature); \
  g_assert_cmpint (dbus_message_get_serial (m), !=, 0); \
  g_assert_cmpint (dbus_message_get_reply_serial (m), ==, 0); \
} while (0)

#define assert_method_call(m, sender, \
    destination, path, iface, method, signature) \
do { \
  g_assert_cmpstr (dbus_message_type_to_string (dbus_message_get_type (m)), \
      ==, dbus_message_type_to_string (DBUS_MESSAGE_TYPE_METHOD_CALL)); \
  g_assert_cmpstr (dbus_message_get_sender (m), ==, sender); \
  g_assert_cmpstr (dbus_message_get_destination (m), ==, destination); \
  g_assert_cmpstr (dbus_message_get_path (m), ==, path); \
  g_assert_cmpstr (dbus_message_get_interface (m), ==, iface); \
  g_assert_cmpstr (dbus_message_get_member (m), ==, method); \
  g_assert_cmpstr (dbus_message_get_signature (m), ==, signature); \
  g_assert_cmpint (dbus_message_get_serial (m), !=, 0); \
  g_assert_cmpint (dbus_message_get_reply_serial (m), ==, 0); \
} while (0)

#define assert_method_reply(m, sender, destination, signature) \
do { \
  g_assert_cmpstr (dbus_message_type_to_string (dbus_message_get_type (m)), \
      ==, dbus_message_type_to_string (DBUS_MESSAGE_TYPE_METHOD_RETURN)); \
  g_assert_cmpstr (dbus_message_get_sender (m), ==, sender); \
  g_assert_cmpstr (dbus_message_get_destination (m), ==, destination); \
  g_assert_cmpstr (dbus_message_get_path (m), ==, NULL); \
  g_assert_cmpstr (dbus_message_get_interface (m), ==, NULL); \
  g_assert_cmpstr (dbus_message_get_member (m), ==, NULL); \
  g_assert_cmpstr (dbus_message_get_signature (m), ==, signature); \
  g_assert_cmpint (dbus_message_get_serial (m), !=, 0); \
  g_assert_cmpint (dbus_message_get_reply_serial (m), !=, 0); \
} while (0)

static DBusHandlerResult
systemd_filter (DBusConnection *connection,
    DBusMessage *message,
    void *user_data)
{
  Fixture *f = user_data;

  if (dbus_message_is_signal (message, DBUS_INTERFACE_DBUS,
        "NameAcquired") ||
      dbus_message_is_signal (message, DBUS_INTERFACE_DBUS,
        "NameLost"))
    {
      return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

  g_test_message("sender %s iface %s member %s",
                 dbus_message_get_sender (message),
                 dbus_message_get_interface (message),
                 dbus_message_get_member (message));


  g_assert (f->systemd_message == NULL);
  f->systemd_message = dbus_message_ref (message);

  if (dbus_message_is_method_call (message, "org.freedesktop.systemd1.Manager",
                                   "SetEnvironment"))
    {
      g_assert (dbus_message_get_no_reply (message));
      g_test_message("got call");
      return DBUS_HANDLER_RESULT_HANDLED;
    }

  return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult
activated_filter (DBusConnection *connection,
    DBusMessage *message,
    void *user_data)
{
  Fixture *f = user_data;

  if (dbus_message_is_signal (message, DBUS_INTERFACE_DBUS,
        "NameAcquired") ||
      dbus_message_is_signal (message, DBUS_INTERFACE_DBUS,
        "NameLost"))
    {
      return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

  g_assert (f->activated_message == NULL);
  f->activated_message = dbus_message_ref (message);

  return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void
setup (Fixture *f,
    gconstpointer context G_GNUC_UNUSED)
{
  f->ctx = test_main_context_get ();

  f->ge = NULL;
  dbus_error_init (&f->e);

  f->address = test_get_dbus_daemon (
      "valid-config-files/systemd-activation.conf",
      TEST_USER_ME, &f->daemon_pid);

  if (f->address == NULL)
    return;

  f->caller = test_connect_to_bus (f->ctx, f->address);
  f->caller_name = dbus_bus_get_unique_name (f->caller);
}

static void
take_well_known_name (Fixture *f,
    DBusConnection *connection,
    const char *name)
{
  int ret;

  ret = dbus_bus_request_name (connection, name,
      DBUS_NAME_FLAG_DO_NOT_QUEUE, &f->e);
  test_assert_no_error (&f->e);
  g_assert_cmpint (ret, ==, DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER);
}

static void
test_activation (Fixture *f,
    gconstpointer context)
{
  DBusMessage *m;

  if (f->address == NULL)
    return;

  /* The sender sends a message to an activatable service. */
  m = dbus_message_new_signal ("/foo", "com.example.bar", "UnicastSignal1");
  if (!dbus_message_set_destination (m, "com.example.SystemdActivatable1"))
    g_error ("OOM");
  dbus_connection_send (f->caller, m, NULL);
  dbus_message_unref (m);

  /* The fake systemd connects to the bus. */
  f->systemd = test_connect_to_bus (f->ctx, f->address);
  if (!dbus_connection_add_filter (f->systemd, systemd_filter, f, NULL))
    g_error ("OOM");
  f->systemd_name = dbus_bus_get_unique_name (f->systemd);
  take_well_known_name (f, f->systemd, "org.freedesktop.systemd1");

  /* It gets its activation request. */
  while (f->systemd_message == NULL)
    test_main_context_iterate (f->ctx, TRUE);

  m = f->systemd_message;
  f->systemd_message = NULL;
  assert_signal (m, DBUS_SERVICE_DBUS, DBUS_PATH_DBUS,
      "org.freedesktop.systemd1.Activator", "ActivationRequest", "s",
      "org.freedesktop.systemd1");
  dbus_message_unref (m);

  /* systemd starts the activatable service. */
  f->activated = test_connect_to_bus (f->ctx, f->address);
  if (!dbus_connection_add_filter (f->activated, activated_filter,
        f, NULL))
    g_error ("OOM");
  f->activated_name = dbus_bus_get_unique_name (f->activated);
  take_well_known_name (f, f->activated, "com.example.SystemdActivatable1");

  /* The message is delivered to the activatable service. */
  while (f->activated_message == NULL)
    test_main_context_iterate (f->ctx, TRUE);

  m = f->activated_message;
  f->activated_message = NULL;
  assert_signal (m, f->caller_name, "/foo",
      "com.example.bar", "UnicastSignal1", "",
      "com.example.SystemdActivatable1");
  dbus_message_unref (m);

  /* The sender sends a message to a different activatable service. */
  m = dbus_message_new_signal ("/foo", "com.example.bar", "UnicastSignal2");
  if (!dbus_message_set_destination (m, "com.example.SystemdActivatable2"))
    g_error ("OOM");
  dbus_connection_send (f->caller, m, NULL);
  dbus_message_unref (m);

  /* This time systemd is already ready for it. */
  while (f->systemd_message == NULL)
    test_main_context_iterate (f->ctx, TRUE);

  m = f->systemd_message;
  f->systemd_message = NULL;
  assert_signal (m, DBUS_SERVICE_DBUS, DBUS_PATH_DBUS,
      "org.freedesktop.systemd1.Activator", "ActivationRequest", "s",
      "org.freedesktop.systemd1");
  dbus_message_unref (m);

  /* A malicious process tries to disrupt the activation.
   * In a more realistic scenario this would be another parallel
   * connection. */
  m = dbus_message_new_signal ("/org/freedesktop/systemd1",
      "org.freedesktop.systemd1.Activator", "ActivationFailure");
  if (!dbus_message_set_destination (m, "org.freedesktop.DBus"))
    g_error ("OOM");

  do
    {
      const char *unit = "dbus-com.example.SystemdActivatable2.service";
      const char *error_name = "com.example.Malice";
      const char *error_message = "I'm on yr bus, making yr activations fail";

      if (!dbus_message_append_args (m,
            DBUS_TYPE_STRING, &unit,
            DBUS_TYPE_STRING, &error_name,
            DBUS_TYPE_STRING, &error_message,
            DBUS_TYPE_INVALID))
        g_error ("OOM");
    }
  while (0);

  dbus_connection_send (f->caller, m, NULL);
  dbus_message_unref (m);

  /* This is just to make sure that the malicious message has arrived and
   * been processed by the dbus-daemon, i.e. @caller won the race
   * with @activated. */
  take_well_known_name (f, f->caller, "com.example.Sync");

  /* The activatable service takes its name. Here I'm faking it by using
   * an existing connection; in real life it would be yet another
   * connection. */
  take_well_known_name (f, f->activated, "com.example.SystemdActivatable2");

  /* The message is delivered to the activatable service. */
  while (f->activated_message == NULL)
    test_main_context_iterate (f->ctx, TRUE);

  m = f->activated_message;
  f->activated_message = NULL;
  assert_signal (m, f->caller_name, "/foo",
      "com.example.bar", "UnicastSignal2", "",
      "com.example.SystemdActivatable2");
  dbus_message_unref (m);

  /* A third activation. */
  m = dbus_message_new_signal ("/foo", "com.example.bar", "UnicastSignal3");
  if (!dbus_message_set_destination (m, "com.example.SystemdActivatable3"))
    g_error ("OOM");
  dbus_connection_send (f->caller, m, NULL);
  dbus_message_unref (m);

  while (f->systemd_message == NULL)
    test_main_context_iterate (f->ctx, TRUE);

  m = f->systemd_message;
  f->systemd_message = NULL;
  assert_signal (m, DBUS_SERVICE_DBUS, DBUS_PATH_DBUS,
      "org.freedesktop.systemd1.Activator", "ActivationRequest", "s",
      "org.freedesktop.systemd1");
  dbus_message_unref (m);

  /* This time activation fails */
  m = dbus_message_new_signal ("/org/freedesktop/systemd1",
      "org.freedesktop.systemd1.Activator", "ActivationFailure");

  do
    {
      const char *unit = "dbus-com.example.SystemdActivatable3.service";
      const char *error_name = "com.example.Nope";
      const char *error_message = "Computer says no";

      if (!dbus_message_append_args (m,
            DBUS_TYPE_STRING, &unit,
            DBUS_TYPE_STRING, &error_name,
            DBUS_TYPE_STRING, &error_message,
            DBUS_TYPE_INVALID))
        g_error ("OOM");
    }
  while (0);

  if (!dbus_message_set_destination (m, "org.freedesktop.DBus"))
    g_error ("OOM");
  dbus_connection_send (f->systemd, m, NULL);
  dbus_message_unref (m);
}

static void
test_uae (Fixture *f,
    gconstpointer context)
{
  DBusMessage *m;
  DBusPendingCall *pc;
  DBusMessageIter args_iter, arr_iter, entry_iter;
  const char *s;

  if (f->address == NULL)
    return;

  m = dbus_message_new_method_call (DBUS_SERVICE_DBUS, DBUS_PATH_DBUS,
      DBUS_INTERFACE_DBUS, "UpdateActivationEnvironment");

  if (m == NULL)
    g_error ("OOM");

  dbus_message_iter_init_append (m, &args_iter);

  /* Append an empty a{ss} (string => string dictionary). */
  if (!dbus_message_iter_open_container (&args_iter, DBUS_TYPE_ARRAY,
        "{ss}", &arr_iter) ||
      !dbus_message_iter_close_container (&args_iter, &arr_iter))
    g_error ("OOM");

  if (!dbus_connection_send_with_reply (f->caller, m, &pc,
        DBUS_TIMEOUT_USE_DEFAULT) || pc == NULL)
    g_error ("OOM");

  dbus_message_unref (m);
  m = NULL;

  if (dbus_pending_call_get_completed (pc))
    test_pending_call_store_reply (pc, &m);
  else if (!dbus_pending_call_set_notify (pc, test_pending_call_store_reply,
        &m, NULL))
    g_error ("OOM");

  while (m == NULL)
    test_main_context_iterate (f->ctx, TRUE);

  assert_method_reply (m, DBUS_SERVICE_DBUS, f->caller_name, "");
  dbus_message_unref (m);

  /* The fake systemd connects to the bus. */
  f->systemd = test_connect_to_bus (f->ctx, f->address);
  if (!dbus_connection_add_filter (f->systemd, systemd_filter, f, NULL))
    g_error ("OOM");
  f->systemd_name = dbus_bus_get_unique_name (f->systemd);
  take_well_known_name (f, f->systemd, "org.freedesktop.systemd1");

  /* It gets the SetEnvironment */
  while (f->systemd_message == NULL)
    test_main_context_iterate (f->ctx, TRUE);

  m = f->systemd_message;
  f->systemd_message = NULL;

  /* With activation, the destination is the well-known name */
  assert_method_call (m, DBUS_SERVICE_DBUS, "org.freedesktop.systemd1",
      "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager",
      "SetEnvironment", "as");

  dbus_message_iter_init (m, &args_iter);
  g_assert_cmpuint (dbus_message_iter_get_arg_type (&args_iter), ==,
      DBUS_TYPE_ARRAY);
  g_assert_cmpuint (dbus_message_iter_get_element_type (&args_iter), ==,
      DBUS_TYPE_STRING);
  dbus_message_iter_recurse (&args_iter, &arr_iter);
  g_assert_cmpuint (dbus_message_iter_get_arg_type (&arr_iter), ==,
      DBUS_TYPE_INVALID);
  dbus_message_iter_next (&args_iter);
  g_assert_cmpuint (dbus_message_iter_get_arg_type (&args_iter), ==,
      DBUS_TYPE_INVALID);
  dbus_message_unref (m);

  m = dbus_message_new_method_call (DBUS_SERVICE_DBUS, DBUS_PATH_DBUS,
      DBUS_INTERFACE_DBUS, "UpdateActivationEnvironment");

  if (m == NULL)
    g_error ("OOM");

  dbus_message_iter_init_append (m, &args_iter);


  {
    const char *k1 = "Key1", *v1 = "Value1",
               *k2 = "Key2", *v2 = "Value2";

    /* Append a filled a{ss} (string => string dictionary). */
    if (!dbus_message_iter_open_container (&args_iter, DBUS_TYPE_ARRAY,
          "{ss}", &arr_iter) ||
        !dbus_message_iter_open_container (&arr_iter, DBUS_TYPE_DICT_ENTRY,
          NULL, &entry_iter) ||
        !dbus_message_iter_append_basic (&entry_iter, DBUS_TYPE_STRING,
          &k1) ||
        !dbus_message_iter_append_basic (&entry_iter, DBUS_TYPE_STRING,
          &v1) ||
        !dbus_message_iter_close_container (&arr_iter, &entry_iter) ||
        !dbus_message_iter_open_container (&arr_iter, DBUS_TYPE_DICT_ENTRY,
          NULL, &entry_iter) ||
        !dbus_message_iter_append_basic (&entry_iter, DBUS_TYPE_STRING,
          &k2) ||
        !dbus_message_iter_append_basic (&entry_iter, DBUS_TYPE_STRING,
          &v2) ||
        !dbus_message_iter_close_container (&arr_iter, &entry_iter) ||
        !dbus_message_iter_close_container (&args_iter, &arr_iter))
      g_error ("OOM");
  }

  if (!dbus_connection_send_with_reply (f->caller, m, &pc,
        DBUS_TIMEOUT_USE_DEFAULT) || pc == NULL)
    g_error ("OOM");

  dbus_message_unref (m);
  m = NULL;

  if (dbus_pending_call_get_completed (pc))
    test_pending_call_store_reply (pc, &m);
  else if (!dbus_pending_call_set_notify (pc, test_pending_call_store_reply,
        &m, NULL))
    g_error ("OOM");

  while (m == NULL)
    test_main_context_iterate (f->ctx, TRUE);

  assert_method_reply (m, DBUS_SERVICE_DBUS, f->caller_name, "");
  dbus_message_unref (m);

  while (f->systemd_message == NULL)
    test_main_context_iterate (f->ctx, TRUE);

  m = f->systemd_message;
  f->systemd_message = NULL;

  /* Without activation, the destination is the unique name */
  assert_method_call (m, DBUS_SERVICE_DBUS, f->systemd_name,
      "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager",
      "SetEnvironment", "as");

  dbus_message_iter_init (m, &args_iter);
  g_assert_cmpuint (dbus_message_iter_get_arg_type (&args_iter), ==,
      DBUS_TYPE_ARRAY);
  g_assert_cmpuint (dbus_message_iter_get_element_type (&args_iter), ==,
      DBUS_TYPE_STRING);
  dbus_message_iter_recurse (&args_iter, &arr_iter);
  g_assert_cmpuint (dbus_message_iter_get_arg_type (&arr_iter), ==,
      DBUS_TYPE_STRING);
  dbus_message_iter_get_basic (&arr_iter, &s);
  g_assert_cmpstr (s, ==, "Key1=Value1");
  dbus_message_iter_next (&arr_iter);
  g_assert_cmpuint (dbus_message_iter_get_arg_type (&arr_iter), ==,
      DBUS_TYPE_STRING);
  dbus_message_iter_get_basic (&arr_iter, &s);
  g_assert_cmpstr (s, ==, "Key2=Value2");
  dbus_message_iter_next (&arr_iter);
  g_assert_cmpuint (dbus_message_iter_get_arg_type (&arr_iter), ==,
      DBUS_TYPE_INVALID);
  dbus_message_iter_next (&args_iter);
  g_assert_cmpuint (dbus_message_iter_get_arg_type (&args_iter), ==,
      DBUS_TYPE_INVALID);
  dbus_message_unref (m);
}

static void
teardown (Fixture *f,
    gconstpointer context G_GNUC_UNUSED)
{
  dbus_error_free (&f->e);
  g_clear_error (&f->ge);

  if (f->caller != NULL)
    {
      dbus_connection_close (f->caller);
      dbus_connection_unref (f->caller);
      f->caller = NULL;
    }

  if (f->systemd != NULL)
    {
      dbus_connection_remove_filter (f->systemd, systemd_filter, f);
      dbus_connection_close (f->systemd);
      dbus_connection_unref (f->systemd);
      f->systemd = NULL;
    }

  if (f->activated != NULL)
    {
      dbus_connection_remove_filter (f->activated, activated_filter, f);
      dbus_connection_close (f->activated);
      dbus_connection_unref (f->activated);
      f->activated = NULL;
    }

  test_kill_pid (f->daemon_pid);
  g_spawn_close_pid (f->daemon_pid);
  test_main_context_unref (f->ctx);
  g_free (f->address);
}

int
main (int argc,
    char **argv)
{
  test_init (&argc, &argv);

  g_test_add ("/sd-activation/activation", Fixture, NULL,
      setup, test_activation, teardown);
  g_test_add ("/sd-activation/uae", Fixture, NULL,
      setup, test_uae, teardown);

  return g_test_run ();
}
