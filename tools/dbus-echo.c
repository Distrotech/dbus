/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* dbus-echo.c - a plain libdbus echo server
 *
 * Copyright © 2003 Philip Blundell <philb@gnu.org>
 * Copyright © 2011 Nokia Corporation
 * Copyright © 2014 Collabora Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dbus/dbus.h>

#include "test-tool.h"
#include "tool-common.h"

static void
usage (int exit_with)
{
  fprintf (stderr,
           "Usage: dbus-test-tool echo [OPTIONS]\n"
           "\n"
           "Respond to all method calls with an empty reply.\n"
           "\n"
           "Options:\n"
           "\n"
           "    --name=NAME   claim this well-known name first\n"
           "\n"
           "    --sleep=N     sleep N milliseconds before sending each reply\n"
           "\n"
           "    --session     use the session bus (default)\n"
           "    --system      use the system bus\n"
           );
  exit (exit_with);
}

static DBusHandlerResult
filter (DBusConnection *connection,
    DBusMessage *message,
    void *user_data)
{
  DBusMessage *reply;
  int *sleep_ms = user_data;

  if (dbus_message_get_type (message) != DBUS_MESSAGE_TYPE_METHOD_CALL)
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

  if (*sleep_ms > 0)
    {
      tool_millisleep (*sleep_ms);
    }

  reply = dbus_message_new_method_return (message);

  if (reply == NULL)
    tool_oom ("allocating reply");

  if (!dbus_connection_send (connection, reply, NULL))
    tool_oom ("sending reply");

  dbus_message_unref (reply);

  return DBUS_HANDLER_RESULT_HANDLED;
}

int
dbus_test_tool_echo (int argc, char **argv)
{
  DBusConnection *connection;
  DBusError error = DBUS_ERROR_INIT;
  DBusBusType type = DBUS_BUS_SESSION;
  int i;
  int sleep_ms = -1;
  const char *name = NULL;

  /* argv[1] is the tool name, so start from 2 */

  for (i = 2; i < argc; i++)
    {
      const char *arg = argv[i];

      if (strcmp (arg, "--system") == 0)
        {
          type = DBUS_BUS_SYSTEM;
        }
      else if (strcmp (arg, "--session") == 0)
        {
          type = DBUS_BUS_SESSION;
        }
      else if (strstr (arg, "--name=") == arg)
        {
          name = arg + strlen ("--name=");
        }
      else if (strstr (arg, "--sleep-ms=") == arg)
        {
          sleep_ms = atoi (arg + strlen ("--sleep-ms="));
        }
      else
        {
          usage (2);
        }
    }

  connection = dbus_bus_get (type, &error);

  if (connection == NULL)
    {
      fprintf (stderr, "Failed to connect to bus: %s: %s\n",
               error.name, error.message);
      dbus_error_free (&error);
      return 1;
    }

  if (name != NULL)
    {
      if (dbus_bus_request_name (connection, name, DBUS_NAME_FLAG_DO_NOT_QUEUE,
                                 NULL) != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER)
        {
          fprintf (stderr, "failed to take bus name %s\n", name);
          exit (1);
        }
    }
  else
    {
      printf ("%s\n", dbus_bus_get_unique_name (connection));
    }

  if (!dbus_connection_add_filter (connection, filter, &sleep_ms, NULL))
    tool_oom ("adding message filter");

  while (dbus_connection_read_write_dispatch (connection, -1))
    {}

  dbus_connection_unref (connection);
  return 0;
}
