/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*-
 * apparmor.c  AppArmor security checks for D-Bus
 *
 * Based on selinux.c
 *
 * Copyright © 2014-2015 Canonical, Ltd.
 *
 * Licensed under the Academic Free License version 2.1
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 *
 */

#include <config.h>
#include "apparmor.h"

#ifdef HAVE_APPARMOR

#include <dbus/dbus-internals.h>
#include <string.h>

typedef enum {
  APPARMOR_DISABLED,
  APPARMOR_ENABLED,
  APPARMOR_REQUIRED
} AppArmorConfigMode;

/* Store the value of the AppArmor mediation mode in the bus configuration */
static AppArmorConfigMode apparmor_config_mode = APPARMOR_ENABLED;

#endif /* HAVE_APPARMOR */

dbus_bool_t
bus_apparmor_set_mode_from_config (const char *mode, DBusError *error)
{
#ifdef HAVE_APPARMOR
  if (mode != NULL)
  {
    if (strcmp (mode, "disabled") == 0)
      apparmor_config_mode = APPARMOR_DISABLED;
    else if (strcmp (mode, "enabled") == 0)
      apparmor_config_mode = APPARMOR_ENABLED;
    else if (strcmp (mode, "required") == 0)
      apparmor_config_mode = APPARMOR_REQUIRED;
    else
      {
        dbus_set_error (error, DBUS_ERROR_FAILED,
                        "Mode attribute on <apparmor> must have value "
                        "\"required\", \"enabled\" or \"disabled\", "
                        "not \"%s\"", mode);
        return FALSE;
      }
  }

  return TRUE;
#else
  if (mode == NULL || strcmp (mode, "disabled") == 0 ||
                      strcmp (mode, "enabled") == 0)
    return TRUE;

  dbus_set_error (error, DBUS_ERROR_FAILED,
                  "Mode attribute on <apparmor> must have value \"enabled\" or "
                  "\"disabled\" but cannot be \"%s\" when D-Bus is built "
                  "without AppArmor support", mode);
  return FALSE;
#endif
}
