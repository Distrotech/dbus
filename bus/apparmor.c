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
#include <dbus/dbus-string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/apparmor.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef HAVE_LIBAUDIT
#include <cap-ng.h>
#include <libaudit.h>
#else
#include <syslog.h>
#endif /* HAVE_LIBAUDIT */

/* Store the value telling us if AppArmor D-Bus mediation is enabled. */
static dbus_bool_t apparmor_enabled = FALSE;

typedef enum {
  APPARMOR_DISABLED,
  APPARMOR_ENABLED,
  APPARMOR_REQUIRED
} AppArmorConfigMode;

/* Store the value of the AppArmor mediation mode in the bus configuration */
static AppArmorConfigMode apparmor_config_mode = APPARMOR_ENABLED;

#ifdef HAVE_LIBAUDIT
static int audit_fd = -1;
#endif

void
bus_apparmor_audit_init (void)
{
#ifdef HAVE_LIBAUDIT
  audit_fd = audit_open ();

  if (audit_fd < 0)
    {
      /* If kernel doesn't support audit, bail out */
      if (errno == EINVAL || errno == EPROTONOSUPPORT || errno == EAFNOSUPPORT)
        return;
      /* If user bus, bail out */
      if (errno == EPERM && getuid () != 0)
        return;
      _dbus_warn ("Failed opening connection to the audit subsystem");
    }
#endif /* HAVE_LIBAUDIT */
}

/*
 * Return TRUE on successful check, FALSE on OOM.
 * Set *is_supported to whether AA has D-Bus features.
 */
static dbus_bool_t
_bus_apparmor_detect_aa_dbus_support (dbus_bool_t *is_supported)
{
  int mask_file;
  DBusString aa_dbus;
  char *aa_securityfs = NULL;
  dbus_bool_t retval = FALSE;

  *is_supported = FALSE;

  if (!_dbus_string_init (&aa_dbus))
    return FALSE;

  if (aa_find_mountpoint (&aa_securityfs) != 0)
    goto out;

  /*
   * John Johansen has confirmed that the mainline kernel will not have
   * the apparmorfs/features/dbus/mask file until the mainline kernel
   * has AppArmor getpeersec support.
   */
  if (!_dbus_string_append (&aa_dbus, aa_securityfs) ||
      !_dbus_string_append (&aa_dbus, "/features/dbus/mask"))
    goto out;

  /* We need to open() the flag file, not just stat() it, because AppArmor
   * does not mediate stat() in the apparmorfs. If you have a
   * dbus-daemon inside an LXC container, with insufficiently broad
   * AppArmor privileges to do its own AppArmor mediation, the desired
   * result is that it behaves as if AppArmor was not present; but a stat()
   * here would succeed, and result in it trying and failing to do full
   * mediation. https://bugs.launchpad.net/ubuntu/+source/dbus/+bug/1238267 */
  mask_file = open (_dbus_string_get_const_data (&aa_dbus),
                    O_RDONLY | O_CLOEXEC);
  if (mask_file != -1)
    {
      *is_supported = TRUE;
      close (mask_file);
    }

  retval = TRUE;

out:
  free (aa_securityfs);
  _dbus_string_free (&aa_dbus);

  return retval;
}
#endif /* HAVE_APPARMOR */

/**
 * Do early initialization; determine whether AppArmor is enabled.
 * Return TRUE on successful check (whether AppArmor is actually
 * enabled or not) or FALSE on OOM.
 */
dbus_bool_t
bus_apparmor_pre_init (void)
{
#ifdef HAVE_APPARMOR
  apparmor_enabled = FALSE;

  if (!aa_is_enabled ())
    return TRUE;

  if (!_bus_apparmor_detect_aa_dbus_support (&apparmor_enabled))
    return FALSE;
#endif

  return TRUE;
}

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

/**
 * Verify that the config mode is compatible with the kernel's AppArmor
 * support. If AppArmor mediation will be enabled, determine the bus
 * confinement context.
 */
dbus_bool_t
bus_apparmor_full_init (DBusError *error)
{
#ifdef HAVE_APPARMOR
  if (apparmor_enabled)
    {
      if (apparmor_config_mode == APPARMOR_DISABLED)
        {
          apparmor_enabled = FALSE;
          return TRUE;
        }
    }
  else
    {
      if (apparmor_config_mode == APPARMOR_REQUIRED)
        {
          dbus_set_error (error, DBUS_ERROR_FAILED,
                          "AppArmor mediation required but not present\n");
          return FALSE;
        }
      else if (apparmor_config_mode == APPARMOR_ENABLED)
        {
          return TRUE;
        }
    }
#endif

  return TRUE;
}

void
bus_apparmor_shutdown (void)
{
#ifdef HAVE_APPARMOR
  if (!apparmor_enabled)
    return;

  _dbus_verbose ("AppArmor shutdown\n");

#ifdef HAVE_LIBAUDIT
  audit_close (audit_fd);
#endif /* HAVE_LIBAUDIT */

#endif /* HAVE_APPARMOR */
}

dbus_bool_t
bus_apparmor_enabled (void)
{
#ifdef HAVE_APPARMOR
  return apparmor_enabled;
#else
  return FALSE;
#endif
}
