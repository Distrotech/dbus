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
#include <syslog.h>
#include <unistd.h>

#ifdef HAVE_LIBAUDIT
#include <cap-ng.h>
#include <libaudit.h>
#endif /* HAVE_LIBAUDIT */

#include "connection.h"
#include "utils.h"

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

struct BusAppArmorConfinement
{
  int refcount; /* Reference count */

  char *context; /* AppArmor confinement context (label) */
  const char *mode; /* AppArmor confinement mode (freed by freeing *context) */
};

static BusAppArmorConfinement *bus_con = NULL;

/**
 * Callers of this function give up ownership of the *context and *mode
 * pointers.
 *
 * Additionally, the responsibility of freeing *context and *mode becomes the
 * responsibility of the bus_apparmor_confinement_unref() function. However, it
 * does not free *mode because libapparmor's aa_getcon(), and libapparmor's
 * other related functions, allocate a single buffer for *context and *mode and
 * then separate the two char arrays with a NUL char. See the aa_getcon(2) man
 * page for more details.
 */
static BusAppArmorConfinement*
bus_apparmor_confinement_new (char *context, const char *mode)
{
  BusAppArmorConfinement *confinement;

  confinement = dbus_new0 (BusAppArmorConfinement, 1);
  if (confinement != NULL)
    {
      confinement->refcount = 1;
      confinement->context = context;
      confinement->mode = mode;
    }

  return confinement;
}

void
bus_apparmor_confinement_unref (BusAppArmorConfinement *confinement)
{
#ifdef HAVE_APPARMOR
  if (!apparmor_enabled)
    return;

  _dbus_assert (confinement != NULL);
  _dbus_assert (confinement->refcount > 0);

  confinement->refcount -= 1;

  if (confinement->refcount == 0)
    {
      /**
       * Do not free confinement->mode, as libapparmor does a single malloc for
       * both confinement->context and confinement->mode.
       */
      free (confinement->context);
      dbus_free (confinement);
    }
#endif
}

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

static dbus_bool_t
modestr_is_complain (const char *mode)
{
  if (mode && strcmp (mode, "complain") == 0)
    return TRUE;
  return FALSE;
}

static void
log_message (dbus_bool_t allow, const char *op, DBusString *data)
{
  const char *mstr;

  if (allow)
    mstr = "ALLOWED";
  else
    mstr = "DENIED";

#ifdef HAVE_LIBAUDIT
  if (audit_fd >= 0)
  {
    DBusString avc;

    capng_get_caps_process ();
    if (!capng_have_capability (CAPNG_EFFECTIVE, CAP_AUDIT_WRITE))
      goto syslog;

    if (!_dbus_string_init (&avc))
      goto syslog;

    if (!_dbus_string_append_printf (&avc,
          "apparmor=\"%s\" operation=\"dbus_%s\" %s\n",
          mstr, op, _dbus_string_get_const_data (data)))
      {
        _dbus_string_free (&avc);
        goto syslog;
      }

    /* FIXME: need to change this to show real user */
    audit_log_user_avc_message (audit_fd, AUDIT_USER_AVC,
                                _dbus_string_get_const_data (&avc),
                                NULL, NULL, NULL, getuid ());
    _dbus_string_free (&avc);
    return;
  }

syslog:
#endif /* HAVE_LIBAUDIT */

  syslog (LOG_USER | LOG_NOTICE, "apparmor=\"%s\" operation=\"dbus_%s\" %s\n",
          mstr, op, _dbus_string_get_const_data (data));
}

static dbus_bool_t
_dbus_append_pair_uint (DBusString *auxdata, const char *name,
                       unsigned long value)
{
  return _dbus_string_append (auxdata, " ") &&
         _dbus_string_append (auxdata, name) &&
         _dbus_string_append (auxdata, "=") &&
         _dbus_string_append_uint (auxdata, value);
}

static dbus_bool_t
_dbus_append_pair_str (DBusString *auxdata, const char *name, const char *value)
{
  return _dbus_string_append (auxdata, " ") &&
         _dbus_string_append (auxdata, name) &&
         _dbus_string_append (auxdata, "=\"") &&
         _dbus_string_append (auxdata, value) &&
         _dbus_string_append (auxdata, "\"");
}

static dbus_bool_t
_dbus_append_mask (DBusString *auxdata, uint32_t mask)
{
  const char *mask_str;

  /* Only one permission bit can be set */
  if (mask == AA_DBUS_SEND)
    mask_str = "send";
  else if (mask == AA_DBUS_RECEIVE)
    mask_str = "receive";
  else if (mask == AA_DBUS_BIND)
    mask_str = "bind";
  else
    return FALSE;

  return _dbus_append_pair_str (auxdata, "mask", mask_str);
}

static dbus_bool_t
is_unconfined (const char *con, const char *mode)
{
  /* treat con == NULL as confined as it is going to result in a denial */
  if ((!mode && con && strcmp (con, "unconfined") == 0) ||
      strcmp (mode, "unconfined") == 0)
    {
      return TRUE;
    }

  return FALSE;
}

static dbus_bool_t
query_append (DBusString *query, const char *buffer)
{
  if (!_dbus_string_append_byte (query, '\0'))
    return FALSE;

  if (buffer && !_dbus_string_append (query, buffer))
    return FALSE;

  return TRUE;
}

static dbus_bool_t
build_common_query (DBusString *query, const char *con, const char *bustype)
{
  /**
   * libapparmor's aa_query_label() function scribbles over the first
   * AA_QUERY_CMD_LABEL_SIZE bytes of the query string with a private value.
   */
  return _dbus_string_insert_bytes (query, 0, AA_QUERY_CMD_LABEL_SIZE, 0) &&
         _dbus_string_append (query, con) &&
         _dbus_string_append_byte (query, '\0') &&
         _dbus_string_append_byte (query, AA_CLASS_DBUS) &&
         _dbus_string_append (query, bustype ? bustype : "");
}

static dbus_bool_t
build_service_query (DBusString *query,
                     const char *con,
                     const char *bustype,
                     const char *name)
{
  return build_common_query (query, con, bustype) &&
         query_append (query, name);
}

static void
set_error_from_query_errno (DBusError *error, int error_number)
{
  dbus_set_error (error, _dbus_error_from_errno (error_number),
                  "Failed to query AppArmor policy: %s",
                  _dbus_strerror (error_number));
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
  char *context, *mode;

  if (apparmor_enabled)
    {
      if (apparmor_config_mode == APPARMOR_DISABLED)
        {
          apparmor_enabled = FALSE;
          return TRUE;
        }

      if (bus_con == NULL)
        {
          if (aa_getcon (&context, &mode) == -1)
            {
              dbus_set_error (error, DBUS_ERROR_FAILED,
                              "Error getting AppArmor context of bus: %s",
                              _dbus_strerror (errno));
              return FALSE;
            }

          bus_con = bus_apparmor_confinement_new (context, mode);
          if (bus_con == NULL)
            {
              BUS_SET_OOM (error);
              free (context);
              return FALSE;
            }
        }
    }
  else
    {
      if (apparmor_config_mode == APPARMOR_REQUIRED)
        {
          dbus_set_error (error, DBUS_ERROR_FAILED,
                          "AppArmor mediation required but not present");
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

  bus_apparmor_confinement_unref (bus_con);
  bus_con = NULL;

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

void
bus_apparmor_confinement_ref (BusAppArmorConfinement *confinement)
{
#ifdef HAVE_APPARMOR
  if (!apparmor_enabled)
    return;

  _dbus_assert (confinement != NULL);
  _dbus_assert (confinement->refcount > 0);

  confinement->refcount += 1;
#endif /* HAVE_APPARMOR */
}

BusAppArmorConfinement*
bus_apparmor_init_connection_confinement (DBusConnection *connection,
                                          DBusError      *error)
{
#ifdef HAVE_APPARMOR
  BusAppArmorConfinement *confinement;
  char *context, *mode;
  int fd;

  if (!apparmor_enabled)
    return NULL;

  _dbus_assert (connection != NULL);

  if (!dbus_connection_get_socket (connection, &fd))
    {
      dbus_set_error (error, DBUS_ERROR_FAILED,
                      "Failed to get socket file descriptor of connection");
      return NULL;
    }

  if (aa_getpeercon (fd, &context, &mode) == -1)
    {
      if (errno == ENOMEM)
        BUS_SET_OOM (error);
      else
        dbus_set_error (error, _dbus_error_from_errno (errno),
                        "Failed to get AppArmor confinement information of socket peer: %s",
                        _dbus_strerror (errno));
      return NULL;
    }

  confinement = bus_apparmor_confinement_new (context, mode);
  if (confinement == NULL)
    {
      BUS_SET_OOM (error);
      free (context);
      return NULL;
    }

  return confinement;
#else
  return NULL;
#endif /* HAVE_APPARMOR */
}

/**
 * Returns true if the given connection can acquire a service,
 * using the tasks security context
 *
 * @param connection connection that wants to own the service
 * @param bustype name of the bus
 * @param service_name the name of the service to acquire
 * @param error the reason for failure when FALSE is returned
 * @returns TRUE if acquire is permitted
 */
dbus_bool_t
bus_apparmor_allows_acquire_service (DBusConnection     *connection,
                                     const char         *bustype,
                                     const char         *service_name,
                                     DBusError          *error)
{

#ifdef HAVE_APPARMOR
  BusAppArmorConfinement *con = NULL;
  DBusString qstr, auxdata;
  dbus_bool_t free_auxdata = FALSE;
  dbus_bool_t allow = FALSE, audit = TRUE;
  unsigned long pid;
  int res, serrno = 0;

  if (!apparmor_enabled)
    return TRUE;

  _dbus_assert (connection != NULL);

  con = bus_connection_dup_apparmor_confinement (connection);

  if (is_unconfined (con->context, con->mode))
    {
      allow = TRUE;
      audit = FALSE;
      goto out;
    }

  if (!_dbus_string_init (&qstr))
    goto oom;

  if (!build_service_query (&qstr, con->context, bustype, service_name))
    {
      _dbus_string_free (&qstr);
      goto oom;
    }

  res = aa_query_label (AA_DBUS_BIND,
                        _dbus_string_get_data (&qstr),
                        _dbus_string_get_length (&qstr),
                        &allow, &audit);
  _dbus_string_free (&qstr);
  if (res == -1)
    {
      serrno = errno;
      set_error_from_query_errno (error, serrno);
      goto audit;
    }

  /* Don't fail operations on profiles in complain mode */
  if (modestr_is_complain (con->mode))
      allow = TRUE;

  if (!allow)
    dbus_set_error (error, DBUS_ERROR_ACCESS_DENIED,
                    "Connection \"%s\" is not allowed to own the service "
                    "\"%s\" due to AppArmor policy",
                    bus_connection_is_active (connection) ?
                     bus_connection_get_name (connection) : "(inactive)",
                    service_name);

  if (!audit)
    goto out;

 audit:
  if (!_dbus_string_init (&auxdata))
    goto oom;
  free_auxdata = TRUE;

  if (!_dbus_append_pair_str (&auxdata, "bus", bustype ? bustype : "unknown"))
    goto oom;

  if (!_dbus_append_pair_str (&auxdata, "name", service_name))
    goto oom;

  if (serrno && !_dbus_append_pair_str (&auxdata, "info", strerror (serrno)))
    goto oom;

  if (!_dbus_append_mask (&auxdata, AA_DBUS_BIND))
    goto oom;

  if (connection && dbus_connection_get_unix_process_id (connection, &pid) &&
      !_dbus_append_pair_uint (&auxdata, "pid", pid))
    goto oom;

  if (con->context && !_dbus_append_pair_str (&auxdata, "profile", con->context))
    goto oom;

  log_message (allow, "bind", &auxdata);

 out:
  if (con != NULL)
    bus_apparmor_confinement_unref (con);
  if (free_auxdata)
    _dbus_string_free (&auxdata);
  return allow;

 oom:
  if (error != NULL && !dbus_error_is_set (error))
    BUS_SET_OOM (error);
  allow = FALSE;
  goto out;

#else
  return TRUE;
#endif /* HAVE_APPARMOR */
}
