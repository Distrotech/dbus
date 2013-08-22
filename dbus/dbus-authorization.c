#include <config.h>
#include "dbus-internals.h"
#include "dbus-authorization.h"
#include "dbus-connection.h"
#include "dbus-connection-internal.h"

struct DBusAuthorization {
  int refcount;

  DBusConnection *connection;

  /* Authorization functions, used as callback by SASL (implemented by
   * DBUsAuth) */
  DBusAllowUnixUserFunction unix_authorization_cb;
  void *unix_data;
  DBusFreeFunction unix_data_free;

  DBusAllowWindowsUserFunction windows_authorization_cb;
  void *windows_data;
  DBusFreeFunction windows_data_free;

  dbus_bool_t allow_anonymous;
};


DBusAuthorization *
_dbus_authorization_new (void)
{
  DBusAuthorization *ret;

  ret = dbus_malloc0 (sizeof (DBusAuthorization));
  if (ret == NULL)
    {
      _dbus_verbose ("OOM\n");
      return NULL; /* OOM */
    }

  ret->refcount = 1;

  return ret;
}

DBusAuthorization *
_dbus_authorization_ref (DBusAuthorization *self)
{
  _dbus_assert (self != NULL);

  self->refcount += 1;

  return self;
}

void
_dbus_authorization_unref (DBusAuthorization *self)
{
  _dbus_assert (self != NULL);
  _dbus_assert (self->refcount > 0);

  self->refcount -= 1;

  if (self->refcount == 0)
    {
      _dbus_verbose ("last reference, finalizing\n");

      if (self->unix_data && self->unix_data_free)
        {
          _dbus_verbose ("freeing unix authorization callback data\n");
          (*self->unix_data_free) (self->unix_data);
          self->unix_data = NULL;
        }

      if (self->windows_data && self->windows_data_free)
        {
          _dbus_verbose ("freeing windows authorization callback data\n");
          (*self->windows_data_free) (self->windows_data);
          self->windows_data = NULL;
        }

      dbus_free (self);
    }
}

/* Called by transport's set_connection with the connection locked */
void
_dbus_authorization_set_connection (DBusAuthorization *self,
                                DBusConnection *connection)
{
  _dbus_assert (connection != NULL);
  _dbus_assert (self->connection == NULL);

  self->connection = connection;
}


/**
 * Set the user set authorization callback for Unix identities authorizations.
 * The callback will be called at the end of the EXTERNAL authentication
 * mechanism and on every message.

 * See dbus_connection_set_unix_authorization_callback() and
 * _dbus_transport_set_unix_authorization_callback().
 *
 * @param self the authorization struct
 * @param function the predicate
 * @param data data to pass to the predicate
 * @param free_data_function function to free the data
 * @param old_data the old user data to be freed
 * @param old_free_data_function old free data function to free it with
 */
void
_dbus_authorization_set_unix_authorization_callback (DBusAuthorization             *self,
                                        DBusAllowUnixUserFunction  function,
                                        void                      *data,
                                        DBusFreeFunction           free_data_function,
                                        void                     **old_data,
                                        DBusFreeFunction          *old_free_data_function)
{
  *old_data = self->unix_data;
  *old_free_data_function = self->unix_data_free;

  self->unix_authorization_cb = function;
  self->unix_data = data;
  self->unix_data_free = free_data_function;
}

/**
 * Set the user set authorization callback for Windows identities
 * authorizations.
 * The callback will be called at the end of the EXTERNAL authentication
 * mechanism and on every message.
 *
 * See dbus_connection_set_windows_authorization_callback() and
 * _dbus_transport_set_windows_authorization_callback().
 *
 * @param self the authorization struct
 * @param function the predicate
 * @param data data to pass to the predicate
 * @param free_data_function function to free the data
 * @param old_data the old user data to be freed
 * @param old_free_data_function old free data function to free it with
 */

void
_dbus_authorization_set_windows_authorization_callback (DBusAuthorization              *self,
                                           DBusAllowWindowsUserFunction   function,
                                           void                       *data,
                                           DBusFreeFunction            free_data_function,
                                           void                      **old_data,
                                           DBusFreeFunction           *old_free_data_function)
{
  *old_data = self->windows_data;
  *old_free_data_function = self->windows_data_free;

  self->windows_authorization_cb = function;
  self->windows_data = data;
  self->windows_data_free = free_data_function;
}

static dbus_bool_t
auth_via_unix_authorization_callback (DBusAuthorization *self,
                             DBusCredentials *auth_identity)
{

  dbus_bool_t allow;
  dbus_uid_t uid;

  /* Dropping the lock here probably isn't that safe. */

  _dbus_assert (auth_identity != NULL);

  uid = _dbus_credentials_get_unix_uid (auth_identity);

  _dbus_verbose ("unlock connection before executing user's authorization callback\n");
  _dbus_connection_unlock (self->connection);

  allow = (*self->unix_authorization_cb) (self->connection,
                                  uid,
                                  self->unix_data);

  _dbus_verbose ("lock connection post unix-authorization callback\n");
  _dbus_connection_lock (self->connection);

  if (allow)
    {
      _dbus_verbose ("Client UID "DBUS_UID_FORMAT" authorized\n", uid);
    }
  else
    {
      _dbus_verbose ("Client UID "DBUS_UID_FORMAT " wasn't authorized.\n",
          _dbus_credentials_get_unix_uid (auth_identity));
    }

  return allow;
}


static dbus_bool_t
auth_via_windows_authorization_callback (DBusAuthorization *self,
                                DBusCredentials *auth_identity)
{
  dbus_bool_t allow;
  char *windows_sid;

  /* Dropping the lock here probably isn't that safe. */

  _dbus_assert (auth_identity != NULL);

  windows_sid = _dbus_strdup (_dbus_credentials_get_windows_sid (auth_identity));

  if (windows_sid == NULL)
    return FALSE; /* OOM */

  _dbus_verbose ("unlock connection before executing user's authorization callback\n");
  _dbus_connection_unlock (self->connection);

  allow = (*self->windows_authorization_cb) (self->connection,
                                     windows_sid,
                                     self->windows_data);

  _dbus_verbose ("lock connection post windows user's authorization callback\n");
  _dbus_connection_lock (self->connection);

  if (allow)
    {
      _dbus_verbose ("Client SID '%s' authorized\n", windows_sid);
    }
  else
    {
      _dbus_verbose ("Client SID '%s' wasn't authorized\n",
                     _dbus_credentials_get_windows_sid (auth_identity));
    }

  dbus_free (windows_sid);

  return allow;
}

static dbus_bool_t
auth_via_default_rules (DBusAuthorization *self,
                        DBusCredentials *auth_identity)

{
  DBusCredentials *our_identity;
  dbus_bool_t allow;

  _dbus_assert (auth_identity != NULL);

  /* By default, connection is allowed if the client is 1) root or 2)
   * has the same UID as us or 3) anonymous is allowed.
   */

  our_identity = _dbus_credentials_new_from_current_process ();
  if (our_identity == NULL)
    return FALSE; /* OOM */

  if (self->allow_anonymous ||
      _dbus_credentials_get_unix_uid (auth_identity) == 0 ||
      _dbus_credentials_same_user (our_identity, auth_identity))
    {
      if (_dbus_credentials_include (our_identity, DBUS_CREDENTIAL_WINDOWS_SID))
          _dbus_verbose ("Client authenticated as SID '%s'"
                         "matching our SID '%s': authorized\n",
                         _dbus_credentials_get_windows_sid (auth_identity),
                         _dbus_credentials_get_windows_sid (our_identity));
      else
          _dbus_verbose ("Client authenticated as UID "DBUS_UID_FORMAT
                         " matching our UID "DBUS_UID_FORMAT": authorized\n",
                         _dbus_credentials_get_unix_uid (auth_identity),
                         _dbus_credentials_get_unix_uid (our_identity));
      /* We have authenticated! */
      allow = TRUE;
    }
  else
    {
      if (_dbus_credentials_include(our_identity,DBUS_CREDENTIAL_WINDOWS_SID))
          _dbus_verbose ("Client authenticated as SID '%s'"
                         " but our SID is '%s', not authorizing\n",
                         (_dbus_credentials_get_windows_sid(auth_identity) ?
                          _dbus_credentials_get_windows_sid(auth_identity) : "<null>"),
                         (_dbus_credentials_get_windows_sid(our_identity) ?
                          _dbus_credentials_get_windows_sid(our_identity) : "<null>"));
      else
          _dbus_verbose ("Client authenticated as UID "DBUS_UID_FORMAT
                         " but our UID is "DBUS_UID_FORMAT", not authorizing\n",
                         _dbus_credentials_get_unix_uid(auth_identity),
                         _dbus_credentials_get_unix_uid(our_identity));
      allow = FALSE;
    }

  _dbus_credentials_unref (our_identity);

  return allow;
}

/* Called with DBusConnection lock held */
dbus_bool_t
_dbus_authorization_do_authorization (DBusAuthorization *self,
    DBusCredentials *auth_identity)
{
  dbus_bool_t allow;

  /* maybe-FIXME: at this point we *should* have a connection set unless we
   * are in some test case, but we assert its presence only in some if's
   * branches since default_rules does not need one and is used in a test case
   * without a connection set */

  if (_dbus_credentials_are_anonymous (auth_identity))
    {
      allow = self->allow_anonymous;
    }
  if (self->unix_authorization_cb != NULL &&
      _dbus_credentials_include (auth_identity, DBUS_CREDENTIAL_UNIX_USER_ID))
    {
      _dbus_assert (self->connection != NULL);
      allow = auth_via_unix_authorization_callback (self, auth_identity);
    }
  else if (self->windows_authorization_cb != NULL &&
      _dbus_credentials_include (auth_identity, DBUS_CREDENTIAL_WINDOWS_SID))
    {
      _dbus_assert (self->connection != NULL);
      allow = auth_via_windows_authorization_callback (self, auth_identity);
    }
  else
    {
      allow = auth_via_default_rules (self, auth_identity);
    }

  return allow;
}



/**
 * See dbus_connection_set_allow_anonymous()
 *
 * @param self an authorization struct
 * @param value #TRUE to allow anonymous connection
 */
void
_dbus_authorization_set_allow_anonymous (DBusAuthorization *self,
                                     dbus_bool_t value)
{
  self->allow_anonymous = value != FALSE;
}
