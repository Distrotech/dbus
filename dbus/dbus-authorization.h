#ifndef _DBUS_AUTHORIZE_H
#define _DBUS_AUTHORIZE_H

#include <dbus/dbus-connection.h>
#include <dbus/dbus-credentials.h>

typedef struct DBusAuthorization DBusAuthorization;

DBusAuthorization *_dbus_authorization_new (void);
void _dbus_authorization_set_connection (DBusAuthorization *self,
    DBusConnection *connection);
DBusAuthorization * _dbus_authorization_ref (DBusAuthorization *self);
void _dbus_authorization_unref (DBusAuthorization *self);
void _dbus_authorization_set_unix_authorization_callback (DBusAuthorization *self,
    DBusAllowUnixUserFunction function, void *data,
    DBusFreeFunction free_data_function, void **old_data,
    DBusFreeFunction *old_free_data_function);
void _dbus_authorization_set_windows_authorization_callback (DBusAuthorization *self,
    DBusAllowWindowsUserFunction function, void *data,
    DBusFreeFunction free_data_function, void **old_data,
    DBusFreeFunction *old_free_data_function);
dbus_bool_t _dbus_authorization_do_authorization (DBusAuthorization *self, DBusCredentials *creds);
void _dbus_authorization_set_allow_anonymous (DBusAuthorization *self, dbus_bool_t value);

#endif /* _DBUS_AUTHORIZE_H */
