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

#ifndef TEST_UTILS_GLIB_H
#define TEST_UTILS_GLIB_H

#include <dbus/dbus.h>

#include <glib.h>

#include "test-utils.h"

#define test_assert_no_error(e) _test_assert_no_error (e, __FILE__, __LINE__)
void _test_assert_no_error (const DBusError *e,
    const char *file,
    int line);

gchar *test_get_dbus_daemon (const gchar *config_file,
    GPid *daemon_pid);

DBusConnection *test_connect_to_bus (TestMainContext *ctx,
    const gchar *address);

void test_kill_pid (GPid pid);

#endif
