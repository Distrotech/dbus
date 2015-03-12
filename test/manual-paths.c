/*
 * Simple manual paths check
 *
 * syntax:  manual-paths
 *
*/

#include "config.h"
#include "dbus/dbus-list.h"
#include "dbus/dbus-internals.h"
#include "dbus/dbus-sysdeps.h"

#include <stdio.h>

static dbus_bool_t print_install_root()
{
  char runtime_prefix[1000];

  if (!_dbus_get_install_root(runtime_prefix, sizeof(runtime_prefix)))
    {
      fprintf(stderr, "dbus_get_install_root() failed\n");
      return FALSE;
    }
  fprintf(stdout, "dbus_get_install_root() returned '%s'\n", runtime_prefix);
  return TRUE;
}

static dbus_bool_t print_service_dirs()
{
  DBusList *dirs;
  DBusList *link;
  dirs = NULL;

  if (!_dbus_get_standard_session_servicedirs (&dirs))
    _dbus_assert_not_reached ("couldn't get standard dirs");

  while ((link = _dbus_list_pop_first_link (&dirs)))
    {
      printf ("default service dir: %s\n", (char *)link->data);
      dbus_free (link->data);
      _dbus_list_free_link (link);
    }
  dbus_free (dirs);
  return TRUE;
}

static dbus_bool_t print_replace_install_prefix(const char *s)
{
  const char *s2 = _dbus_replace_install_prefix(s);
  if (!s2)
    return FALSE;

  fprintf(stdout, "replaced '%s' by '%s'\n", s, s2);
  return TRUE;
}

int
main (int argc, char **argv)
{
  if (!print_install_root())
    return -1;

  if (!print_service_dirs())
    return -2;

  if (!print_replace_install_prefix(DBUS_BINDIR "/dbus-daemon"))
    return -3;

  if (!print_replace_install_prefix("c:\\Windows\\System32\\testfile"))
    return -4;

  return 0;
}
