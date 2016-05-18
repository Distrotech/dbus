/* This is simply a process that segfaults */
#include <config.h>
#include <stdlib.h>
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#ifdef HAVE_SETRLIMIT
#include <sys/resource.h>
#endif

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#ifdef DBUS_WIN
#include <stdio.h>
#include <windows.h>

int
exception_handler(LPEXCEPTION_POINTERS p);

/* Explicit Windows exception handlers needed to supress OS popups */
int
exception_handler(LPEXCEPTION_POINTERS p)
{
  fprintf(stderr, "test-segfault: raised fatal exception as intended\n");
  ExitProcess(0xc0000005);
}
#endif

int
main (int argc, char **argv)
{
  char *p;  

#ifdef DBUS_WIN
  /* Disable Windows popup dialog when an app crashes so that app quits
   * immediately with error code instead of waiting for user to dismiss
   * the dialog.  */
  DWORD dwMode = SetErrorMode(SEM_NOGPFAULTERRORBOX);
  SetErrorMode(dwMode | SEM_NOGPFAULTERRORBOX);
  /* Disable "just in time" debugger */
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)&exception_handler);
#endif

#if HAVE_SETRLIMIT
  /* No core dumps please, we know we crashed. */
  struct rlimit r = { 0, };
  
  getrlimit (RLIMIT_CORE, &r);
  r.rlim_cur = 0;
  setrlimit (RLIMIT_CORE, &r);
#endif

#if defined(HAVE_PRCTL) && defined(PR_SET_DUMPABLE)
  /* Really, no core dumps please. On Linux, if core_pattern is
   * set to a pipe (for abrt/apport/corekeeper/etc.), RLIMIT_CORE of 0
   * is ignored (deliberately, so people can debug init(8) and other
   * early stuff); but Linux has PR_SET_DUMPABLE, so we can avoid core
   * dumps anyway. */
  prctl (PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif

#ifdef HAVE_RAISE
  raise (SIGSEGV);
#endif
  p = NULL;
  *p = 'a';
  
  return 0;
}
