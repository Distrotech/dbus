#! /bin/sh

SCRIPTNAME=$0
MODE=$1

## so the tests can complain if you fail to use the script to launch them
DBUS_TEST_NAME_RUN_TEST_SCRIPT=1
export DBUS_TEST_NAME_RUN_TEST_SCRIPT

SOURCE_CONFIG_FILE=$DBUS_TOP_SRCDIR/test/name-test/tmp-session-like-system.conf
export SOURCE_CONFIG_FILE
# Rerun ourselves with tmp session bus if we're not already
if test -z "$DBUS_TEST_NAME_IN_SYS_RUN_TEST"; then
  DBUS_TEST_NAME_IN_SYS_RUN_TEST=1
  export DBUS_TEST_NAME_IN_SYS_RUN_TEST
  exec $DBUS_TOP_SRCDIR/tools/run-with-tmp-session-bus.sh $SCRIPTNAME $MODE
fi 

if test -n "$DBUS_TEST_MONITOR"; then
  dbus-monitor --session >&2 &
fi

XDG_RUNTIME_DIR="$DBUS_TOP_BUILDDIR"/test/XDG_RUNTIME_DIR
test -d "$XDG_RUNTIME_DIR" || mkdir "$XDG_RUNTIME_DIR"
chmod 0700 "$XDG_RUNTIME_DIR"
export XDG_RUNTIME_DIR

# Translate a command and exit status into TAP syntax.
# Usage: interpret_result $? description-of-test
# Uses global variable $test_num.
interpret_result () {
  e="$1"
  shift
  case "$e" in
    (0)
      echo "ok $test_num $*"
      ;;
    (77)
      echo "ok $test_num # SKIP $*"
      ;;
    (*)
      echo "not ok $test_num $*"
      ;;
  esac
  test_num=$(( $test_num + 1 ))
}

dbus_send_test () {
  t="$1"
  expected_exit="$2"
  phrase="$3"
  shift 3
  e=0
  echo "# running test $t"
  "${DBUS_TOP_BUILDDIR}/libtool" --mode=execute $DEBUG "$DBUS_TOP_BUILDDIR/tools/dbus-send" "$@" > output.tmp 2>&1 || e=$?
  if [ $e != $expected_exit ]; then
    sed -e 's/^/#  /' < output.tmp
    interpret_result "1" "$t" "$@" "(expected exit status $expected_exit, got $e)"
    return
  fi
  echo "# parsing results of test $t"
  if ! grep -q "$phrase" output.tmp; then
    sed -e 's/^/#  /' < output.tmp
    interpret_result "1" "$t" "$@" "(Did not see \"$phrase\" in output)"
    return
  fi
  interpret_result "0" "$t" "$@" "(Saw \"$phrase\" in output as expected)"
  rm -f output.tmp
}

py_test () {
  t="$1"
  shift
  if test "x$PYTHON" = "x:"; then
    interpret_result 77 "$t" "(Python interpreter not found)"
  else
    e=0
    echo "# running test $t"
    $PYTHON "$DBUS_TOP_SRCDIR/test/name-test/$t" "$@" >&2 || e=$?
    interpret_result "$e" "$t" "$@"
  fi
}

test_num=1
# TAP syntax: we plan to run 2 tests
echo "1..2"

dbus_send_test test-expected-echo-fail 1 DBus.Error --print-reply --dest=org.freedesktop.DBus.TestSuiteEchoService /org/freedesktop/TestSuite org.freedesktop.TestSuite.Echo string:hi
py_test test-wait-for-echo.py
