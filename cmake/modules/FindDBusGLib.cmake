# - Try to find the DBUSGLIB libraries
# Once done this will define
#
#  DBUSGLIB_FOUND - system has DBUSGLIB
#  DBUSGLIB_INCLUDE_DIR - the DBUSGLIB include directory
#  DBUSGLIB_LIBRARIES - DBUSGLIB library

# Copyright (c) 2013 Ralf Habacker <ralf.habacker@freenet.de>
#
# Redistribution and use is allowed according to the terms of the BSD license.
# For details see the accompanying COPYING-CMAKE-SCRIPTS file.

if(DBUSGLIB_INCLUDE_DIR AND DBUSGLIB_LIBRARIES)
    # Already in cache, be silent
    set(DBUSGLIB_FIND_QUIETLY TRUE)
endif(DBUSGLIB_INCLUDE_DIR AND DBUSGLIB_LIBRARIES)

if(NOT WIN32)
    find_package(PkgConfig)
    pkg_check_modules(PC_LibDBUSGLIB QUIET dbus-glib)
endif()

find_path(DBUSGLIB_INCLUDE_DIR
          NAMES dbus/dbus-glib.h
          HINTS ${PC_LibDBUSGLIB_INCLUDEDIR}
          PATH_SUFFIXES dbus-1.0)

find_library(DBUSGLIB_LIBRARY
             NAMES dbus-glib-1
             HINTS ${PC_LibDBUSGLIB_LIBDIR}
)

set(DBUSGLIB_LIBRARIES ${DBUSGLIB_LIBRARY})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(DBUSGLIB  DEFAULT_MSG  DBUSGLIB_LIBRARIES DBUSGLIB_INCLUDE_DIR)

mark_as_advanced(DBUSGLIB_INCLUDE_DIR DBUSGLIB_LIBRARIES)
