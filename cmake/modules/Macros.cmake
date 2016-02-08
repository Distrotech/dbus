if(DBUS_BUILD_TESTS AND CMAKE_CROSSCOMPILING AND CMAKE_SYSTEM_NAME STREQUAL "Windows")
    if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
        find_file(WINE_EXECUTABLE
            NAMES wine
            PATHS /usr/bin /usr/local/bin
            NO_CMAKE_FIND_ROOT_PATH
        )
        find_file(BINFMT_WINE_SUPPORT_FILE
            NAMES DOSWin wine Wine windows Windows
            PATHS /proc/sys/fs/binfmt_misc
            NO_SYSTEM_PATH NO_CMAKE_FIND_ROOT_PATH
        )
        if(BINFMT_WINE_SUPPORT_FILE)
            file(READ ${BINFMT_WINE_SUPPORT_FILE} CONTENT)
            if(${CONTENT} MATCHES "enabled")
                set(HAVE_BINFMT_WINE_SUPPORT 1)
            endif()
        endif()
        if(WINE_EXECUTABLE)
            list(APPEND FOOTNOTES "NOTE: The requirements to run cross compiled applications on your host system are achieved. You may run 'make check'.")
        endif()
        if(NOT WINE_EXECUTABLE)
            list(APPEND FOOTNOTES "NOTE: You may install the Windows emulator 'wine' to be able to run cross compiled test applications.")
        endif()
        if(NOT HAVE_BINFMT_WINE_SUPPORT)
            list(APPEND FOOTNOTES "NOTE: You may activate binfmt_misc support for wine to be able to run cross compiled test applications directly.")
        endif()
    else()
        list(APPEND FOOTNOTES "NOTE: You will not be able to run cross compiled applications on your host system.")
    endif()
endif()

MACRO(TIMESTAMP RESULT)
    if (CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
        EXECUTE_PROCESS(COMMAND "cmd" " /C date /T" OUTPUT_VARIABLE DATE)
        string(REGEX REPLACE "(..)[/.](..)[/.](....).*" "\\3\\2\\1" DATE ${DATE})
        EXECUTE_PROCESS(COMMAND "cmd" " /C time /T" OUTPUT_VARIABLE TIME)
        string(REGEX REPLACE "(..):(..)" "\\1\\2" TIME ${TIME})
        set (${RESULT} "${DATE}${TIME}")
    else ()
        EXECUTE_PROCESS(COMMAND "date" "+%Y%m%d%H%M" OUTPUT_VARIABLE ${RESULT})
    endif ()
ENDMACRO()

macro(add_test_executable _target _source)
    add_executable(${_target} ${_source})
    target_link_libraries(${_target} ${ARGN})
    if (CMAKE_CROSSCOMPILING AND CMAKE_SYSTEM_NAME STREQUAL "Windows")
        # run tests with binfmt_misc
        set(PREFIX "z:")
        set(_env "DBUS_TEST_DAEMON=${PREFIX}${CMAKE_BINARY_DIR}/bin/dbus-daemon${EXEEXT}")
        if(HAVE_BINFMT_WINE_SUPPORT)
            add_test(NAME ${_target} COMMAND $<TARGET_FILE:${_target}> --tap)
        else()
            add_test(NAME ${_target} COMMAND ${WINE_EXECUTABLE} ${PREFIX}$<TARGET_FILE:${_target}> --tap)
        endif()
    else()
        set(PREFIX)
        set(_env "DBUS_TEST_DAEMON=${CMAKE_BINARY_DIR}/bin/dbus-daemon${EXEEXT}")
        add_test(NAME ${_target} COMMAND $<TARGET_FILE:${_target}> --tap)
    endif()
    list(APPEND _env "DBUS_SESSION_BUS_ADDRESS=")
    list(APPEND _env "DBUS_FATAL_WARNINGS=1")
    list(APPEND _env "DBUS_TEST_DATA=${PREFIX}${CMAKE_BINARY_DIR}/test/data")
    list(APPEND _env "DBUS_TEST_DBUS_LAUNCH=${PREFIX}${CMAKE_BINARY_DIR}/bin/dbus-launch${EXEEXT}")
    list(APPEND _env "DBUS_TEST_HOMEDIR=${PREFIX}${CMAKE_BINARY_DIR}/dbus")
    set_tests_properties(${_target} PROPERTIES ENVIRONMENT "${_env}")
endmacro(add_test_executable)

macro(add_helper_executable _target _source)
    add_executable(${_target} ${_source})
    target_link_libraries(${_target} ${ARGN})
endmacro(add_helper_executable)


#
# generate compiler flags from MSVC warning identifiers (e.g. '4114') or gcc warning keys (e.g. 'pointer-sign')
#
# @param target the variable name which will contain the warnings flags
# @param warnings a string with space delimited warnings
# @param disabled_warnings a string with space delimited disabled warnings
# @param error_warnings a string with space delimited warnings which should result into compile errors
#
macro(generate_warning_cflags target warnings disabled_warnings error_warnings)
    if(DEBUG_MACROS)
        message("generate_warning_cflags got: ${warnings} - ${disabled_warnings} - ${error_warnings}")
    endif()
    if(MSVC)
        # level 1 is default
        set(enabled_prefix "/w1")
        set(error_prefix "/we")
        set(disabled_prefix "/wd")
    else()
        set(enabled_prefix "-W")
        set(error_prefix "-Werror=")
        set(disabled_prefix "-Wno-")
    endif()

    set(temp)
    string(REPLACE " " ";" warnings_list "${warnings}")
    foreach(warning ${warnings_list})
        string(STRIP ${warning} _warning)
        if(_warning)
            set(temp "${temp} ${enabled_prefix}${_warning}")
        endif()
    endforeach()

    string(REPLACE " " ";" disabled_warnings_list "${disabled_warnings}")
    foreach(warning ${disabled_warnings_list})
        string(STRIP ${warning} _warning)
        if(_warning)
            set(temp "${temp} ${disabled_prefix}${_warning}")
        endif()
    endforeach()

    string(REPLACE " " ";" error_warnings_list "${error_warnings}")
    foreach(warning ${error_warnings_list})
        string(STRIP ${warning} _warning)
        if(_warning)
            set(temp "${temp} ${error_prefix}${_warning}")
        endif()
    endforeach()
    set(${target} "${temp}")
    if(DEBUG_MACROS)
        message("generate_warning_cflags return: ${${target}}")
    endif()
endmacro()
