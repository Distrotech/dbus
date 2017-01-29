add_definitions("-DDBUS_COMPILATION")

set (dbus_send_SOURCES
	../../tools/dbus-print-message.c			
	../../tools/dbus-print-message.h			
	../../tools/dbus-send.c
	../../tools/tool-common.c
	../../tools/tool-common.h
)

set (dbus_monitor_SOURCES
	../../tools/dbus-monitor.c				
	../../tools/dbus-print-message.c			
	../../tools/dbus-print-message.h
	../../tools/tool-common.c
	../../tools/tool-common.h
)

set (dbus_test_tool_SOURCES
	../../tools/dbus-echo.c
	../../tools/dbus-spam.c
	../../tools/tool-common.c
	../../tools/tool-common.h
	../../tools/test-tool.c
	../../tools/test-tool.h
)

set (dbus_update_activation_environment_SOURCES
	../../tools/dbus-update-activation-environment.c
	../../tools/tool-common.c
	../../tools/tool-common.h
)

if (WIN32)
set (dbus_launch_SOURCES
	../../tools/dbus-launch-win.c
)
else (WIN32)
set (dbus_launch_SOURCES
	../../tools/dbus-launch.c
	../../tools/tool-common.c
	../../tools/tool-common.h
)
endif (WIN32)

if (DBUS_BUILD_X11)
set (dbus_launch_SOURCES
     ${dbus_launch_SOURCES}
     ../../tools/dbus-launch-x11.c
)
endif(DBUS_BUILD_X11)

set (dbus_cleanup_sockets_SOURCES
	../../tools/dbus-cleanup-sockets.c
)

add_executable(dbus-send ${dbus_send_SOURCES})
target_link_libraries(dbus-send ${DBUS_LIBRARIES})
install(TARGETS dbus-send ${INSTALL_TARGETS_DEFAULT_ARGS})

add_executable(dbus-test-tool ${dbus_test_tool_SOURCES})
target_link_libraries(dbus-test-tool ${DBUS_LIBRARIES})
install(TARGETS dbus-test-tool ${INSTALL_TARGETS_DEFAULT_ARGS})

add_executable(dbus-update-activation-environment ${dbus_update_activation_environment_SOURCES})
target_link_libraries(dbus-update-activation-environment ${DBUS_LIBRARIES})
install(TARGETS dbus-update-activation-environment ${INSTALL_TARGETS_DEFAULT_ARGS})

add_executable(dbus-launch ${dbus_launch_SOURCES})
target_link_libraries(dbus-launch ${DBUS_LIBRARIES})
if (DBUS_BUILD_X11)
  target_link_libraries(dbus-launch ${X11_LIBRARIES} )
endif (DBUS_BUILD_X11)
install(TARGETS dbus-launch ${INSTALL_TARGETS_DEFAULT_ARGS})

add_executable(dbus-monitor ${dbus_monitor_SOURCES})
target_link_libraries(dbus-monitor ${DBUS_LIBRARIES})
install(TARGETS dbus-monitor ${INSTALL_TARGETS_DEFAULT_ARGS})

# create the /var/lib/dbus directory for dbus-uuidgen
install(DIRECTORY DESTINATION var/lib/dbus)
