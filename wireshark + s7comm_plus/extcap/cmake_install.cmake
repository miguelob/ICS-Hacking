# Install script for directory: /Users/miguel/Downloads/wireshark-3.4.2/extcap

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "RelWithDebInfo")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/Library/Developer/CommandLineTools/usr/bin/objdump")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap" TYPE EXECUTABLE FILES "/Users/miguel/Downloads/make/run/Wireshark.app/Contents/MacOS/extcap/androiddump")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap/androiddump" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap/androiddump")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/usr/local/opt/gettext/lib"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap/androiddump")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/Users/miguel/Downloads/make/run"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap/androiddump")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/Library/Developer/CommandLineTools/usr/bin/strip" -u -r "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap/androiddump")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap" TYPE EXECUTABLE FILES "/Users/miguel/Downloads/make/run/Wireshark.app/Contents/MacOS/extcap/sshdump")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap/sshdump" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap/sshdump")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/usr/local/opt/gettext/lib"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap/sshdump")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/Users/miguel/Downloads/make/run"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap/sshdump")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/Library/Developer/CommandLineTools/usr/bin/strip" -u -r "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap/sshdump")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap" TYPE EXECUTABLE FILES "/Users/miguel/Downloads/make/run/Wireshark.app/Contents/MacOS/extcap/ciscodump")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap/ciscodump" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap/ciscodump")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/usr/local/opt/gettext/lib"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap/ciscodump")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/Users/miguel/Downloads/make/run"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap/ciscodump")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/Library/Developer/CommandLineTools/usr/bin/strip" -u -r "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap/ciscodump")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap" TYPE EXECUTABLE FILES "/Users/miguel/Downloads/make/run/Wireshark.app/Contents/MacOS/extcap/udpdump")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap/udpdump" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap/udpdump")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/usr/local/opt/gettext/lib"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap/udpdump")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/Users/miguel/Downloads/make/run"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap/udpdump")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/Library/Developer/CommandLineTools/usr/bin/strip" -u -r "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap/udpdump")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap" TYPE EXECUTABLE FILES "/Users/miguel/Downloads/make/run/Wireshark.app/Contents/MacOS/extcap/randpktdump")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap/randpktdump" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap/randpktdump")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/usr/local/opt/gettext/lib"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap/randpktdump")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/Users/miguel/Downloads/make/run"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap/randpktdump")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/Library/Developer/CommandLineTools/usr/bin/strip" -u -r "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/wireshark/extcap/randpktdump")
    endif()
  endif()
endif()

