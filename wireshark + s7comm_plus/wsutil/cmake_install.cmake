# Install script for directory: /Users/miguel/Downloads/wireshark-3.4.2/wsutil

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
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES
    "/Users/miguel/Downloads/make/run/libwsutil.12.0.0.dylib"
    "/Users/miguel/Downloads/make/run/libwsutil.12.dylib"
    )
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwsutil.12.0.0.dylib"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwsutil.12.dylib"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      execute_process(COMMAND /usr/bin/install_name_tool
        -delete_rpath "/usr/local/opt/gettext/lib"
        "${file}")
      if(CMAKE_INSTALL_DO_STRIP)
        execute_process(COMMAND "/Library/Developer/CommandLineTools/usr/bin/strip" -x "${file}")
      endif()
    endif()
  endforeach()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES "/Users/miguel/Downloads/make/run/libwsutil.dylib")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwsutil.dylib" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwsutil.dylib")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/usr/local/opt/gettext/lib"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwsutil.dylib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/Library/Developer/CommandLineTools/usr/bin/strip" -x "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwsutil.dylib")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/wireshark/wsutil" TYPE FILE FILES
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/adler32.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/base32.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/bits_count_ones.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/bits_ctz.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/bitswap.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/buffer.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/codecs.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/color.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/copyright_info.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/cpu_info.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/crash_info.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/crc5.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/crc6.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/crc7.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/crc8.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/crc10.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/crc11.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/crc16.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/crc16-plain.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/crc32.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/curve25519.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/eax.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/epochs.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/filesystem.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/frequency-utils.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/g711.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/inet_addr.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/inet_ipv4.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/inet_ipv6.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/interface.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/jsmn.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/json_dumper.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/mpeg-audio.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/netlink.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/nstime.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/os_version_info.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/pint.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/please_report_bug.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/plugins.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/pow2.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/privileges.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/processes.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/report_message.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/sign_ext.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/sober128.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/socket.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/str_util.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/strnatcmp.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/strtoi.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/tempfile.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/time_util.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/type_util.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/unicode-utils.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/utf8_entities.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/ws_cpuid.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/ws_mempbrk.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/ws_mempbrk_int.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/ws_pipe.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/ws_printf.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/wsjson.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/wsutil/xtea.h"
    )
endif()

