# Install script for directory: /Users/miguel/Downloads/wireshark-3.4.2

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
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE DIRECTORY FILES "/Users/miguel/Downloads/make/run/Wireshark.app" USE_SOURCE_PERMISSIONS)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/Wireshark.app/Contents/MacOS/Wireshark" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/Wireshark.app/Contents/MacOS/Wireshark")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/usr/local/opt/gettext/lib"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/Wireshark.app/Contents/MacOS/Wireshark")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/Users/miguel/Downloads/make/run"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/Wireshark.app/Contents/MacOS/Wireshark")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/usr/local/Caskroom/sparkle/1.22.0"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/Wireshark.app/Contents/MacOS/Wireshark")
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE EXECUTABLE FILES "/Users/miguel/Downloads/make/run/Wireshark.app/Contents/MacOS/tshark")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/tshark" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/tshark")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/usr/local/opt/gettext/lib"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/tshark")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/Users/miguel/Downloads/make/run"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/tshark")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/Library/Developer/CommandLineTools/usr/bin/strip" -u -r "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/tshark")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE EXECUTABLE FILES "/Users/miguel/Downloads/make/run/Wireshark.app/Contents/MacOS/rawshark")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/rawshark" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/rawshark")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/usr/local/opt/gettext/lib"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/rawshark")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/Users/miguel/Downloads/make/run"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/rawshark")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/Library/Developer/CommandLineTools/usr/bin/strip" -u -r "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/rawshark")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE EXECUTABLE FILES "/Users/miguel/Downloads/make/run/Wireshark.app/Contents/MacOS/sharkd")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/sharkd" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/sharkd")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/usr/local/opt/gettext/lib"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/sharkd")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/Users/miguel/Downloads/make/run"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/sharkd")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/Library/Developer/CommandLineTools/usr/bin/strip" -u -r "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/sharkd")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE EXECUTABLE FILES "/Users/miguel/Downloads/make/run/Wireshark.app/Contents/MacOS/randpkt")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/randpkt" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/randpkt")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/usr/local/opt/gettext/lib"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/randpkt")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/Users/miguel/Downloads/make/run"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/randpkt")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/Library/Developer/CommandLineTools/usr/bin/strip" -u -r "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/randpkt")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE EXECUTABLE FILES "/Users/miguel/Downloads/make/run/Wireshark.app/Contents/MacOS/text2pcap")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/text2pcap" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/text2pcap")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/usr/local/opt/gettext/lib"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/text2pcap")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/Users/miguel/Downloads/make/run"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/text2pcap")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/Library/Developer/CommandLineTools/usr/bin/strip" -u -r "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/text2pcap")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE EXECUTABLE FILES "/Users/miguel/Downloads/make/run/Wireshark.app/Contents/MacOS/mergecap")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/mergecap" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/mergecap")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/usr/local/opt/gettext/lib"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/mergecap")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/Users/miguel/Downloads/make/run"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/mergecap")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/Library/Developer/CommandLineTools/usr/bin/strip" -u -r "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/mergecap")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE EXECUTABLE FILES "/Users/miguel/Downloads/make/run/Wireshark.app/Contents/MacOS/reordercap")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/reordercap" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/reordercap")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/usr/local/opt/gettext/lib"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/reordercap")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/Users/miguel/Downloads/make/run"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/reordercap")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/Library/Developer/CommandLineTools/usr/bin/strip" -u -r "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/reordercap")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE EXECUTABLE FILES "/Users/miguel/Downloads/make/run/Wireshark.app/Contents/MacOS/capinfos")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/capinfos" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/capinfos")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/usr/local/opt/gettext/lib"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/capinfos")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/Users/miguel/Downloads/make/run"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/capinfos")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/Library/Developer/CommandLineTools/usr/bin/strip" -u -r "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/capinfos")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE EXECUTABLE FILES "/Users/miguel/Downloads/make/run/Wireshark.app/Contents/MacOS/captype")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/captype" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/captype")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/usr/local/opt/gettext/lib"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/captype")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/Users/miguel/Downloads/make/run"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/captype")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/Library/Developer/CommandLineTools/usr/bin/strip" -u -r "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/captype")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE EXECUTABLE FILES "/Users/miguel/Downloads/make/run/Wireshark.app/Contents/MacOS/editcap")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/editcap" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/editcap")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/usr/local/opt/gettext/lib"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/editcap")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/Users/miguel/Downloads/make/run"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/editcap")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/Library/Developer/CommandLineTools/usr/bin/strip" -u -r "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/editcap")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE EXECUTABLE PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE FILES "/Users/miguel/Downloads/make/run/Wireshark.app/Contents/MacOS/dumpcap")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/dumpcap" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/dumpcap")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/usr/local/opt/gettext/lib"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/dumpcap")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/Users/miguel/Downloads/make/run"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/dumpcap")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/Library/Developer/CommandLineTools/usr/bin/strip" -u -r "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/dumpcap")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE EXECUTABLE FILES "/Users/miguel/Downloads/make/run/Wireshark.app/Contents/MacOS/idl2wrs")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/idl2wrs" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/idl2wrs")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/usr/local/opt/gettext/lib"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/idl2wrs")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/Users/miguel/Downloads/make/run"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/idl2wrs")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/Library/Developer/CommandLineTools/usr/bin/strip" -u -r "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/idl2wrs")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE EXECUTABLE FILES "/Users/miguel/Downloads/make/run/Wireshark.app/Contents/MacOS/mmdbresolve")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/mmdbresolve" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/mmdbresolve")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/usr/local/opt/gettext/lib"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/mmdbresolve")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/Library/Developer/CommandLineTools/usr/bin/strip" -u -r "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/mmdbresolve")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/wireshark" TYPE FILE PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ FILES
    "/Users/miguel/Downloads/wireshark-3.4.2/cfilters"
    "/Users/miguel/Downloads/wireshark-3.4.2/colorfilters"
    "/Users/miguel/Downloads/wireshark-3.4.2/dfilters"
    "/Users/miguel/Downloads/wireshark-3.4.2/dfilter_macros"
    "/Users/miguel/Downloads/wireshark-3.4.2/enterprises.tsv"
    "/Users/miguel/Downloads/wireshark-3.4.2/ipmap.html"
    "/Users/miguel/Downloads/wireshark-3.4.2/manuf"
    "/Users/miguel/Downloads/wireshark-3.4.2/pdml2html.xsl"
    "/Users/miguel/Downloads/wireshark-3.4.2/services"
    "/Users/miguel/Downloads/wireshark-3.4.2/smi_modules"
    "/Users/miguel/Downloads/wireshark-3.4.2/wka"
    "/Users/miguel/Downloads/wireshark-3.4.2/docbook/ws.css"
    "/Users/miguel/Downloads/make/doc/AUTHORS-SHORT"
    "/Users/miguel/Downloads/make/doc/androiddump.html"
    "/Users/miguel/Downloads/make/doc/udpdump.html"
    "/Users/miguel/Downloads/make/doc/capinfos.html"
    "/Users/miguel/Downloads/make/doc/captype.html"
    "/Users/miguel/Downloads/make/doc/ciscodump.html"
    "/Users/miguel/Downloads/make/doc/dftest.html"
    "/Users/miguel/Downloads/make/doc/dumpcap.html"
    "/Users/miguel/Downloads/make/doc/editcap.html"
    "/Users/miguel/Downloads/make/doc/extcap.html"
    "/Users/miguel/Downloads/make/doc/mergecap.html"
    "/Users/miguel/Downloads/make/doc/randpkt.html"
    "/Users/miguel/Downloads/make/doc/randpktdump.html"
    "/Users/miguel/Downloads/make/doc/rawshark.html"
    "/Users/miguel/Downloads/make/doc/reordercap.html"
    "/Users/miguel/Downloads/make/doc/sshdump.html"
    "/Users/miguel/Downloads/make/doc/text2pcap.html"
    "/Users/miguel/Downloads/make/doc/tshark.html"
    "/Users/miguel/Downloads/make/doc/wireshark.html"
    "/Users/miguel/Downloads/make/doc/wireshark-filter.html"
    "/Users/miguel/Downloads/make/doc/mmdbresolve.html"
    "/Users/miguel/Downloads/wireshark-3.4.2/COPYING"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/wireshark" TYPE FILE FILES
    "/Users/miguel/Downloads/wireshark-3.4.2/cfile.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/cli_main.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/file.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/globals.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/log.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/ws_attributes.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/ws_compiler_tests.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/ws_diag_control.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/ws_symbol_export.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/version_info.h"
    "/Users/miguel/Downloads/make/ws_version.h"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/pkgconfig" TYPE FILE FILES "/Users/miguel/Downloads/make/wireshark.pc")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/wireshark" TYPE DIRECTORY PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ DIR_PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ FILES
    "/Users/miguel/Downloads/wireshark-3.4.2/diameter"
    "/Users/miguel/Downloads/wireshark-3.4.2/dtds"
    "/Users/miguel/Downloads/wireshark-3.4.2/profiles"
    "/Users/miguel/Downloads/wireshark-3.4.2/radius"
    "/Users/miguel/Downloads/wireshark-3.4.2/tpncp"
    "/Users/miguel/Downloads/wireshark-3.4.2/wimaxasncp"
    REGEX "/\\.git$" EXCLUDE REGEX "/\\.svn$" EXCLUDE REGEX "/makefile\\.[^/]*$" EXCLUDE)
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/wireshark/cmake" TYPE FILE FILES
    "/Users/miguel/Downloads/wireshark-3.4.2/cmake/modules/FindGLIB2.cmake"
    "/Users/miguel/Downloads/wireshark-3.4.2/cmake/modules/FindWSLibrary.cmake"
    "/Users/miguel/Downloads/wireshark-3.4.2/cmake/modules/FindWSWinLibs.cmake"
    "/Users/miguel/Downloads/wireshark-3.4.2/cmake/modules/UseAsn2Wrs.cmake"
    "/Users/miguel/Downloads/wireshark-3.4.2/cmake/modules/LocatePythonModule.cmake"
    "/Users/miguel/Downloads/wireshark-3.4.2/cmake/modules/UseMakePluginReg.cmake"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/wireshark/cmake" TYPE FILE FILES
    "/Users/miguel/Downloads/make/WiresharkConfig.cmake"
    "/Users/miguel/Downloads/make/WiresharkConfigVersion.cmake"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/wireshark/cmake/WiresharkTargets.cmake")
    file(DIFFERENT EXPORT_FILE_CHANGED FILES
         "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/wireshark/cmake/WiresharkTargets.cmake"
         "/Users/miguel/Downloads/make/CMakeFiles/Export/lib/wireshark/cmake/WiresharkTargets.cmake")
    if(EXPORT_FILE_CHANGED)
      file(GLOB OLD_CONFIG_FILES "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/wireshark/cmake/WiresharkTargets-*.cmake")
      if(OLD_CONFIG_FILES)
        message(STATUS "Old export file \"$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/wireshark/cmake/WiresharkTargets.cmake\" will be replaced.  Removing files [${OLD_CONFIG_FILES}].")
        file(REMOVE ${OLD_CONFIG_FILES})
      endif()
    endif()
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/wireshark/cmake" TYPE FILE FILES "/Users/miguel/Downloads/make/CMakeFiles/Export/lib/wireshark/cmake/WiresharkTargets.cmake")
  if("${CMAKE_INSTALL_CONFIG_NAME}" MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/wireshark/cmake" TYPE FILE FILES "/Users/miguel/Downloads/make/CMakeFiles/Export/lib/wireshark/cmake/WiresharkTargets-relwithdebinfo.cmake")
  endif()
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/Users/miguel/Downloads/make/speexdsp/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/capchild/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/caputils/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/doc/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/epan/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/extcap/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/randpkt_core/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/tools/lemon/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/ui/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/wiretap/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/writecap/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/wsutil/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/ui/qt/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/plugins/epan/ethercat/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/plugins/epan/gryphon/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/plugins/epan/irda/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/plugins/epan/mate/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/plugins/epan/opcua/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/plugins/epan/profinet/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/plugins/epan/stats_tree/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/plugins/epan/transum/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/plugins/epan/unistim/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/plugins/epan/wimax/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/plugins/epan/wimaxasncp/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/plugins/epan/wimaxmacphy/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/plugins/wiretap/usbdump/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/plugins/codecs/G711/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/plugins/codecs/l16_mono/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/plugins/epan/s7comm_plus/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/fuzz/cmake_install.cmake")

endif()

if(CMAKE_INSTALL_COMPONENT)
  set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
file(WRITE "/Users/miguel/Downloads/make/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
