# Install script for directory: /Users/miguel/Downloads/wireshark-3.4.2/doc

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
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/man/man1" TYPE FILE FILES
    "/Users/miguel/Downloads/make/doc/androiddump.1"
    "/Users/miguel/Downloads/make/doc/capinfos.1"
    "/Users/miguel/Downloads/make/doc/captype.1"
    "/Users/miguel/Downloads/make/doc/ciscodump.1"
    "/Users/miguel/Downloads/make/doc/ciscodump.1"
    "/Users/miguel/Downloads/make/doc/dftest.1"
    "/Users/miguel/Downloads/make/doc/dumpcap.1"
    "/Users/miguel/Downloads/make/doc/editcap.1"
    "/Users/miguel/Downloads/make/doc/mergecap.1"
    "/Users/miguel/Downloads/make/doc/randpkt.1"
    "/Users/miguel/Downloads/make/doc/randpktdump.1"
    "/Users/miguel/Downloads/make/doc/rawshark.1"
    "/Users/miguel/Downloads/make/doc/reordercap.1"
    "/Users/miguel/Downloads/make/doc/sshdump.1"
    "/Users/miguel/Downloads/make/doc/text2pcap.1"
    "/Users/miguel/Downloads/make/doc/tshark.1"
    "/Users/miguel/Downloads/make/doc/udpdump.1"
    "/Users/miguel/Downloads/make/doc/wireshark.1"
    "/Users/miguel/Downloads/make/doc/mmdbresolve.1"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/man/man4" TYPE FILE FILES
    "/Users/miguel/Downloads/make/doc/extcap.4"
    "/Users/miguel/Downloads/make/doc/wireshark-filter.4"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/doc/wireshark" TYPE FILE FILES
    "/Users/miguel/Downloads/make/doc/androiddump.html"
    "/Users/miguel/Downloads/make/doc/capinfos.html"
    "/Users/miguel/Downloads/make/doc/captype.html"
    "/Users/miguel/Downloads/make/doc/ciscodump.html"
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
    "/Users/miguel/Downloads/make/doc/udpdump.html"
    "/Users/miguel/Downloads/make/doc/wireshark-filter.html"
    "/Users/miguel/Downloads/make/doc/wireshark.html"
    "/Users/miguel/Downloads/make/doc/mmdbresolve.html"
    )
endif()

