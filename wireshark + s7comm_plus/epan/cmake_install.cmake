# Install script for directory: /Users/miguel/Downloads/wireshark-3.4.2/epan

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
    "/Users/miguel/Downloads/make/run/libwireshark.14.0.2.dylib"
    "/Users/miguel/Downloads/make/run/libwireshark.14.dylib"
    )
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwireshark.14.0.2.dylib"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwireshark.14.dylib"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      execute_process(COMMAND /usr/bin/install_name_tool
        -delete_rpath "/usr/local/opt/gettext/lib"
        "${file}")
      execute_process(COMMAND /usr/bin/install_name_tool
        -delete_rpath "/Users/miguel/Downloads/make/run"
        "${file}")
      if(CMAKE_INSTALL_DO_STRIP)
        execute_process(COMMAND "/Library/Developer/CommandLineTools/usr/bin/strip" -x "${file}")
      endif()
    endif()
  endforeach()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES "/Users/miguel/Downloads/make/run/libwireshark.dylib")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwireshark.dylib" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwireshark.dylib")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/usr/local/opt/gettext/lib"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwireshark.dylib")
    execute_process(COMMAND /usr/bin/install_name_tool
      -delete_rpath "/Users/miguel/Downloads/make/run"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwireshark.dylib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/Library/Developer/CommandLineTools/usr/bin/strip" -x "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libwireshark.dylib")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/wireshark/epan" TYPE FILE FILES
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/addr_and_mask.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/addr_resolv.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/address.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/address_types.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/afn.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/aftypes.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/app_mem_usage.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/arcnet_pids.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/arptypes.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/asn1.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/ax25_pids.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/bridged_pids.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/capture_dissectors.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/charsets.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/chdlctypes.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/cisco_pid.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/color_filters.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/column.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/column-info.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/column-utils.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/conversation.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/conversation_debug.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/conversation_table.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/conv_id.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/crc10-tvb.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/crc16-tvb.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/crc32-tvb.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/crc6-tvb.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/crc8-tvb.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/decode_as.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/diam_dict.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/disabled_protos.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/conversation_filter.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/dtd_parse.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/dvb_chartbl.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/eap.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/eapol_keydes_types.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/epan.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/epan_dissect.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/etypes.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/ex-opt.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/except.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/exceptions.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/expert.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/export_object.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/exported_pdu.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/filter_expressions.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/follow.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/frame_data.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/frame_data_sequence.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/funnel.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/garrayfix.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/golay.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/guid-utils.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/iana_charsets.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/iax2_codec_type.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/in_cksum.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/ip_opts.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/ipproto.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/ipv4.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/ipv6.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/lapd_sapi.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/llcsaps.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/maxmind_db.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/media_params.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/next_tvb.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/nlpid.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/oids.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/osi-utils.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/oui.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/packet.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/packet_info.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/params.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/plugin_if.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/ppptypes.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/print.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/print_stream.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/prefs.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/prefs-int.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/proto.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/proto_data.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/ps.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/ptvcursor.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/range.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/reassemble.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/reedsolomon.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/register.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/req_resp_hdrs.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/rtd_table.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/rtp_pt.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/sctpppids.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/secrets.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/show_exception.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/slow_protocol_subtypes.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/sminmpec.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/srt_table.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/stat_tap_ui.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/stat_groups.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/stats_tree.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/stats_tree_priv.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/stream.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/strutil.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/t35.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/tap.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/tap-voip.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/timestamp.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/timestats.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/tfs.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/time_fmt.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/to_str.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/tvbparse.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/tvbuff.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/tvbuff-int.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/uat.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/uat-int.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/unit_strings.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/value_string.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/x264_prt_id.h"
    "/Users/miguel/Downloads/wireshark-3.4.2/epan/xdlc.h"
    )
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/Users/miguel/Downloads/make/epan/crypt/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/epan/dfilter/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/epan/dissectors/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/epan/ftypes/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/epan/wmem/cmake_install.cmake")
  include("/Users/miguel/Downloads/make/epan/wslua/cmake_install.cmake")

endif()

