set(Wireshark_MAJOR_VERSION 3)
set(Wireshark_MINOR_VERSION 4)
set(Wireshark_PATCH_VERSION 2)
set(Wireshark_VERSION "3.4.2")

set(Wireshark_PLUGINS_ENABLED 1)


####### Expanded from @PACKAGE_INIT@ by configure_package_config_file() #######
####### Any changes to this file will be overwritten by the next CMake run ####
####### The input file was WiresharkConfig.cmake.in                            ########

get_filename_component(PACKAGE_PREFIX_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../" ABSOLUTE)

macro(set_and_check _var _file)
  set(${_var} "${_file}")
  if(NOT EXISTS "${_file}")
    message(FATAL_ERROR "File or directory ${_file} referenced by variable ${_var} does not exist !")
  endif()
endmacro()

macro(check_required_components _NAME)
  foreach(comp ${${_NAME}_FIND_COMPONENTS})
    if(NOT ${_NAME}_${comp}_FOUND)
      if(${_NAME}_FIND_REQUIRED_${comp})
        set(${_NAME}_FOUND FALSE)
      endif()
    endif()
  endforeach()
endmacro()

####################################################################################

set_and_check(Wireshark_LIB_DIR            "${PACKAGE_PREFIX_DIR}/lib")
set_and_check(Wireshark_INCLUDE_DIR        "${PACKAGE_PREFIX_DIR}/include/wireshark")
if(Wireshark_PLUGINS_ENABLED)
    set_and_check(Wireshark_PLUGIN_INSTALL_DIR "${PACKAGE_PREFIX_DIR}/lib/wireshark/plugins/3-4")
endif()
set_and_check(Wireshark_EXTCAP_INSTALL_DIR "${PACKAGE_PREFIX_DIR}/lib/wireshark/extcap")

include("${CMAKE_CURRENT_LIST_DIR}/WiresharkTargets.cmake")

check_required_components(Wireshark)
