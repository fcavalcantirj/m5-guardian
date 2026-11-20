# Native, no-radio compile/link qualification only. Never automatically flashed.
cmake_minimum_required(VERSION 3.16)
set(GUARDIAN_LAYER "core" CACHE STRING "core or presenter")
if(NOT GUARDIAN_LAYER MATCHES "^(core|presenter)$")
  message(FATAL_ERROR "GUARDIAN_LAYER must be core or presenter")
endif()
get_filename_component(GUARDIAN_FIRMWARE "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
set(EXTRA_COMPONENT_DIRS "${GUARDIAN_FIRMWARE}/components/guardian_core")
if(GUARDIAN_LAYER STREQUAL "presenter")
  list(APPEND EXTRA_COMPONENT_DIRS "${GUARDIAN_FIRMWARE}/components/guardian_presenter")
endif()
set(COMPONENTS main)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
# IDF resolves requirements in a separate CMake process. Export the choice as
# a build property so that early dependency expansion sees the same layer.
idf_build_set_property(GUARDIAN_QUALIFICATION_LAYER "${GUARDIAN_LAYER}")
project(guardian_qualify_${GUARDIAN_LAYER})
