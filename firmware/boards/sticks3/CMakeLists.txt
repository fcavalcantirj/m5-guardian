# M5Stack StickS3 (K150, ESP32-S3-PICO-1-N8R8) board project for M5 Guardian.
# Native ESP-IDF, no Arduino runtime. Shared portable components live in
# firmware/components; this directory only adds the board adapter (main/).
cmake_minimum_required(VERSION 3.16)
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../../components")
# G16B: the app version (esp_app_desc, STATUS app_version=, OTA manifest) comes
# from <build dir>/guardian_app_version.txt, written by tools/build.sh for every
# build; changing it re-runs the configure step. Without it: "dev-unversioned".
set(GUARDIAN_VERSION_FILE "${CMAKE_BINARY_DIR}/guardian_app_version.txt")
if(EXISTS "${GUARDIAN_VERSION_FILE}")
  file(STRINGS "${GUARDIAN_VERSION_FILE}" PROJECT_VER LIMIT_COUNT 1)
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${GUARDIAN_VERSION_FILE}")
else()
  set(PROJECT_VER "dev-unversioned")
endif()
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(guardian_sticks3)
