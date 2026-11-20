# Portability contract check (G03): the portable components may include only an
# allow-listed set of freestanding-friendly standard headers and guardian/ headers.
# No Arduino, ESP-IDF, FreeRTOS, M5Stack, graphics, filesystem, network or clock
# headers may appear (docs/contracts.md section 1). Run by ctest as
#   cmake -DROOT=<firmware dir> -P tests/portability_check.cmake
# It greps source text; it is a contract guard, not a substitute for the host link.
if(NOT DEFINED ROOT)
  message(FATAL_ERROR "portability_check: -DROOT=<firmware dir> required")
endif()

set(ALLOWED_STD
  "<array>" "<algorithm>" "<cstddef>" "<cstdint>" "<cstring>" "<limits>" "<climits>"
  "<type_traits>" "<utility>")

file(GLOB_RECURSE SOURCES
  "${ROOT}/components/guardian_core/*.cpp" "${ROOT}/components/guardian_core/*.hpp"
  "${ROOT}/components/guardian_presenter/*.cpp" "${ROOT}/components/guardian_presenter/*.hpp"
  "${ROOT}/components/guardian_canvas/*.cpp" "${ROOT}/components/guardian_canvas/*.hpp")

set(BAD 0)
set(CHECKED 0)
foreach(src ${SOURCES})
  get_filename_component(fname "${src}" NAME)
  if(fname MATCHES "^\\._")
    continue() # macOS AppleDouble shadow files on SMB checkouts
  endif()
  math(EXPR CHECKED "${CHECKED} + 1")
  file(STRINGS "${src}" INCLUDES REGEX "^[ \t]*#[ \t]*include")
  foreach(line ${INCLUDES})
    string(REGEX MATCH "[<\"][^>\"]+[>\"]" target "${line}")
    if(target MATCHES "^\"guardian/[A-Za-z0-9_]+\\.hpp\"$")
      continue()
    endif()
    list(FIND ALLOWED_STD "${target}" idx)
    if(idx EQUAL -1)
      message(SEND_ERROR "portability: ${src}: forbidden include ${target}")
      set(BAD 1)
    endif()
  endforeach()
  # Belt and braces: SDK identifiers must not appear even behind macros.
  file(STRINGS "${src}" SDK_LINES REGEX "(esp_|freertos|Arduino\\.h|M5Unified|M5GFX|lgfx|LovyanGFX|sdkconfig|nvs_flash|xQueue|vTaskDelay)")
  foreach(line ${SDK_LINES})
    if(NOT line MATCHES "^[ \t]*//")
      message(SEND_ERROR "portability: ${src}: SDK reference outside a comment: ${line}")
      set(BAD 1)
    endif()
  endforeach()
endforeach()

if(CHECKED LESS 12)
  message(FATAL_ERROR "portability: only ${CHECKED} files checked; expected the 12+ portable sources (glob broken?)")
endif()
if(BAD)
  message(FATAL_ERROR "portability: forbidden includes found")
endif()
message(STATUS "portability: ${CHECKED} portable sources, includes limited to guardian/ and ${ALLOWED_STD}")
