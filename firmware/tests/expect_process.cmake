# Run a host child and require BOTH its exit status and any requested output.
# PASS_REGULAR_EXPRESSION alone can override a normal nonzero child exit.
if(NOT DEFINED PROGRAM OR NOT DEFINED EXPECT_EXIT)
  message(FATAL_ERROR "PROGRAM and EXPECT_EXIT are required")
endif()
execute_process(COMMAND "${PROGRAM}" ${ARGS}
  RESULT_VARIABLE actual OUTPUT_VARIABLE output ERROR_VARIABLE errors)
if(NOT "${actual}" STREQUAL "${EXPECT_EXIT}")
  message(FATAL_ERROR "Expected exit ${EXPECT_EXIT}, got ${actual}\n${output}\n${errors}")
endif()
string(STRIP "${output}" output)
if(DEFINED OUTPUT_PATTERN AND NOT output MATCHES "${OUTPUT_PATTERN}")
  message(FATAL_ERROR "Output mismatch: ${OUTPUT_PATTERN}\n${output}\n${errors}")
endif()
message(STATUS "${output}")
