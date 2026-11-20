idf_build_get_property(GUARDIAN_LAYER GUARDIAN_QUALIFICATION_LAYER)
set(QUALIFY_REQUIRES guardian_core)
if(GUARDIAN_LAYER STREQUAL "presenter")
  list(APPEND QUALIFY_REQUIRES guardian_presenter)
endif()
idf_component_register(
  SRCS "entry.cpp" "../../tests/qualification/profile_checks.cpp"
  PRIV_REQUIRES ${QUALIFY_REQUIRES})
target_compile_features(${COMPONENT_LIB} PRIVATE cxx_std_17)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
if(GUARDIAN_LAYER STREQUAL "presenter")
  target_compile_definitions(${COMPONENT_LIB} PRIVATE GUARDIAN_QUALIFY_PRESENTER=1)
endif()
