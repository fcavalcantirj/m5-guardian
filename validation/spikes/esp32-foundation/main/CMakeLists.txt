idf_component_register(SRCS "probe.cpp" INCLUDE_DIRS "." PRIV_REQUIRES guardian_core guardian_presenter esp_timer esp_psram)
target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)
