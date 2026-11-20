idf_component_register(SRCS "presenter.cpp" INCLUDE_DIRS "include" REQUIRES guardian_core)
target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
