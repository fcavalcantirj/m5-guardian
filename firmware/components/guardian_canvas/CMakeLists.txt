idf_component_register(SRCS "canvas.cpp" "font5x7.cpp" INCLUDE_DIRS "include")
target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
# G16C rework: per-pixel drawing runs every animated frame; -O2 here only.
target_compile_options(${COMPONENT_LIB} PRIVATE -O2)
