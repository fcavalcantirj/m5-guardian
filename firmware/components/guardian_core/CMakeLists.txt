idf_component_register(SRCS "core.cpp" "parser.cpp" "rating.cpp" "detectors.cpp" "advice.cpp" "threat.cpp" "threats.cpp" "datapath.cpp" "shapes.cpp" "ble.cpp" "guard_cycle.cpp" INCLUDE_DIRS "include")
target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
