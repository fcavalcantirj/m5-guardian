# G16C: the 16 upright 135x160 portraits (every rating, both ALERT pulses of each, the
# NoData silhouette), built by art/persona/v2/build_assets.py portraits. Each must be
# exactly persona::art_bytes (135x160 RGB565 = 43,200 B); fail the build otherwise.
set(GUARDIAN_PORTRAIT_NAMES VeryGood Good Medium Bad Horrible
    VeryGood_ALERT_p0 VeryGood_ALERT_p1 Good_ALERT_p0 Good_ALERT_p1 Medium_ALERT_p0 Medium_ALERT_p1
    Bad_ALERT_p0 Bad_ALERT_p1 Horrible_ALERT_p0 Horrible_ALERT_p1 NoData)
set(GUARDIAN_PORTRAIT_FILES "")
foreach(name ${GUARDIAN_PORTRAIT_NAMES})
  set(file "${CMAKE_CURRENT_LIST_DIR}/../../../art/persona/v2/portrait/${name}_portrait.rgb565")
  file(SIZE "${file}" bytes)
  if(NOT bytes EQUAL 43200)
    message(FATAL_ERROR "${file}: ${bytes} bytes, expected 43200 (135x160 RGB565)")
  endif()
  list(APPEND GUARDIAN_PORTRAIT_FILES "${file}")
endforeach()
# G21: the 3D head's frame sets (art/persona/v3/frames/<Mood>.bin + manifest.json, built by
# tools/face3d/pack_frames.py). Each mood's file that exists is embedded and announced to the code as
# GUARDIAN_HEAD3D_<Mood>; a mood without a file shows its 2D portrait. The manifest must list exactly
# the files that are there (pack_frames.py verify; build.sh's archive step checks the image itself).
set(GUARDIAN_HEAD3D_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../art/persona/v3/frames")
set(GUARDIAN_HEAD3D_FILES "")
set(GUARDIAN_HEAD3D_DEFS "")
foreach(mood VeryGood Good Medium Bad Horrible)
  # G16Q: the art bench image leaves the frame sets out; their room in the OTA slot goes to the bench frames.
  if(EXISTS "${GUARDIAN_HEAD3D_DIR}/${mood}.bin" AND NOT CONFIG_GUARDIAN_ART_BENCH)
    list(APPEND GUARDIAN_HEAD3D_FILES "${GUARDIAN_HEAD3D_DIR}/${mood}.bin")
    list(APPEND GUARDIAN_HEAD3D_DEFS "GUARDIAN_HEAD3D_${mood}=1")
  endif()
endforeach()
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${GUARDIAN_HEAD3D_DIR}/manifest.json")
# G16Q: the art bench's candidate frames (art/bench/<A..E>_<Mood>.rgb565 and ramp.rgb565, built and pinned by
# tools/art/candidates.py), embedded ONLY in the bench image (CONFIG_GUARDIAN_ART_BENCH, build.sh build-art-bench).
# Each must be exactly 135x240 RGB565 = 64,800 B; fail the build otherwise. (Source and embedded files may follow
# Kconfig, requirements may not: ESP-IDF v5.4 api-guides/build-system.rst.)
set(GUARDIAN_BENCH_FILES "")
if(CONFIG_GUARDIAN_ART_BENCH)
  set(GUARDIAN_BENCH_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../art/bench")
  set(GUARDIAN_BENCH_NAMES ramp)
  foreach(letter A B C D E)
    foreach(mood VeryGood Horrible Medium)
      list(APPEND GUARDIAN_BENCH_NAMES "${letter}_${mood}")
    endforeach()
  endforeach()
  foreach(name ${GUARDIAN_BENCH_NAMES})
    set(file "${GUARDIAN_BENCH_DIR}/${name}.rgb565")
    file(SIZE "${file}" bytes)
    if(NOT bytes EQUAL 64800)
      message(FATAL_ERROR "${file}: ${bytes} bytes, expected 64800 (135x240 RGB565)")
    endif()
    list(APPEND GUARDIAN_BENCH_FILES "${file}")
  endforeach()
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${GUARDIAN_BENCH_DIR}/manifest.json")
endif()
idf_component_register(
    SRCS "app_main.cpp" "sticks3_board.cpp" "measurement_main.cpp" "measurement_radio.cpp" "measurement_display.cpp" "nvs_blob.cpp"
         "imu_task.cpp"
         "../../../adapters/measurement/measurement.cpp"
         "../../../adapters/companion/companion.cpp" "../../../adapters/companion/screens.cpp" "../../../adapters/companion/persona.cpp"
         "../../../adapters/companion/motion.cpp" "../../../adapters/companion/shake.cpp" "../../../adapters/companion/burst.cpp"
         "../../../adapters/companion/inflate.cpp" "../../../adapters/companion/head3d.cpp"
         "../../../adapters/imu/bmi270.cpp" "../../../adapters/imu/bmi270_config.cpp"
         "../../../adapters/tune/tune.cpp" "../../../adapters/tune/threat_tune.cpp" "../../../adapters/tune/session.cpp" "tune_link.cpp"
         "../../../adapters/tune/offer_rsa.cpp"   # G22A: the offer signature check (mbedtls, the image check's library)
         "ota_board.cpp" "../../../adapters/ota/ota.cpp" "../../../adapters/power/battery.cpp" "../../../adapters/power/idle.cpp"
         # G16M: phone setup (SoftAP + one page + name service) and the encrypted credential vault
         "../../../adapters/setup/setup.cpp" "setup_board.cpp" "cred_vault.cpp"
         # G16H coexistence spike: ble_spike.cpp is empty unless CONFIG_GUARDIAN_BLE_SPIKE (build-ble-spike);
         # the portable spike recorder is unreferenced (dropped at link) in the normal image.
         "ble_spike.cpp" "../../../adapters/coex/coex_spike.cpp"
         # G16Q art bench: SDK-free catalogue/keys/drawing, unreferenced (dropped at link) unless CONFIG_GUARDIAN_ART_BENCH.
         "art_bench.cpp"
    # G16C: 16 x 43,200 B portraits (691,200 B), size-checked above and again at run time
    # G21: + the 3D head frame sets (raw-deflate frames, inflated one at a time into PSRAM)
    # G16Q: + the 16 bench frames in the art bench image only (which has no head frame sets)
    EMBED_FILES ${GUARDIAN_PORTRAIT_FILES} ${GUARDIAN_HEAD3D_FILES} ${GUARDIAN_BENCH_FILES}
    INCLUDE_DIRS "." "../../../adapters/measurement" "../../../adapters/companion" "../../../adapters/imu" "../../../adapters/tune"
                 "../../../adapters/ota" "../../../adapters/power" "../../../adapters/coex" "../../../adapters/setup"
                 "../../../../lab/receiver/main"
    PRIV_REQUIRES guardian_core guardian_presenter guardian_canvas
                  esp_lcd esp_driver_spi esp_driver_i2c esp_driver_gpio esp_driver_ledc
                  esp_app_format esp_wifi esp_event esp_driver_usb_serial_jtag esp_psram nvs_flash esp_partition spi_flash esp_timer
                  app_update esp_http_client esp_netif bootloader_support
                  esp_http_server lwip nvs_sec_provider efuse esp_hw_support   # G16M
                  mbedtls   # G22A: RSA-3072 PKCS#1 v1.5 + SHA-256 for the signed TUNE offer
                  bt)   # G16H: headers only unless the spike variant enables BT (requirements cannot follow Kconfig)
target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
if(GUARDIAN_HEAD3D_DEFS)
  target_compile_definitions(${COMPONENT_LIB} PRIVATE ${GUARDIAN_HEAD3D_DEFS})
endif()
# G16C rework: the per-frame render path is built with -O2 (the rest of the app
# keeps the project's -Og; IRAM is nearly full, so the global level stays). The
# canvas component gets the same in components/guardian_canvas/CMakeLists.txt.
set_source_files_properties(
    "../../../adapters/companion/screens.cpp" "../../../adapters/companion/persona.cpp"
    "../../../adapters/companion/motion.cpp" "../../../adapters/companion/companion.cpp"
    "../../../adapters/companion/shake.cpp" "../../../adapters/companion/burst.cpp"
    "../../../adapters/companion/inflate.cpp" "../../../adapters/companion/head3d.cpp"   # G21: the inflate is in the frame path
    "art_bench.cpp"   # G16Q: the bench's frame copy is a frame path too
    PROPERTIES COMPILE_OPTIONS "-O2")
