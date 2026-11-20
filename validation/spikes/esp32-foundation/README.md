# ESP32 foundation probe

A temporary on-chip execution check of the production portable library. No RF,
display or NVS is initialized. All input is explicitly Imported fixture bytes.
This does not satisfy on-board live-RF or product visual acceptance.

Back up the exact device first. Build with pinned ESP-IDF v5.4 and archive source,
sdkconfig, ELF/binaries, checksums and serial output in the store. Restore that device's
original full-flash image after the probe. Do not use another board's backup.
The supervising validation record owns actual results; this source alone proves
nothing. Build and flash are never automatic consequences of running Ralph.
