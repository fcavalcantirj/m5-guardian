# Guardian task 1: supervising review

Decision: retain the implementation as a board feasibility spike. Do not mark task 1 passed. No firmware was flashed and no test suite or fresh build was run during this review.

## Confirmed from saved artifacts

- The ESP-IDF build log ends in a successful 315,168-byte app image. This verifies a recorded build, not device operation.
- SHA-256 matches the saved manifest for bootloader, partition table, app image and ELF.
- The full-flash backup is 8,388,608 bytes and matches its checksum sidecar. This does not establish that restoration works.
- Ralph's receipt is awaiting_review, exit code 0. Exit code 0 is not task acceptance.
- The board project links portable core/presenter/canvas components; board SDK imports stay in the board adapter in the reviewed changes.

## Findings before hardware acceptance

1. Framebuffer ownership: sticks3_board.cpp:269 queues the single mutable buffer; app_main.cpp:121 ignores the submission result and the next draw rewrites it after a fixed delay. The pinned ESP-IDF esp_lcd_panel_io.h explicitly requires recycling color buffers after on_color_trans_done. Add a completion handshake (or managed buffers). A 40 ms delay is not an ownership guarantee. No actual tearing was observed because this image has not been booted.
2. Error reporting: sticks3_board.cpp:60 discards PM1 setup success. app_main.cpp repeatedly reports initial display setup as display=ok regardless of subsequent submissions. Track power setup, panel setup and transfer status separately. A successful SPI setup does not prove visible pixels. NVS writes and commit also need checked results before persistence is claimed.
3. Artifact archive: build.sh:57-60 suppresses copy failures. Required outputs should be copied explicitly and missing outputs should fail the archive step. Preserved flasher paths must work from the archived layout rather than depending on disposable scratch paths.
4. The host target still references missing firmware/tests/contracts.cpp. The successful ESP-IDF build is not proof of a working host validation lane. This was pre-existing and remains a foundation task.
5. Storage policy differs: build.sh places its scratch build on the Mac despite the repository's the store-only build instruction. The filesystem rationale is documented, but it is an explicit exception to reconcile, not the store-only operation.

## Architecture and next work

Preserve this board spike. Put portable contracts and reuse decisions before detector implementation, then validate the portable implementation, then integrate live radio and the board renderer. Reserve full on-device acceptance for after these dependencies. No radio adapter exists in this app; it cannot yet measure Wi-Fi health.

The current runner selects the first false ledger entry and identifies its handoff by index plus content hash. Do not reorder the ledger while its continuous supervisor waits: it will reject the changed task identity. Stop that waiting supervisor before an intentional ledger migration. Do not set task 1 true merely to advance.

Hardware acceptance remains pending: verified boot log, visible display, button behavior, actual power/RAM operation and evidence of no-SD operation. The flash restoration route is documented but untested.
