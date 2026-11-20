> Historical review below. Superseded on 2026-11-14 by the
> [accepted L01/L02 live validation](L02-live-validation.md). The earlier blocked
> findings are preserved as history, not current equipment status.

# L01 supervisor review — 2026-11-14

Status: qualification reviewed and documentation corrected; **L01 remains
blocked and unaccepted**. G01–G08 host acceptance remains intact.

## What was checked

Reviewed the saved Pi/USB inspection, backup identity, installed-control
limitations and qualification record. Independently rehashed the 8 MiB backup,
Bruce and Aircrack source snapshots, and three local RF-lab sources. Local
sources also match their pinned Git objects; Bruce snapshots match the recorded
Git blob hashes. These checks confirm evidence consistency, not live reception
or installed Bruce command behavior. No new SSH session or device action was
needed for this review.

Corrected one scenario description: `BaselineDetector::maybe_report` compares
qualifying advertisement count with `change_threshold` (default two). Two
qualifying advertisements from one unapproved BSSID can reach the threshold;
the separately reported distinct-BSSID count can remain one. No code changed,
so no new library tests were needed.

## Smallest practical next step

Designate a spare receiver and the controlled AP/client. The inventoried generic
USB Wi-Fi dongle can be identified and qualified if available; its capabilities
are currently unknown. The Pi uplink must remain intact, and the attached
assistive device is excluded.

An owner-designated spare ESP32-S3 is another possible receiver. Espressif's
[pinned sniffer documentation](https://docs.espressif.com/projects/esp-idf/en/v5.4/esp32s3/api-guides/wifi.html#wi-fi-sniffer-mode)
supports receiving management frames through a driver callback. A native-IDF
bridge could forward bounded raw frames and acquisition metadata over USB to
Guardian running on the host. This is an engineering proposal: that bridge is
not built or qualified. Its FCS convention, timestamps/epochs, throughput,
drops and fixed-channel coverage would need measurement. This would be lab
instrumentation, not moving Guardian's business logic or UI onto a board before
host live validation. Backup and identify the designated board before any
separately authorized firmware replacement.

AntiHunter summaries cannot substitute for the raw frames needed to test the
actual Guardian parser and detectors. A raw bridge would solve only reception;
it would not qualify Bruce control or complete the scenario suite. Start with
passive baseline reception once the receiver is available, then qualify the
separate stimulus source. Installed firmware must support bounded operation and
an effective stop. The old synchronous ESP emitter does not process its serial
stop command during transmission.

The AP/client choice also needs exact identities, channel and restore control.
A phone hotspot can support some observations, but automated security-mode
changes may require a controllable spare router. Do not infer scope from nearby
captures or silently omit unsupported scenarios.

## Evidence and boundaries

Worker evidence: `$GUARDIAN_STORE/ralph/20261114-154815-299021-task-9/qualification/`.
Supervisor checks: `$GUARDIAN_STORE/evidence-raw/L01-review-20261114/verification.json`.

Ledger and Ralph receipts unchanged. No harness, RF, flashing, installation of
device software, job changes or new worker sessions. Retrying the same blocked
task without new equipment/control evidence will not resolve these blockers.
