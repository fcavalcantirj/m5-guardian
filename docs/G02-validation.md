# G02 supervising review — 2026-11-13

Acceptance: G02 source/reuse decisions accepted with the corrections in this
package. The guarded installer applies those corrections and sets only G02's
`passes` flag. This is not Guardian parser, detector, firmware or RF acceptance.

## Evidence inspected and reproduced

- Verified all worker-manifest audited sources/licenses against both SHA-256 and
  the pinned git object's bytes, not just HEAD. Original/prepared AntiHunter and
  SDK commits match the stated revisions. The worker ledger snapshot is unchanged.
- Added specific M5 display/power/build file hashes; each matches its pinned git
  object and the installed PlatformIO copy. A source subset match is not a
  whole-tree comparison or proof of native linkage.
- Reran the four direct RSN cases and the IE-walk case with ASan/UBSan on this Mac.
  Captured entire stdout/stderr without `head`, and actual process return codes.
  `short` and `nocaps`: ASan heap-buffer-overflow, exit -6. `count256`: success
  with zero pairwise/AKM count. `seven`: success with six pairwise/zero AKM.
  Later zero-length IE: success but WEP retained and WPA2 omitted.
- Added controls: the complete common RSN sample and an initial empty SSID both
  report WPA2, one AKM, WEP cleared. Thus the iterator defect is about advancing
  to a later empty IE, not every initial empty SSID. These are limited libwifi
  observations, not a format conformance certificate.
- Checked SDK count/default/unknown/trailing-byte branches, private include paths,
  AntiHunter retry filtering/callback dependencies and M5 source provenance.
- Verified the AntiHunter saved patch equals the diff from upstream `c891485` to
  prepared `e7646f5`; it is a delta requiring that base, not a complete archive.

Evidence destination:
`$GUARDIAN_STORE/evidence-raw/G02-review-20261113/`

The supervising session cannot write the project or the store. Commands ran using
explicit temporary reviewer staging at `/private/tmp/guardian-G02-review-20261113`.
The installer copies logs, command records and hash manifests to the destination
above before accepting G02. Original worker evidence is preserved. Disposable
host executables remain in staging; no firmware was built or flashed.

## Corrections

1. libwifi has separate `wpa_info` and `rsn_info`. Removed the contrary claim.
2. A known-buggy parser is not a sole oracle even for “valid” inputs. G04 can use
   individually vetted libwifi comparisons alongside independently established
   expectations, while Guardian's malformed/optional/unknown cases use its own
   contracts. No requirement to reproduce libwifi bugs.
3. Corrected two silent-success cases versus two ASan failures, the malformed
   count256 description, initial versus later empty IE, and truncated worker logs.
4. Documented SDK trailing-byte leniency and narrowed native-build compatibility
   to source evidence. No SDK/parser runtime validation is claimed.
5. Rejected blanket Retry-bit drops and source-MAC attribution as Guardian policy;
   frame filtering must be represented in coverage. A 24-byte requirement applies
   to management-header parsing, not all 802.11 traffic.
6. Added `THIRD_PARTY_NOTICES.md` with the full M5Stack MIT notice and references
   in the existing board/pin files. These are comment-only code edits; behavior
   remains the unvalidated retained spike. Removed blanket license conclusions.
7. Retained Wi-Fi Guardian/PocketLab links and clarified their reference-only role.

## Independent Claude ledger review is separate

The normal Fable 5.1/high attempt in
`reviews/20261113-233521-710039-ledger-independent` returned `stop_reason=refusal`
and `is_error=true`. The requested model was identified; no ledger review was
completed. This is neither a failed Guardian test nor independent approval.

The reporting helper now separates provider refusal from model verification,
records failure state, and supports `--report EVIDENCE_DIR` with no provider call.
Verified using the saved refusal and five offline response cases (including a
refusal with no error flag). No prompt concealment, automatic retry, model/account
fallback or fresh Claude request. These checks are reviewer-side inspection,
not a Ralph auto-verifier or a Guardian library TDD claim.

## Next gate

G03 builds/links the portable host harness and repairs the missing contracts test
target. G04–G08 implement behavior with scoped host TDD. L01/L02 must establish
actual host live RF evidence before new board integration. No later task passes
as part of this review; the independent ledger review remains incomplete.
