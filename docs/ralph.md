# Ralph: bounded implementation batches

`guardian-tasks.json` remains the acceptance ledger. Only the supervising
assistant sets `passes=true`, after inspecting, fixing and verifying the work.
Each worker session implements one selected task and runs its scoped host TDD.

After G01–G03 are accepted, **G04–G08 may run consecutively without a manual
review between each task**. Their implementation receipts permit dependent work
inside this batch. They remain unaccepted until the assistant reviews the batch.

```sh
./ralph-claude.sh 1              # One fresh worker session
./ralph-claude.sh 5              # Up to five sessions; G04–G08 after G03 acceptance
./ralph-codex.sh 5               # Same batching rules, configured Codex
./ralph.sh --status              # Acceptance, pending review, last run
./ralph.sh --dry-run             # Next implementation or blocking review boundary
./ralph-claude.sh 5 --retry      # Explicit retry after inspecting a failure
./ralph-continuous.sh claude 5   # Up to five sessions, waiting at review boundaries
```

The count is a strict maximum in every mode. `--continuous` waits at review
boundaries; it never means unlimited sessions. At a count of five starting G04,
the runner finishes G08 and exits. It never flows automatically into L01 or any
later phase. Starting again resumes the next not-yet-handed-off host task; it
neither marks prior tasks passed nor silently repeats the whole batch.

G03 remains a reviewed foundation prerequisite. Outside G04–G08, each task still
needs its dependencies accepted and any earlier batch reviewed. A fresh explicit
invocation is required to enter a later phase after a batch. Nothing here starts
RF interference, flashes hardware, bypasses model permissions or accepts work.

## Handoff and failure behavior

The worker must finish its output with exactly `READY FOR REVIEW` or `BLOCKED`
on a plain-text line. A zero CLI exit without READY is an incomplete handoff;
BLOCKED, engine failure, interruption or ledger mutation stops the batch.
This completion signal is not a test result or independent approval.

the store holds `handoffs.json`, `state.json`, per-attempt `result.json`, prompts,
engine logs, and the append-only progress journal. Receipts carry task-content
hashes and dependency attempt identities. Changed task definitions cannot reuse
old handoffs. Retrying an upstream host task invalidates downstream handoffs
through their recorded inputs; they must be implemented again before advancing.
Acceptance is still reviewer-owned, including the impact of reviewer code fixes.

`--retry` targets the last failed/interrupted unaccepted task; otherwise it
reworks the earliest unaccepted task. It cannot bypass the foundation or phase
review boundary. It starts no automatic retry loop. Legacy receipts remain
readable; a legacy handoff without dependency inputs requires review or explicit
retry, rather than being silently treated as a batch receipt.

the store must be mounted and writable. `RALPH_DATA_ROOT` is an explicit destination
override, never an automatic fallback. Claude uses normal `claude`, defaults to
`claude-fable-5-1` / high, and never uses `claude-work-profile`. Codex uses its configured
model unless `CODEX_MODEL` / `CODEX_EFFORT` override it. No model/account fallback.

No automatic acceptance/verifier, nested agent loop, commit, push, deployment,
Telegram message, RF activity or flashing is added. Library workers run focused
TDD; independent validation and fixes remain the supervising assistant's work.
The owner explicitly launches any qualified live harness later.

The shared prompt is `tools/prompts/guardian-worker.md`. The complete selected
entry remains visible to each worker. Batching changes scheduling, not the
product's defensive scope or an external provider's safeguards.

Execution style adapted from
[sticks3-ai-usage](https://github.com/fcavalcantirj/sticks3-ai-usage/tree/f2e03c2aad5014d2797776b1a2c7acaef263f3bb).
See [source license](ralph-source-LICENSE.txt).
