# Receipt index and replay

Linear DRA-167. Status: proposed on branch `feat/dra-167-receipt-index` as a draft pull request.
It changes the layout of this repository, so under `AGENTS.md` ("Safety and approvals") it needs
explicit maintainer approval, and the ADR 0033 doctrine in `aien-architecture` changes first.
Neither has happened yet.

`index/receipt_index.json` lists receipts that may be cited as evidence. For each one it pins
where the bytes live, what they hash to, which correction applies and what verdict follows.
`tools/replay_receipt.py` rebuilds every entry from the pinned commits and refuses an entry
whose recomputed fields differ from the file.

## What an entry records

| Field | Meaning |
|---|---|
| `id`, `issue_or_gate` | Entry name (no `:`), and the issue or gate the receipt evidences. |
| `kind` | `signed-bundle` (this shelf) or `omega-qualification-receipt` (`aien-dev/omega-evidence`). |
| `shelf` | Repository, commit, path, SHA-256 and byte length of the receipt bytes at that commit. |
| `source` | The verified repository and commit. For Omega receipts also: the field that named the commit, whether it resolves upstream, and the result for every artifact digest (`match`, `mismatch`, `absent`, `commit-unresolved`, `not-recoverable (build output)`). |
| `trust_anchor` | Signed bundles: the first parent of the source commit, with its `.aien/verify.pub` and `.aien/always`. |
| `correction` | The adjacent `<basename>.correction.json` at the same shelf commit: path, SHA-256, id, `supersedes_historical_status_for_admission`, `qualification_claim`. `null` when none exists. |
| `historical_verdict`, `effective_verdict`, `effective_basis` | The status the receipt states, the verdict after the admission check, and which rule decided it. |
| `replay` | The command that replays the entry. |

## The admission check

Applied in this order. The first rule that decides wins.

1. **Bytes.** The file at `shelf.repository@shelf.commit:shelf.path` must hash to `shelf.sha256`.
   Otherwise the entry is REJECTED (`DIGEST_MISMATCH`).
2. **Correction.** If `<basename>.correction.json` exists next to the receipt at the same shelf
   commit, its `corrects` member must name this repository, path and SHA-256. Otherwise REJECTED
   (`CORRECTION_UNBOUND`). When it sets `supersedes_historical_status_for_admission`, its
   `qualification_claim` is the effective verdict. The receipt bytes are never changed.
3. **Signed bundles.** The key must equal `.aien/verify.pub` from the first parent of the source
   commit, never a key found only in the bundle. The Ed25519 signature must verify over the
   canonical bytes without `signature`. The repository and commit must match the shelf path,
   `executor.id` must be the SHA-256 of the key, every gate in `.aien/always` must be present and
   required, and the declared verdict must equal the computed one (FAIL if any required check
   failed; PASS if every required check ran or was cached with PASS; NOT_RUN otherwise). Any
   failure is REJECTED with the `aien-test` reason code. Otherwise the bundle verdict stands.
4. **Omega receipts without a superseding correction.** The named implementation commit
   (`qualified_implementation_commit`, else `git_commit`) must exist in the source repository,
   and every recoverable source artifact must hash to its recorded digest at that commit.
   Otherwise the effective verdict is `REFUSED_SOURCE_PROVENANCE`. `build/` outputs cannot be
   recovered and are not counted. The `receipt_commit` field is recorded but does not decide.
5. **Index drift.** Every field except `id`, `issue_or_gate` and `replay` is recomputed. Any
   difference from the index is REJECTED (`INDEX_DRIFT`). An index that forgets a correction
   added later fails here.

A historical `QUALIFIED / PASS` is therefore never admitted on its own text.

## Replaying

Needs network access to GitHub, Python 3, Git and OpenSSL 3. Each run uses a fresh temporary Git
cache unless `--cache DIR` is given.

```bash
python3 tools/replay_receipt.py replay spark-rsi@f72209e6     # one entry
python3 tools/replay_receipt.py replay --all                  # the whole index
python3 tools/replay_receipt.py replay spark-rsi@f72209e6 --bytes /tmp/copy.json   # control
```

The last line is the result, for example `REPLAY omega-evidence/M8: REFUSED_UNSUPPORTED_PROVENANCE rc=4`.

| Exit | Meaning |
|---|---|
| 0 | PASS |
| 1 | FAIL: an authenticated FAIL verdict |
| 2 | NOT_RUN: an input could not be reached, or a usage error |
| 3 | REJECTED: bytes, signature, binding, correction binding or index drift |
| 4 | REFUSED: by a shelf correction or by the source-provenance check |

`replay --all` exits 0 only when every entry reproduces exactly as indexed, whatever its verdict.
Never treat a nonzero exit of a single replay as a pass.

Keep negative controls outside this checkout. `--bytes` replays a local copy instead of the
fetched file, so a byte-corrupted copy must end in `REJECTED DIGEST_MISMATCH` with exit 3.

The offline tests build disposable repositories and serve them over `file://`:

```bash
python3 -m unittest discover -s tests -v
```

## Admitting a new receipt

Every later receipt goes through the same check. `admit` computes the entry from pinned commits
and prints it; it exits 3 instead when rule 1, 2 or 3 rejects the receipt.

```bash
python3 tools/replay_receipt.py admit --kind signed-bundle \
  --shelf aien-dev/aien-receipts@<shelf-commit>:<repo>/<sha>/bundle.json \
  --id <repo>@<short-sha> --issue-or-gate "<issue or gate>"
python3 tools/replay_receipt.py admit --kind omega-qualification-receipt \
  --shelf aien-dev/omega-evidence@<shelf-commit>:<receipt>.json --source-repo aien-dev/omega-mv \
  --id omega-evidence/<milestone> --issue-or-gate "<issue or gate>"
```

Append the printed object to `entries`, increase `index_version` when the schema changes, and run
`replay --all`. Never write an entry by hand: a hand-typed digest or verdict fails rule 5.

## Version 1 contents

Generated and replayed on the Spark on 2026-11-06 (`replay --all`: 16/16 entries reproduce).

| Entry | Effective verdict | Basis |
|---|---|---|
| `spark-rsi@68528eca` | FAIL | Signed bundle; RSI-TEST FAIL. DRA-167 source anchor. |
| `spark-rsi@f72209e6`, `aien-architecture@1a359434` | PASS | Signed bundles. |
| `omega-evidence/M4`, `M10`, `M11`, `M12`, `M13`, `M14`, `M15`, `M17` | PASS | Named commit resolves; source digests match. |
| `omega-evidence/M8`, `M9` | REFUSED_UNSUPPORTED_PROVENANCE | Shelf corrections recorded 2026-10-26. |
| `omega-evidence/M5` | REFUSED_SOURCE_PROVENANCE | `git_commit` does not exist in `aien-dev/omega-mv`. No shelf correction yet. |
| `omega-evidence/M6` | REFUSED_SOURCE_PROVENANCE | At the named commit, `src/omega_self_host.c` is absent and both AArch64 sources differ. No shelf correction yet. |
| `omega-evidence/M7` | REFUSED_SOURCE_PROVENANCE | At the named commit, `src/omega_verify.c` is absent and `src/omega_validate.c` differs. No shelf correction yet. |

Also recorded, not deciding:
- M12's `receipt_commit` does not resolve, as its non-superseding correction says.
- M14's `receipt_commit` does not resolve either, and no correction says so yet.
- M10, M11 and M13 carry the placeholder `pending-receipt-commit`.

`index.excluded` lists the omega-evidence receipts in other layouts, which are not yet covered.

## Limits

- **Not independent.** The author of the index and the author of the tool are the same agent. An
  independent replay needs a different operator, or `aien-test verify-bundle` for signed bundles
  as in `docs/verify-one-bundle.md`.
- **Not `aien-test`.** The signature check uses OpenSSL Ed25519, not `ed25519-dalek`
  `verify_strict`. The canonical encoder is a Python port of `evidence::canonical`
  (aien-sovereign-core@c26f4d7ac3156088469b27462390f5b08ef4f436); the tests use that file's
  golden cases.
- **Omega PASS is narrow.** Omega receipts carry no signature. PASS here means the pinned bytes,
  a resolving named commit and matching source digests. The binary and the run were not
  recovered, and nothing here is hardware qualification.
- **Signed PASS is narrow.** A valid signature authenticates the recorded statement, not the
  sufficiency of the tests behind it. All three bundles in version 1 ran on the `host` backend.
- **Host dependencies.** Observed on the Spark: Python 3.12.3, Git 2.43.0, OpenSSL 3.0.13.
  They fetch commits, compute SHA-256 and verify Ed25519. No Omega replacement exists; porting
  the check to seeded Omega is an open proposal, in line with `audit/tools`, which is also Python.
