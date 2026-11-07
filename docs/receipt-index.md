# Receipt index and replay

Linear DRA-167. Status: merged. The index, tool and tests landed through aien-receipts#12
(merge `bda984fa92fecef3ad43375b5db402f794acd224`, 2026-11-06), after the ADR 0033 amendment
[below](#adr-0033-amendment) merged in `aien-architecture` through aien-architecture-mv#379
(merge `c9dd6f37b6b83fad5e45662ee6ab423a8b74551d`). Maintainer approval for the layout change
came from Queen, the Completion Hive coordinator, under Drake Stapleton's delegation of merge
judgment (DRA-162, 59767dce). One independent replay is recorded in
[Independent replay](#independent-replay-2026-11-07).

`index/receipt_index.json` lists receipts that may be cited as evidence. For each one it pins
where the bytes live, what they hash to, which correction applies and what verdict follows.
`tools/replay_receipt.py` rebuilds every entry from the pinned commits, checks the shelf HEAD
for a later correction, and refuses an entry whose recomputed fields differ from the file or
that carries a field the tool does not check.

## What an entry records

| Field | Meaning |
|---|---|
| `id` | Entry name (no `:`). |
| `issue_or_gate` | The issue or gate the receipt evidences: `value`, `basis` and `verified`. Derived from the receipt where it names one: for signed bundles the repository and the gate of every required check, for Omega receipts `milestone` and `contract_id`. A receipt that names neither carries operator text with `verified: false`, and replay prints it as UNVERIFIED. |
| `kind` | `signed-bundle` (this shelf) or `omega-qualification-receipt` (`aien-dev/omega-evidence`). |
| `shelf` | Repository, commit, path, SHA-256 and byte length of the receipt bytes at that commit. |
| `source` | The verified repository and commit. For Omega receipts also: the field that named the commit, whether it resolves upstream, and the result for every artifact digest (`match`, `mismatch`, `absent`, `commit-unresolved`, `not-recoverable (build output)`). |
| `trust_anchor` | Signed bundles: the first parent of the source commit, with its `.aien/verify.pub` and `.aien/always`. |
| `correction` | The adjacent `<basename>.correction.json` at the shelf commit, which must be byte-identical at the shelf HEAD: path, SHA-256, id, `supersedes_historical_status_for_admission`, `qualification_claim`. `null` when none exists at either. |
| `historical_verdict`, `effective_verdict`, `effective_basis` | The status the receipt states, the verdict after the admission check, and which rule decided it. |
| `replay` | The command that replays the entry: exactly `python3 tools/replay_receipt.py replay <id>`. |

Any other field, in an entry or at the top level of the index, is REJECTED (`UNKNOWN_FIELD`):
a claim the tool does not check cannot sit in the index. The descriptive top-level fields
(`issue`, `generated_by`, `independence`, `admission_check`, `precedence`, `exit_codes`, `scope`,
`excluded`, `generated_utc`) are known but not recomputed; see "Values taken on trust".

## The admission check

Applied in this order. The first rule that decides wins.

1. **Bytes.** The file at `shelf.repository@shelf.commit:shelf.path` must hash to `shelf.sha256`.
   Otherwise the entry is REJECTED (`DIGEST_MISMATCH`).
2. **Correction.** The adjacent `<basename>.correction.json` must be byte-identical at the shelf
   commit and at the current HEAD of the shelf repository; a correction added or changed after
   the indexed commit is REJECTED (`STALE_CORRECTION`) until the entry is re-admitted at the
   HEAD. If the correction exists, its `corrects` member must name this repository, path and
   SHA-256. Otherwise REJECTED (`CORRECTION_UNBOUND`). When it sets
   `supersedes_historical_status_for_admission`, its `qualification_claim` is the effective
   verdict. The receipt bytes are never changed. Signed bundles have no correction rule yet, so
   a `bundle.correction.json` is REJECTED (`CORRECTION_UNSUPPORTED`) rather than ignored. Each
   kind lives on one shelf (`signed-bundle` in this repository, `omega-qualification-receipt`
   in `aien-dev/omega-evidence`); any other shelf is REJECTED (`SHELF_REPOSITORY`).
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
5. **Index drift.** Every field except `id` and `replay` is recomputed, `issue_or_gate`
   included, and `replay` must be the exact command for the `id`. Any difference from the
   index is REJECTED (`INDEX_DRIFT`); an unknown field is REJECTED (`UNKNOWN_FIELD`). An index
   whose entry was edited to claim, say, "hardware qualified on GB10" fails here.

The shelf HEAD is printed on every replay but not stored, so a new publish on the shelf does not
change the index unless it touches a correction.

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
| 3 | REJECTED: bytes, signature, binding, correction binding, stale correction, unknown field or index drift |
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
and prints it; it exits 3 instead when rule 1, 2 or 3 rejects the receipt. Admit at the shelf
HEAD: an older commit fails rule 2 whenever a correction has landed since.

```bash
python3 tools/replay_receipt.py admit --kind signed-bundle \
  --shelf aien-dev/aien-receipts@<shelf-commit>:<repo>/<sha>/bundle.json --id <repo>@<short-sha>
python3 tools/replay_receipt.py admit --kind omega-qualification-receipt \
  --shelf aien-dev/omega-evidence@<shelf-commit>:<receipt>.json --source-repo aien-dev/omega-mv \
  --id omega-evidence/<milestone>
```

`--issue-or-gate "<text>"` is accepted only for a receipt that names no issue or gate; the text
is recorded with `verified: false`. For a receipt that names one, the option is a usage error
(exit 2).

Append the printed object to `entries`, increase `index_version` when the schema changes, and run
`replay --all`. Never write an entry by hand: a hand-typed digest, verdict or issue fails rule 5.

## Values taken on trust

The tool cannot recompute these from the pinned bytes. A reader relies on them as stated:

- **`source.repository` of an Omega receipt.** The receipts do not name their implementation
  repository, so it comes from the index (`--source-repo` at admission). The tool checks only
  that it is an `aien-dev/<name>` repository and that the named commit and artifact digests
  hold there. A wrong repository shows as `REFUSED_SOURCE_PROVENANCE`, but the index cannot
  prove that the receipt meant that repository.
- **The signed-bundle basis "this shelf has no correction records".** `effective_basis` of a
  signed bundle reads `authenticated bundle verdict (this shelf has no correction records)`.
  The tool checks the part it can see: no `bundle.correction.json` beside the bundle at the
  pinned commit or at the shelf HEAD. It cannot see corrections recorded anywhere else, such as
  issues, ADRs or `audit/` stamps.
- **Descriptive top-level fields** (`issue`, `generated_by`, `independence`, `precedence`,
  `exit_codes`, `scope`, `excluded`, `generated_utc`). They describe the index and are not
  recomputed; `precedence` and `exit_codes` restate this document.
- **An `issue_or_gate` marked `verified: false`.** Operator text. Version 2 has none.

## Version 2 contents

Version 1 was generated on 2026-11-06 by Receipts167. Version 2 was regenerated by `admit` at
the same pinned shelf commits; only `issue_or_gate` changed, every digest and verdict is
identical. Replayed on the Spark on 2026-11-06: `replay --all` 16/16 entries reproduce, and
every `issue_or_gate` is derived from its receipt.

| Entry | Effective verdict | Basis |
|---|---|---|
| `spark-rsi@68528eca` | FAIL | Signed bundle; RSI-TEST FAIL. DRA-167 source anchor (recorded here, not in the index). |
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

- **Tool replays are not independent.** The author of the index and the author of the tool are
  the same agent, so `replay` by that agent is not an independent review. The one independent
  replay so far, and its boundary, is in [Independent replay](#independent-replay-2026-11-07).
- **Not `aien-test`.** The signature check uses OpenSSL Ed25519, not `ed25519-dalek`
  `verify_strict`. The canonical encoder is a Python port of `evidence::canonical`
  (aien-sovereign-core@c26f4d7ac3156088469b27462390f5b08ef4f436); the tests use that file's
  golden cases.
- **Omega PASS is narrow.** Omega receipts carry no signature. PASS here means the pinned bytes,
  a resolving named commit and matching source digests. The binary and the run were not
  recovered, and nothing here is hardware qualification.
- **Signed PASS is narrow.** A valid signature authenticates the recorded statement, not the
  sufficiency of the tests behind it. All three bundles in version 2 ran on the `host` backend.
- **Host dependencies.** Observed on the Spark: Python 3.12.3, Git 2.43.0, OpenSSL 3.0.13.
  They fetch commits, compute SHA-256 and verify Ed25519. No Omega replacement exists; porting
  the check to seeded Omega is an open proposal, in line with `audit/tools`, which is also Python.

## Independent replay, 2026-11-07

Run by a different agent from the author of the index and of `tools/replay_receipt.py` (hive card
t_c85c314e; the index was written by Receipts167 and FixReceipts12). It does not use
`tools/replay_receipt.py`: shelf bytes come from `git show <shelf.commit>:<path>` and `sha256sum`,
trust anchors from the source repository, the signed bundle is checked by upstream
`aien-test verify-bundle` (aien-sovereign-core@c26f4d7ac3156088469b27462390f5b08ef4f436, built
with `cargo build --locked --offline --release -p aien-test`, rustc 1.98.1, binary sha256
`a35ea32f666567eb5cb9e0db3c76a19c07eb10f343d4c9be545cb393eedea9d7`), and the correction rule is
read with `jq`. Index read at this repository's `bda984fa`, file sha256
`f5613bac8b1061d20cab70047da838e57f0ffb03b8f45ff382e54f30cdc9e8c3`. Spark host, network sandboxed
off (`bwrap --unshare-net`) for every `aien-test` call.

| Check | Command (abridged) | Observed | Result |
|---|---|---|---|
| `aien-architecture@1a359434` bytes | `git show 09368f48:aien-architecture/1a35.../bundle.json \| sha256sum` | `cac84aa1...612a`, equal to `shelf.sha256` | PASS |
| its trust anchor | `git show efbba982:.aien/verify.pub`, `.aien/always` (first parent of `1a359434`) | key `01368e0b...cf68`, gates CRUMB-VERIFY, ARCH-DOCTRINE, ARCH-QUALIFICATION-STATUS | as indexed |
| its correction | `bundle.correction.json` at `09368f48` and at shelf HEAD `bda984fa` | none at either | as indexed |
| signature, binding, verdict | `aien-test verify-bundle bundle.json --repo github.com/aien-dev/aien-architecture --commit 1a35... --pubkey verify.pub --require <always>` | exit 0, `AIEN Verification: PASS (3 checks, 3 required, 0 from cache)` | PASS, equal to `effective_verdict` |
| control: verdict edited to FAIL | same, on a scratch copy | exit 3, `REJECTED BAD_SIGNATURE` | refused |
| control: wrong commit (last digit) | same, `--commit 1a35...a020` | exit 3, `REJECTED COMMIT_MISMATCH` | refused |
| control: wrong key | same, `--pubkey` of 32 zero bytes | exit 3, `REJECTED UNKNOWN_KEY` | refused |
| control: one appended byte | `sha256sum` of a scratch copy | `e123882e...0d1d`, not `shelf.sha256` | refused |
| `omega-evidence/M8` bytes | `git show 1da6a283:omega_program_core_qualification_receipt.json \| sha256sum` | `2e5febd9...e6bd`, equal; receipt text says `QUALIFIED / PASS` | PASS |
| its correction | `git show 1da6a283:<basename>.correction.json`, compared with omega-evidence HEAD | sha256 `668f1c94...4777` as indexed, byte-identical at HEAD `1da6a283`; `corrects` names this repository, path and sha256 | bound |
| correction precedence | `jq .disposition` | `supersedes_historical_status_for_admission: true`, claim `REFUSED_UNSUPPORTED_PROVENANCE` | effective verdict REFUSED_UNSUPPORTED_PROVENANCE, as indexed; the historical PASS is not admitted |
| control: one appended byte | `sha256sum` of a scratch copy | differs from `shelf.sha256` | refused |

The tool arm ran in the same session, for comparison only: `replay --all` exit 0, last line
`INDEX receipt_index.json v2: 16/16 entries reproduce as indexed rc=0`; `replay
aien-architecture@1a359434 --bytes <copy with one appended byte>` exit 3
`REJECTED DIGEST_MISMATCH`; `python3 -m unittest discover -s tests` 28 tests OK.

**Independence boundary.** Independent of the index's author and of its tool: different agent,
different signature implementation (`ed25519-dalek` in `aien-test`, not OpenSSL), digests and
the correction rule recomputed without the tool. Not independent of the operator: same Spark host
and same GitHub account as the author, and no independence of model is claimed. It covers two of
the sixteen entries (one signed bundle, one corrected Omega receipt); the other fourteen were
replayed only by the tool. It is not hardware qualification.

## ADR 0033 amendment

Landed in `docs/adr/0033-aien-verification-pipeline.md` of `aien-dev/aien-architecture` through
aien-architecture-mv#379 (merge `c9dd6f37b6b83fad5e45662ee6ab423a8b74551d`). The text as drafted
here against ad8d1eb, after the 2026-10-26 amendment and before "Not decided here":

> ## Amendment 2026-11-06 (receipt index on the receipts shelf)
>
> Approved for the maintainer by Queen, the Completion Hive coordinator, under Drake
> Stapleton's delegation of merge judgment (DRA-162, 59767dce), with aien-dev/aien-receipts#12
> (DRA-167). Nothing in Decisions 1 to 14 or in the earlier amendments changes, and published
> `<repo>/<sha>/bundle.json` files keep their bytes, layout and meaning.
>
> 1. **A receipt index on the same shelf.** `aien-dev/aien-receipts` gains `index/receipt_index.json`,
>    the replay tool `tools/replay_receipt.py`, its offline tests `tests/test_replay.py` and the
>    description `docs/receipt-index.md`. The index lists the receipts that may be cited:
>    signed bundles from this shelf and Omega qualification receipts from
>    `aien-dev/omega-evidence`, each with the pinned shelf commit, SHA-256, the correction that
>    applies and the effective verdict.
> 2. **Written only by the tool.** Entries are written only by `tools/replay_receipt.py admit`.
>    Replay recomputes every entry except its name and command, and rejects any difference, any
>    field it does not check, and any correction that differs between the indexed commit and the
>    shelf HEAD.
> 3. **Corrections outrank historical status.** A `.correction.json` that supersedes a receipt's
>    historical status decides the effective verdict; a historical `QUALIFIED / PASS` is never
>    admitted on its own text. Omega receipts without a superseding correction must also match
>    their named source commit.
> 4. **Bundles unchanged.** Signed bundles are checked as in Decision 6 (key from the source
>    commit's first parent, verdict algebra of Decision 7). The index does not re-sign or move
>    them, and a bundle correction file is refused until a rule for it is decided.
> 5. **Not a gate.** The index is a citation aid. It is not an input to `aien-test
>    verify-bundle`, the AIEN Alpha job or any merge gate, and a replay by the index's author is
>    not an independent review.
