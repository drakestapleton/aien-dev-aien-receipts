# Verifying an org audit stamp yourself

Every step below runs on your own machine against public data. You need `git`, Python 3.10+,
a C compiler (for the pinned `crumb` checker) and, for the signature, the GitHub CLI.

## 1. Install the pinned tools

```sh
git clone https://github.com/aien-dev/aien-receipts && cd aien-receipts
python3 audit/tools/install_tools.py /tmp/audit-tools
```

The installer downloads every binary listed in `audit/tools/tools.lock.json` and refuses any file whose
SHA-256 differs from the lock. Python tools (semgrep, zizmor) are pip-installed at exact versions into
`/tmp/audit-tools/venv`; the semgrep rules are checked out at the pinned commit; `crumb.c` is fetched
from `aien-architecture-mv` at the pinned commit and its SHA-256 compared before it is built.

## 2. Check that the stamp is well formed

```sh
python3 audit/tools/verify.py audit/stamps/<repo>/<sha>
```

This validates the schema, recomputes the SHA-256 of every check output and review report the stamp
cites, and recomputes the verdict ceiling: a stamp may never claim a better verdict than its own
contents allow (see `audit/tools/stamp.py`).

## 3. Re-run the deterministic checks (public repositories)

```sh
git init -q /tmp/src && git -C /tmp/src fetch -q https://github.com/aien-dev/<repo> <sha>
git -C /tmp/src worktree add -q --detach /tmp/wt <sha>
python3 audit/tools/verify.py audit/stamps/<repo>/<sha> --rerun /tmp/src --worktree /tmp/wt --tools /tmp/audit-tools
```

Exit codes: `0` every reproducible check output matched byte for byte; `1` a mismatch (named on
stderr); `2` NOT_RUN, because the checker source, the tool lock or a tool version differs from the one
the stamp recorded. `2` is not a pass. C11 (dependency advisories) queries the live OSV database, so it
is recorded with its date and is not compared.

## 4. Check the signature

```sh
gh attestation verify audit/stamps/<repo>/<sha>/stamp.json --repo aien-dev/aien-receipts \
  --signer-workflow aien-dev/aien-receipts/.github/workflows/audit-attest.yml
```

A valid attestation shows that the `audit-attest` workflow, on a GitHub-hosted runner, validated the
stamp and re-ran its checks before signing. It does not show that a model review was right or complete:
read the review reports in the stamp directory and their `files_covered`.

## 5. Is the stamp current?

`audit/status.json` is refreshed daily. `CURRENT` means the default-branch HEAD still equals the
stamped commit; `STALE` means HEAD has moved and the stamp describes an older tree; `UNKNOWN` means
HEAD could not be read; `NOT_CHECKABLE` marks private repositories; `SUPERSEDED` means a newer stamp
exists. You can check one yourself: `git ls-remote https://github.com/aien-dev/<repo> HEAD`.

## Private repositories

They appear only as `private-01` .. `private-11` with a salted SHA-256 commitment
(`sha256("<salt>:<name>")`). Their stamps carry `self_reported: true`: nobody outside can re-run
them, so step 3 does not apply, and the signature attests only that the stamp was well formed.
