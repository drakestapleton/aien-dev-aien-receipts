# Verify one published bundle without the Spark

This lesson uses an unchanged, public `aien-architecture` bundle. It does not run
its gates, sign anything, or need a model, GPU, Spark login, or private key.
**The official verifier recipe below was reproduced on 2026-11-07** (Linux aarch64,
rustc 1.98.1, outputs quoted in step 2; see also `docs/receipt-index.md`, "Independent
replay"). The separate, narrower OpenSSL exercise was reproduced earlier; it is not a
substitute for `aien-test verify-bundle`.

**Choose a route:** for full bundle verification follow steps 1 and 2. For the
signature-only exercise without Cargo, follow step 1 and then jump directly to
step 3, skipping every step 2 block (including its tampered-bundle commands).
The shell uses `set -e`, so a missing Cargo command otherwise stops the recipe.

## What was built, and why

[ADR 0033, context and decisions 6/9/11](https://github.com/aien-dev/aien-architecture/blob/efbba982f5c095e3ae71c057b22faaafc11ed84d/docs/adr/0033-aien-verification-pipeline.md)
records the original problem: repeated hosted setup and tests that could not run
without Spark hardware, with no inbound path from GitHub to Spark. The chosen
mechanism publishes a signed bundle from the worker and lets an independent
consumer check it. This is the ADR's account, not a claim that this tutorial
reproduced that performance baseline. The ADR contains proposals as well as
implementation history; the pinned code below establishes what this lesson uses.

The bundle names the repository, exact commit, executor, checks and verdict. The
Ed25519 signature covers the upstream canonical JSON with only the top-level
`signature` member removed. Reading the key and required gate list from the base
ref prevents a candidate change from authorizing its own key or dropping its own
requirements. A signature authenticates a statement under a trusted key; it does
not prove that the tests are sufficient, their implementation is correct, or that
hardware has been independently re-tested. A hosted bridge check going green is
not the Spark verdict of record, `AIEN Verification (Spark)`.

Upstream implementation is AIEN's `aien-test` in `aien-sovereign-core` (copyright
Drake Stapleton / AIEN), using `ed25519-dalek` for strict signature verification,
`serde_json` for parsing and `sha2` for digests:

- [`signed_bytes`, `verify`, CLI and refusal tests](https://github.com/aien-dev/aien-sovereign-core/blob/c26f4d7ac3156088469b27462390f5b08ef4f436/tools/aien-test/src/bundle.rs):
  `verify` validates shape, trusted key, signature, repository, commit, executor
  fingerprint, required checks and derived verdict, in that order.
- [`evidence::canonical` and golden encoding tests](https://github.com/aien-dev/aien-sovereign-core/blob/c26f4d7ac3156088469b27462390f5b08ef4f436/tools/aien-test/src/evidence.rs).
- [Base workflow, including its verifier pin and trust-anchor extraction](https://github.com/aien-dev/aien-architecture/blob/efbba982f5c095e3ae71c057b22faaafc11ed84d/.github/workflows/aien-verification.yml).
- [Existing pipeline explanation](https://github.com/aien-dev/aien-architecture/blob/efbba982f5c095e3ae71c057b22faaafc11ed84d/docs/PIPELINE.md).

## 1. Fetch exact inputs (network required)

Use Bash on Linux, Git, Python 3, and standard `grep`, `paste`, `sha256sum` tools.
The official build additionally needs Cargo/Rust **1.98.1**, the pinned upstream
`rust-toolchain.toml` requirement, a native linker and the locked Cargo dependencies.
Obtain those through your normal trusted development setup; this lesson does not
install toolchains or download an executable. The optional signature exercise
needs OpenSSL 3 with Ed25519 support. No model weights or hardware setup is needed.

Run all blocks in the same Bash shell. These are public HTTPS clones, with no
credential required. Stop on a failed checkout or fingerprint check.

```bash
set -eu
work=$(mktemp -d)
cd "$work"
SHELF=adac8533c922b676bfb12fbc83b047f19e28c0b9
COMMIT=1a3594340c70969c245554b07062efd8ead8a026
BASE=efbba982f5c095e3ae71c057b22faaafc11ed84d
VERIFIER=c26f4d7ac3156088469b27462390f5b08ef4f436

git clone https://github.com/aien-dev/aien-receipts.git shelf
git -C shelf checkout --detach "$SHELF"
git clone https://github.com/aien-dev/aien-architecture.git source
git -C source checkout --detach "$COMMIT"
git clone https://github.com/aien-dev/aien-sovereign-core.git verifier
git -C verifier checkout --detach "$VERIFIER"

test "$(git -C source rev-parse HEAD^)" = "$BASE"
git -C source show "$BASE:.aien/verify.pub" > verify.pub
git -C source show "$BASE:.aien/always" > always
cp "shelf/aien-architecture/$COMMIT/bundle.json" bundle.json
printf '%s  bundle.json\n' \
  cac84aa17376d4349e13d16ba935e349a24db421eaf44cb2bb6be2be5263612a \
  | sha256sum -c -
required=$(grep -v '^#' always | grep -v '^$' | paste -sd, -)
printf '%s\n' "$required"
cat verify.pub
```

Expected output includes `bundle.json: OK`, then:

```text
CRUMB-VERIFY,ARCH-DOCTRINE,ARCH-QUALIFICATION-STATUS
01368e0b02dc1113ae7425ad6ab00fdf5aa7dd97e0690745918a52f051d5cf68
```

Here `BASE` is the tested commit's parent on the source history, not a moving
`main` and not the candidate's key. This is an explicitly pinned historical trust
snapshot; it does not establish current key authorization or recreate every
historical branch-protection setting. For a new candidate use its actual trusted
base anchors. The shelf pin fixes the published file bytes, independently of the
source commit pin. Never use a key supplied only inside a bundle as a trust anchor.

## 2. Build the existing verifier, then verify offline

The initial build may download locked dependencies. Review the pinned source and
its `Cargo.lock` as usual. `--locked` prevents silently updating dependency pins.
Once built, the verification and negative case below require no network. Build
from inside `verifier/` so Rust tooling selects its pinned `rust-toolchain.toml`.

```bash
(cd verifier && cargo build --locked --release -p aien-test)
AIEN_TEST="$work/verifier/target/release/aien-test"
"$AIEN_TEST" verify-bundle bundle.json \
  --repo github.com/aien-dev/aien-architecture --commit "$COMMIT" \
  --pubkey verify.pub --require "$required"
```

Observed on 2026-11-07 (Linux aarch64, rustc 1.98.1, aien-test built at the pin above
with `--locked`, binary sha256 `a35ea32f666567eb5cb9e0db3c76a19c07eb10f343d4c9be545cb393eedea9d7`),
exit 0:

```text
AIEN Verification: PASS (3 checks, 3 required, 0 from cache) bundle cac84aa17376d4349e13d16ba935e349a24db421eaf44cb2bb6be2be5263612a
```

The three declared checks are ARCH-DOCTRINE, ARCH-QUALIFICATION-STATUS and
CRUMB-VERIFY, all `run`, `EXACT`, required and PASS. These are signed declarations,
not new gate executions. Exit 1 means a verified FAIL verdict; exit 2 means NOT_RUN
(or usage/input error); exit 3 means REJECTED. Never interpret nonzero as PASS.

### Tamper refusal in a disposable copy

This mirrors upstream `t11_tampered_verdict_is_rejected`. It changes only a scratch
copy, preserves the existing signature, and never writes into `shelf/`.

```bash
python3 - <<'PY'
import json
from pathlib import Path
b = json.loads(Path('bundle.json').read_bytes())
b['checks'][0]['verdict'] = 'FAIL'
b['verdict'] = 'FAIL'
Path('tampered.json').write_text(json.dumps(b), encoding='utf-8')
PY
rc=0
"$AIEN_TEST" verify-bundle tampered.json \
  --repo github.com/aien-dev/aien-architecture --commit "$COMMIT" \
  --pubkey verify.pub --require "$required" || rc=$?
printf 'tampered exit=%s\n' "$rc"
test "$rc" -eq 3
```

Observed on 2026-11-07, with the same edit made by `jq -c '.checks[0].verdict="FAIL" |
.verdict="FAIL"'` instead of Python: `AIEN Verification: REJECTED BAD_SIGNATURE: signature
does not verify over the canonical bytes`, exit 3. A refusal is the
success condition for this negative test. Do not sign the edited file or replace
the published receipt. The ordinary unit suite passing would not establish that
this real-bundle recipe was reproduced.

## 3. Optional: an observed signature-only experiment

This small exercise works with the installed OpenSSL/Python tools when Cargo is
unavailable. It **does not implement a general JSON canonicalizer or bundle
verifier**, and must not be used as an admission gate. It checks only this exact
fixture's Ed25519 signature and one tampered byte sequence. It does not implement
`ed25519-dalek::verify_strict`'s full rejection behavior, schema validation,
required-gate checks, executor binding or verdict algebra.

The fixture is already compact, sorted canonical JSON. After enforcing its exact
file SHA-256, remove the known top-level signature member's byte span, retaining
all other bytes unchanged as prescribed by upstream `signed_bytes`. The fixed
DER prefix below is the Ed25519 SubjectPublicKeyInfo wrapper for the 32-byte public
key; the key comes from `verify.pub`, not from the signature block.

```bash
python3 - <<'PY'
import hashlib, json
from pathlib import Path
raw = Path('bundle.json').read_bytes()
assert hashlib.sha256(raw).hexdigest() == (
    'cac84aa17376d4349e13d16ba935e349a24db421eaf44cb2bb6be2be5263612a')
b = json.loads(raw)
key = Path('verify.pub').read_text().strip()
assert key == '01368e0b02dc1113ae7425ad6ab00fdf5aa7dd97e0690745918a52f051d5cf68'
assert b['signature']['pubkey'] == key
start = raw.index(b',"signature":')
end = raw.index(b',"started_utc":', start)
message = raw[:start] + raw[end:]
Path('message.bin').write_bytes(message)
Path('signature.bin').write_bytes(bytes.fromhex(b['signature']['sig']))
Path('public.der').write_bytes(bytes.fromhex('302a300506032b6570032100' + key))
assert b'"verdict":"PASS"' in message
Path('tampered-message.bin').write_bytes(
    message.replace(b'"verdict":"PASS"', b'"verdict":"FAIL"', 1))
PY
openssl pkeyutl -verify -pubin -keyform DER -inkey public.der \
  -rawin -in message.bin -sigfile signature.bin
rc=0
openssl pkeyutl -verify -pubin -keyform DER -inkey public.der \
  -rawin -in tampered-message.bin -sigfile signature.bin || rc=$?
printf 'tampered signature exit=%s\n' "$rc"
test "$rc" -eq 1
```

Observed with Python 3.12.14 and OpenSSL 3.5.7 on Linux: original signature
`Signature Verified Successfully`, exit 0; tampered message `Signature Verification
Failure`, exit 1 (OpenSSL also emits a provider error diagnostic). This establishes
signature verification for those fixed bytes only. The official verifier's PASS
and BAD_SIGNATURE outputs above were reproduced separately, on 2026-11-07.

## Review checklist

Record OS/tool versions, pins, commands, output and exit codes in the PR. Keep
fetch/hash checks, the OpenSSL exercise, the official verifier and actual Spark
gate execution separate. If Rust or dependencies are unavailable, report that
blocker and leave full reproduction outstanding. No workflows run in this data
repository; do not add one to manufacture a green check. Remove the temporary
workspace when finished, never published receipts.
