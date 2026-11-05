# ACVP sample-vector proof pack for Omega's TLS 1.3 library (om/tls)

**What this is:** the om/tls library was tested against the CAVP/ACVP test methods with NIST's published vectors. It is **not NIST-validated.** These are self-run sample vectors from NIST's public ACVP-Server repository. They are **not a CAVP certificate**. A CAVP certificate (an "A-number") is issued only when an accredited laboratory submits through NIST's ACVP production server. Nothing here is "FIPS validated" or "FIPS certified". The ACVP-Server sample files hold both the prompts and NIST's expected answers. This pack answers the prompts with the library, then compares the answers field by field with NIST's expectedResults.json.

Labels: MEASURED = observed in the cited artifact in this directory. NOT_RUN = not executed. No figure here is MODELED. All figures are integer counts or hashes, so Wolfram was not used.

## Pins
- Library: aien-dev/omega-mv branch `audit/tls-outside-review` at `2d613b2d2f4650ae9b5a693b3fb4caffab0dea20` (draft PR #833). The remote branch has since moved to `c4bf4150b7f1111580cd714b12d020894425ff48`, which was **not** tested here.
- Compiler: `seed/out/omc` sha256 `2c82480596bbdc50cda9626866209ef662d5834f278f839ff4ce0250c495029f`, MEASURED (`sha256sum`).
- Vectors: usnistgov/ACVP-Server `975de31eb83d87039ec88934fdc47d8c312b892d`, `gen-val/json-files`. Every file used (47) is pinned by sha256 in `code/acvp-inputs.sha256`. run.sh refuses to run when any file differs.
- ML-KEM sources (TlsSuites): an uncommitted working-tree snapshot of `/home/drakestapleton/workspace/tlsverify-TlsSuites/om/tls/` taken on 2026-10-26, since `audit/tls-suites` was not pushed:
  - `sha3.om` 328f86e4f4f1e69faef8399dec704398583c830eedb7ea02d8e77afd1e13c56d
  - `mlkem.om` 04297d84e5d9c7d24a0b29aa1c1a4a57836780f894838ed9f3740fdba720890c

  Copies are in `mlkem-snap/`. Re-pin when TlsSuites commits.
- HMAC_DRBG (TlsProof.FipsModule): uncommitted files in `/tmp/tlsproof/fipsmodule/src` (branch `audit/tls-fipsmodule`, base 2d613b2d):
  - `om/tls/drbg.om` 3d5f866a6d1b55cb350d28a5927132031cae819f59dbeb3d53cddaa6e94db0e5
  - `test/drbg/run.sh` 69273d04ef47479fc7efe00cff3e7f09a6a799ff9beb48ebde7fd5f8d74d990f
  - `driver.om` 40344b00ad00c7d566678fc0aa4dff9ea4f4bedd84286a7582f6e07ebe666767
  - `convert.py` de18a5213ca7647db2b7983fb5f9ab99238cc8ab30e5b52ef784ee5f104f12eb
  - `vectors/acvp.txt` a9589fc54a20b96d4da0012ec7e84242c686424d247e771b10ab0591cbc8b607
  - `vectors/cavp.txt` 472e4864f23806094851db9b81af6f6c3faeaa8401c49bd14705417fce844dad

  run.sh checks that acvp.txt names the same ACVP-Server commit and the sha256 of both hmacDRBG internalProjection.json files.
- Host: Linux 7.0.0-1019-nvidia aarch64 (DGX Spark), dash as /bin/sh, Python 3.12.3, git 2.43.0, GNU coreutils sha256sum 0.8.0. No GPU was used.

## Rerun
```
git clone --branch audit/tls-outside-review https://github.com/aien-dev/omega-mv.git src && cd src
git checkout 2d613b2d2f4650ae9b5a693b3fb4caffab0dea20
# copy code/* to om/tls/test/acvp/ (the integration PR will carry them)
MLKEM_SRC=<dir with sha3.om mlkem.om> ACVP_DRBG_ROOT=<tree with om/tls/test/drbg> sh om/tls/test/acvp/run.sh seed/out/omc
```
Without `ACVP_DIR`, run.sh fetches the pinned ACVP-Server commit into `build/tls/acvp/acvp-server`. The fetch is a sparse checkout of the 47 files. Without `MLKEM_SRC` / `ACVP_DRBG_ROOT`, and with no such files in the tree, those lines print NOT_RUN and the final line is `ACVP PARTIAL ... not_run=...` with exit 3. NOT_RUN never counts as PASS.

## How it works
- `acvp2om.py` converts NIST's prompt.json to one-line records. It is a converter only, with no cryptography in it. It writes `FOLDER.map.json`, which maps each record to its (tgId, tcId) and lists every test it does not run with a reason. It asserts that every prompt test is either a record or listed.
- `acvp.om` (with `acvpio.om` and `acvpmain.om`, composed after the library by `om/tls/build.sh`) computes every answer with the library's own functions. `mlkemacvp.om` does the same for ML-KEM. The driver computes but does not grade. Three exceptions decide pass/fail inside .om, using the library's own decision:
  - KDA VAL, where the IUT must judge a supplied DKM;
  - AES-GCM decrypt, where the library's tag check decides;
  - the ML-KEM key checks, where the library's FIPS 203 §7.2/§7.3 input checks decide.
- `om2acvp.py` turns the outputs into an ACVP response JSON (`responses/FOLDER.response.json`) in the ACVP response format. A non-zero library return code where a value is expected becomes an `error` entry, which counts as a failure.
- `acvpcmp.py` compares the response with expectedResults.json. It checks vsId, algorithm and revision. Hex is compared case-insensitively. It fails on any missing, extra or unequal answer, and when nothing was compared.
- **Negative controls, MEASURED in `logs/run.log`:**
  - Each folder that ran is compared a second time with `--flip`. That corrupts one result value of NIST's expected answer in memory, and the comparison must then FAIL. 20 of 20 printed `negative control FAIL as required`. The TLS native subset has the same control, and run.sh fails if it does not fail.
  - The driver must refuse a malformed record (`H 1 256 abc` → `1 BAD`, exit 1).
  - Input manifest (MEASURED, `logs/neg-manifest.log`): a copy of the vector tree with one byte of `ACVP-AES-GCM-1.0/expectedResults.json` overwritten was refused before anything ran (`ACVP FAIL inputs differ from acvp-inputs.sha256`, exit 1).
  - NOT_RUN path (MEASURED, `logs/neg-partial-notrun.log`): without `MLKEM_SRC` and `ACVP_DRBG_ROOT`, run.sh printed both NOT_RUN lines and `ACVP PARTIAL algos=18 tests=7543 not_applicable=7139 not_run=ML-KEM,hmacDRBG` with exit 3, not PASS.
  - Pinned fetch (MEASURED, `logs/run-pinned-fetch.log`): with `ACVP_DIR` unset, run.sh fetched ACVP-Server 975de31e itself, all 47 files matched, and the final line was identical: `ACVP PASS algos=21 tests=7623 not_applicable=7299 not_run=NONE`.

## Results (MEASURED, `logs/run.log`, run 2026-10-26, wall time 113.6 s from `/usr/bin/time`)
```
ACVP SHA2-256-1.0 PASS tests=517 not_applicable=0
ACVP SHA2-384-1.0 PASS tests=137 not_applicable=892
ACVP SHA2-512-1.0 PASS tests=1029 not_applicable=0
ACVP HMAC-SHA2-256-1.0 PASS tests=975 not_applicable=0
ACVP HMAC-SHA2-384-1.0 PASS tests=975 not_applicable=0
ACVP HMAC-SHA2-512-1.0 PASS tests=975 not_applicable=0
ACVP HMAC-SHA2-256-2.0 PASS tests=150 not_applicable=0
ACVP HMAC-SHA2-384-2.0 PASS tests=150 not_applicable=0
ACVP HMAC-SHA2-512-2.0 PASS tests=150 not_applicable=0
ACVP ACVP-AES-GCM-1.0 PASS tests=60 not_applicable=0
ACVP ACVP-AES-ECB-1.0 PASS tests=1072 not_applicable=1072
ACVP ECDSA-SigVer-1.0 PASS tests=42 not_applicable=2268
ACVP ECDSA-SigVer-FIPS186-5 PASS tests=28 not_applicable=168
ACVP RSA-SigVer-FIPS186-4 NOT_APPLICABLE tests=0 not_applicable=432
ACVP RSA-SigVer-FIPS186-5 PASS tests=108 not_applicable=162
ACVP KDA-HKDF-Sp800-56Cr1 PASS tests=300 not_applicable=700
ACVP KDA-HKDF-Sp800-56Cr2 PASS tests=600 not_applicable=1400
ACVP TLS-v1.3-KDF-RFC8446 PASS tests=250 not_applicable=0
ACVP XECDH-SSC-RFC7748 PASS tests=25 not_applicable=25
ACVP KAS-ECC-SSC-Sp800-56Ar3 NOT_APPLICABLE tests=0 not_applicable=20
ACVP TLS-v1.3-KDF-RFC8446-native(tls.om) PASS tests=25 not_applicable=0
ACVP ML-KEM-keyGen-FIPS203 PASS tests=25 not_applicable=50
ACVP ML-KEM-encapDecap-FIPS203 PASS tests=55 not_applicable=110
ACVP hmacDRBG (om/tls/test/drbg/run.sh in /tmp/tlsproof/fipsmodule/src) DRBG PASS vectors=810 (acvp=90, cavp=720) api=23 mutants=13/13
NONFIPS CHACHA PASS vectors=3087 (wycheproof=339) mutants=5/5
NONFIPS X25519 PASS vectors=531 (wycheproof=518) mutants=7/7
ACVP PASS algos=21 tests=7623 not_applicable=7299 not_run=NONE
```
- `tests=7623` counts the ACVP-Server tests answered and compared through this pack's own drivers (20 folders). `algos=21` adds the hmacDRBG suite, whose 90 ACVP vectors are counted by its own line, not in 7623.
- Line-by-line MEASURED from `logs/run.log`; responses are in `responses/`.
- The TLS native line re-answers the 25 tests that tls.om's own key-schedule path (`tls_xtr`/`tls_drv`, SHA-256, 32-byte PSK and DHE) can take. Those 25 are already inside the 250.

### Development finding (MEASURED, `logs/run1-ecdsa-sp800-106.log`)
The first full run failed on `ECDSA-SigVer-1.0` (fail=6 of 84). The cause was in the converter, not the library. ECDSA-SigVer-1.0 has groups with `conformance: SP800-106`, whose message must first be randomized with `randomValue` (SP 800-106) before hashing. The converter had ignored that field. Those groups are now listed as not applicable, and any other `conformance` value stops the converter. The second run passes 42 of 42.

## Test types covered
- **AFT** (algorithm functional tests): known-answer tests where the IUT computes outputs from the given inputs. Covered for SHA2, HMAC, AES-GCM, AES-ECB, ECDSA SigVer, KDA, TLS-v1.3-KDF, XECDH and ML-KEM keyGen/encaps.
- **MCT** (Monte Carlo tests): chained iterations, 100 outer × 1000 inner. Covered for SHA2-256/384/512 (the standard MCT) and AES-ECB encrypt.
- **LDT** (large-data tests): SHA2 messages of 1, 2, 4 and 8 GiB (MEASURED, prompt.json `largeMsg.fullLength`), built by repeating `content` to `fullLength` bits. They are streamed through `sha2_update` without being stored. There are 4 per SHA2 folder, and all 12 ran.
- **VAL** (validation tests): the IUT must accept or reject, or recover a value. Covered for KDA (judge a supplied DKM), ML-KEM decapsulation (including implicit rejection) and both ML-KEM key checks.
- **GDT** (RSA SigVer, FIPS 186-5): verify generated signatures, some of them deliberately corrupted, and give pass or fail. Covered for PKCS#1 v1.5 with SHA2-256 across 2048/3072/4096-bit moduli (the only PKCS#1 v1.5 groups in this file, MEASURED, prompt.json). The other RSA groups are listed as not applicable below.

## Exclusions (each test is listed with its reason in `responses/FOLDER.map.json` → `na`)
| Folder | Not applicable | Reason |
|---|---|---|
| SHA2-384-1.0 | 892 | message length is not a whole number of bytes, and the library hashes bytes. (SHA2-256/512 vectors are all byte-aligned.) |
| ACVP-AES-ECB-1.0 | 1072 | decrypt: the library has no AES inverse cipher. TLS uses AES only inside GCM, encrypt direction. ECB encrypt is tested through the library's internal `aes_setkey`/`aes_enc4`, which are not a public API. |
| ECDSA-SigVer-1.0 | 2268 | curves other than P-256/P-384, hashes other than SHA2-256/384/512, and SP 800-106 randomized hashing |
| ECDSA-SigVer-FIPS186-5 | 168 | curves other than P-256/P-384, hashes other than SHA2-256/384/512 |
| RSA-SigVer-FIPS186-4 | 432 | ANSI X9.31 (144), PKCS#1 v1.5 with SHA-1 or SHA2-224 (144), PSS with SHA-1 or SHA2-224 (144). Every group in this file uses one of these, so none can run. |
| RSA-SigVer-FIPS186-5 | 162 | every RSASSA-PSS group here uses SHAKE-128, SHAKE-256 or SHA3-256 as hash and/or MGF. The library's PSS takes SHA2-256/384/512 with MGF1. `rsa_verify_pss` is therefore **not exercised through ACVP**. It is covered by `om/tls/test/rsa` (Wycheproof rsa_pss_* files), which is not part of this pack. |
| KDA-HKDF-Sp800-56Cr1 / Cr2 | 700 / 1400 | HMAC hash not in the library: SHA2-224, SHA2-512/224, SHA2-512/256, SHA3-224/256/384/512 |
| XECDH-SSC-RFC7748 | 25 | Curve448 |
| KAS-ECC-SSC-Sp800-56Ar3 | 20 | no SP 800-56A ECC key agreement in the library. Its key exchange is X25519; P-256/P-384 serve ECDSA verification only. |
| ML-KEM keyGen / encapDecap | 50 / 110 | ML-KEM-512 and ML-KEM-1024. The library is ML-KEM-768 only. |

### Encodings the converter applies
These are re-encodings of NIST's inputs, not computations:
- **ECDSA:** public key = `04‖X‖Y`, signature = `r‖s`, each left-padded to 32 or 48 bytes.
- **RSA:** a DER RSAPublicKey built from n and e.
- **KDA:** IKM = Z, or Z‖T where `usesHybridSharedSecret` is true (every Cr2 group; no Cr1 group). FixedInfo = uPartyId‖uEphemeral‖vPartyId‖vEphemeral‖uint32(L bits). Every in-scope single-expansion group uses `fixedInfoPattern` `uPartyInfo||vPartyInfo||l` with `concatenation` (MEASURED, prompt.json). Multi-expansion tests use the given fixedInfo.
- **SHA2 LDT:** NBYTES = fullLength/8.
- **XECDH:** the private key comes from internalProjection.json.
- **ML-KEM decapsulationKeyCheck:** run as `mlkem_decaps(dk, all-zero ct)`, whose FIPS 203 §7.3 length and H(ek) checks run before decapsulation (return code 3 means the check failed). encapsulationKeyCheck is run as `mlkem_encaps(ek, all-zero m)` with the §7.2 length and modulus checks (return code 1 means the check failed).

## Outside the FIPS track
ChaCha20-Poly1305 (RFC 8439) and X25519 (RFC 7748) have no CAVP/ACVP test method in this ACVP-Server tree as used here. XECDH-SSC above does cover X25519 shared secrets: 25 tests. Both ran through the repo's own suites:
- `om/tls/test/chacha/run.sh`: RFC 8439 vectors plus Wycheproof chacha20_poly1305 (339 vectors);
- `om/tls/test/x25519/run.sh`: RFC 7748 vectors plus Wycheproof x25519 (518 vectors).

Results are MEASURED in `logs/run.log` (NONFIPS lines). Wycheproof was not duplicated here; it belongs to TlsSuites.

## Overlap
TlsSuites' own ML-KEM suite also replays ACVP 975de31e ML-KEM-768 vectors from internalProjection.json. Per TlsSuites.MlKem's message (not run by me), it reports `MLKEM PASS vectors=4500 (wycheproof=756 fips203=105)`. This pack checks the prompt → response → expectedResults path independently.

## NOT_RUN
- Anything on the moved branch head c4bf4150.
- ACVP **production** or demo server submission (requires an accredited lab and NIST credentials).
- AES-ECB decrypt, PSS SigVer through ACVP, and every not-applicable row above. These are excluded with reasons, not run.

## Files
- `code/`: run.sh, the drivers and Python tools, and acvp-inputs.sha256.
- `mlkem-snap/`: the ML-KEM sources tested.
- `responses/`: per folder, the response JSON, map, driver input/output, comparator output and negative-control output.
- `logs/`: run.log (final), the run1 ECDSA log, and the pinned-fetch run.
- `SHA256SUMS`: covers every file here except itself.
