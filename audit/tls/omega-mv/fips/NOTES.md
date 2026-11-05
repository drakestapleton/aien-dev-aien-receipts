# TlsProof / FipsModule — FIPS 140-3 readiness work on om/tls (2026-10-26)

Status: IMPLEMENTED and EXERCISED on the host (DGX Spark, arm64). Tested against the FIPS 140-3 /
CAVP test methods, not NIST-validated. No laboratory, no CMVP/CAVP/ESV submission, nothing QUALIFIED,
nothing merged or deployed.

Base: aien-dev/omega-mv `audit/tls-outside-review` @ 2d613b2d2f4650ae9b5a693b3fb4caffab0dea20.
Compiler: seed/out/omc sha256 2c82480596bbdc50cda9626866209ef662d5834f278f839ff4ce0250c495029f.
Branch: audit/tls-fipsmodule (draft PR, base audit/tls-outside-review).
File sums (final): fips.om e9f8127b…d2c6, drbg.om 3d5f866a…0e5, tls.om a9524d7a…0181 (sha256, MEASURED).

## What was added

| item | FIPS 140-3 / SP reference | where | evidence |
|---|---|---|---|
| HMAC_DRBG SHA-256 (instantiate, reseed, generate, PR, reseed counter, error state) | SP 800-90A Rev. 1 §10.1.2 | om/tls/drbg.om | `DRBG PASS vectors=810 (acvp=90, cavp=720) api=23 mutants=13/13` MEASURED, logs/unit-drbg.log |
| pre-operational / first-use KATs (SHA-256/384/512, HMAC-256/384, HKDF, TLS 1.3 KDF, AES-128-GCM enc+dec, ECDSA P-256 verify + must-fail, RSA PKCS#1 v1.5 + PSS verify, ChaCha20-Poly1305, X25519, DRBG) | FIPS 140-3 area 10 (self-tests), IG 10.3.A (CASTs) | om/tls/fips.om `fips_selftest`, called from `tls_fips` in tls_connect | 14/14 KAT mutants each refuse with the right detail id, MEASURED logs/fips-run.log |
| module error state, latched, process-wide (`FPST`) | FIPS 140-3 area 10 (error state) | fips_fail, fips_bad; tls_connect/tls_seal/tls_open return TLS_ERR_SELFTEST (30) | driver checks 60-66, 70-75; code mutants latch-keep, connect-hook, seal-refuse, open-refuse MEASURED |
| X25519 pairwise consistency test on each ephemeral key | SP 800-56A Rev. 3 §5.6.2.1.4, FIPS 140-3 area 10 (conditional PCT) | fips_pctx, tls_ephem | checks 40-43, mutant pct-nocompare MEASURED |
| RCT + APT health tests with 1024-sample start-up test on every getrandom byte feeding the DRBG | SP 800-90B §4.4.1, §4.4.2, §4.3 | fips_ht, fips_draw, fips_entropy | checks 10-24, mutants rct-cutoff, apt-cutoff, apt-window, ht-unused MEASURED |
| approved mode (tls_init flag 4) | — | tls_rand / tls_randc / tls_fips in tls.om | checks 50-58, mutants rand-approved, wipe-drbg, pr-no-reseed MEASURED |
| DRBG state wiped on close | FIPS 140-3 area 9 (SSP zeroisation) | tls_wipe `tls_zero c TLDRBG DRSZ` | check 58 + mutant wipe-drbg MEASURED |
| constant-time check of new secret code | — | test/tls/timing.om modes health, drbg, pct | timing/welch.md, all |t| < 4.5 MEASURED |
| SP 800-90B entropy assessment | SP 800-90B §3.1, §6 (NIST EA tool) | test/fips/entropy.om + entropy.sh | entropy/run1, entropy/run2 MEASURED |

The DRBG continuous test (compare of successive outputs) is kept although IG
10.3.A no longer requires it for DRBGs.

## Health-test cut-offs (MODELED, Wolfram)

Query: `Table[{h, 1+Ceiling[40/h], 1+InverseCDF[BinomialDistribution[512,2^-h],1-2^-40], ...}, {h,{6,6.5,7}}]`
-> h=6: RCT 8, APT 35; h=6.5: RCT 8, APT 30; h=7: RCT 7, APT 26. alpha = 2^-40, W = 512.
Claimed H = 6 bits/byte because run 2's non-IID restart estimate (6.638383) fell below 7; first
implementation used H = 7 and was changed to H = 6 (FHRCT1 7, FHAPT1 34) after that measurement.
False-alarm probability per APT window if the true source has 8 bits/byte, H = 6 cut-off: 1.65e-31
(MODELED, same query, 1-CDF[BinomialDistribution[512,2^-8],34]).
DRBG budget at H = 6: 48-byte entropy input = 288 bits >= 256, 32-byte nonce = 192 bits >= 128
(MODELED, Wolfram `{48*6, 48*6>=256, 32*6, 32*6>=128}` -> {288, True, 192, True}).

## SP 800-90B assessment — what it grades

It grades Linux kernel getrandom output (blocking flag 0), which the kernel has already conditioned
(ChaCha20 CRNG). It is not an Omega noise source and om/tls has none of its own. An ESV would need a
kernel or platform entropy certificate; this is NOT an ESV.
Tool: usnistgov/SP800-90B_EntropyAssessment 87c104d0ed4cbc96103e7b8b38d6f2c7e0a6b289, built at
/tmp/tlsproof/fipsmodule/ea/cpp.

| run | samples.bin sha256 | min-entropy non-IID | IID | IID permutation tests | restart IID | restart non-IID |
|---|---|---|---|---|---|---|
| run1 (manual) | 3eb3092b…3247 | 7.110248 | 7.878214 | passed | 7.878214 | 7.110248 |
| run2 (entropy.sh) | 373179d1…52f1 | 7.182711 | 7.871996 | passed | 7.871996 | 6.638383 |

All MEASURED; files in entropy/run1, entropy/run2 (SHA256SUMS.bin hold the input sums).
Non-IID estimators are conservative on full-entropy data; the spread (6.64 to 7.18) is the reason for
claiming H = 6, not evidence of a defect in getrandom (INFERENCE).

## Suite final lines (omc 2c824805, commit a38cf3d8 = tree tested; MEASURED, logs/)

- SHA2 PASS vectors=1777 (wycheproof=774) mutants=5/5
- X25519 PASS vectors=531 (wycheproof=518) mutants=7/7
- CHACHA PASS vectors=3087 (wycheproof=339) mutants=5/5
- AESGCM PASS vectors=47570 (fips197=4, nist=47250, wycheproof=316) mutants=5/5
- EC PASS vectors=3984 (wycheproof=3748 cavp=180 edge=56) mutants=6/6
- RSA PASS vectors=6486 (wycheproof=5250) mutants=4/4
- X509 PASS cases=91 (openssl-parity=73/91) mutants=12/12
- DRBG PASS vectors=810 (acvp=90, cavp=720) api=23 mutants=13/13
- FIPS PASS checks=45 drbgerr=46 kat-mutants=14/14 code-mutants=16/16
- ENTROPY PASS non_iid=7.182711 iid=7.871996 iid_tests=passed restart_iid=7.871996 restart_non_iid=6.638383 (on H=7 code; entropy.sh does not depend on the cut-offs)
- TLS PASS vectors=24 (rfc8448) dns=23 dit=1 interop=44 residue=PASS net=NOT_RUN mutants=27/27 (logs/tls-run.log, commit a38cf3d8)
- seed/net check.py: HTTPS PASS, HTTP-CHECK PASS, HTTPS-LIVE NOT_RUN (logs/net-check.log)
- One TLS run done in parallel with check.py failed 9+ fakesrv rows with TLS_ERR_IO and empty server logs
  (logs/tls-run-fail-parallel.log); rerun alone passed. Attributed to fakesrv's fixed 0.6 s start-up sleep under load
  (INFERENCE, not root-caused).

Pins: ACVP-Server 975de31eb83d87039ec88934fdc47d8c312b892d (DRBG ACVP vectors); CAVP drbgvectors
zip sha256 5f7e5658…9377769.

## Fix made during this work

test/tls/run.sh mutant "read record limit gone" uses range `/^fn tls_open /,/^end$/`; the first
self-test hook placed before the record-limit check ended that range early and the mutant stopped
applying (FAIL in an earlier run). The hooks in tls_open and tls_seal now sit after the record-limit
check; the fips mutants seal-refuse / open-refuse use `/^for i ulong 5$/` as range end.

## Coordination

Approved-mode flag is 4 (TlsSuites.TlsProto took 2 for a forced-HRR test); tls_init mask
`and fl 5` matches TlsProof.ApprovedMode's branch. ApprovedMode will route its EC keygen through
`tls_rand` and its PCT failure through `fips_fail 21`, whichever branch lands second. Its interop.sh
has approved-mode handshake rows (openssl P-256/P-384 AES-128-GCM, RSA leaf, fakesrv ap-ok/ap-cvbad).

## NOT_RUN / open

- NOT_RUN: TLS_NET live GETs; an approved-mode end-to-end handshake on this branch (rows live on
  audit/tls-approvedmode); PCT handshake cost (per-call fips_pctx ≈318.4 µs cpu0 / ≈178.2 µs cpu5 crop90
  means are MEASURED in timing/pct-*.txt); timing rerun with the H = 6 constants; EA tool self-test;
  any hardware-lab or second-machine run.
- Open for a lab: module boundary and security policy document; ESV for the entropy source (kernel);
  approved-algorithm list (X25519, ChaCha20-Poly1305 are non-approved; the approved-mode suite and
  group restriction is ApprovedMode's lane); ECDSA/RSA verify are variable-time by design (public
  data only); omc does not scrub registers/spilled locals (THREAT_MODEL limit 1); PSTATE.DIT not set
  (limit 2); the cropped health timing on cpu0 (t 3.97 / 3.41) is below 4.5 but not root-caused;
  ACVP server submission (AcvpRun lane) not done.
