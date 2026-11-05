# Proof pack: Omega TLS 1.3 client (aien-dev/omega-mv om/tls)

Tested code: omega-mv `2d613b2d2f4650ae9b5a693b3fb4caffab0dea20` (PR #833; the code is the same at head c4bf4150).
Compiler: seed/out/omc, sha256 2c824805…029f. Host: DGX Spark, arm64, Ubuntu 24.04.
Wording: **tested against the FIPS 140-3 / CAVP test methods, not NIST-validated.** No certificate is claimed.

| file | what it shows |
|---|---|
| INDUSTRY.md | what OpenSSL, BoringSSL, AWS-LC, rustls, wolfSSL and Go publish as proof, with links |
| READINESS.md | each FIPS 140-3 area marked READY / GAP / BLOCKER, with evidence |
| SECURITY-POLICY.md | draft security policy in SP 800-140B order (self-written) |
| COSTS.md | the steps that need money or a signature, with published prices |
| acvp/ | NIST ACVP sample vectors: `ACVP PASS algos=21 tests=7623 not_applicable=7299 not_run=NONE` (MEASURED, acvp/logs/run.log; reproduced on omega-mv#844, acvp/logs/run-branch-844-full.log) |
| fips/ | DRBG (810 vectors), self-tests and error state (45 checks), SP 800-90B entropy (omega-mv#846, MEASURED) |
| approvedmode/ | approved-only mode and P-256/P-384 ECDH (2458 vectors; omega-mv#847, MEASURED) |
| bench/ | HTTPS benchmark against OpenSSL 3.0.13 and rustls 0.23.42: frozen protocol, raw rows, Wolfram statistics, RESULTS.md |
| handshake-cost/, omeganext-crypto-hostwords.md | why Omega's handshake is slower and the proposed fix (PROPOSED, not built) |
| nodelay/ | TLS suite and 7/7 live HTTPS parity on the TCP_NODELAY fix (omega-mv#844, MEASURED) |
| repro/ | two fresh clones build byte-identical binaries (MEASURED, same machine only) |
| rerun.sh | reruns all of the above from a clean directory (`--bench` adds the benchmark) |

Fuzzing: AFL++ harness and controls in omega-mv#849, evidence in TlsProof/fuzz on the Spark. The long campaign is NOT_RUN.
Conformance suites (Wycheproof, x509-limbo, tlsfuzzer, BoGo, badssl): see the TlsSuites draft PR stacked on omega-mv#833.
