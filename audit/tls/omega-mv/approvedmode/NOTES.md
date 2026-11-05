# TlsProof.ApprovedMode: approved-only mode for om/tls (omega-mv, base audit/tls-outside-review 2d613b2d)

Wording: tested against the FIPS 140-3 / CAVP test methods, not NIST-validated. Nothing here is a
certification, a module boundary or a lab result.

## Mode definition
`tls_init c host flags` with flag 4 (opt-in; mask `and fl 5`, flag 2 is TlsSuites' forced-HRR test bit).
Default mode (flag 4 clear) is byte-for-byte the old ClientHello and policy.
- Offers: cipher suite TLS_AES_128_GCM_SHA256 only; supported_groups secp256r1 (23), secp384r1 (24)
  with a key share for each; signature_algorithms ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384,
  rsa_pss_rsae_sha256/384/512.
- Refuses: ServerHello with ChaCha20-Poly1305 -> TLS_ERR_CIPHER_SUITE (10); x25519 or any other group
  -> TLS_ERR_KEY_SHARE (11); invalid EC point -> TLS_ERR_KEY_SHARE; Z at infinity -> TLS_ERR_ZERO_SECRET;
  HelloRetryRequest still refused (13).
- Key generation: rejection sampling (FIPS 186-5 A.2.2 / SP 800-56A Rev.3 5.6.1.2.2), at most 16
  draws from getrandom; pair-wise consistency test (SP 800-56A Rev.3 5.6.2.1.4); failure TLS_ERR_RANDOM (24).
- Wipes: both EC private keys after Z (tls_ecdhp), Z in tls_hskeys, all state in tls_wipe.

## Approved algorithms used and their NIST documents
| function | om unit | document | test evidence |
|---|---|---|---|
| AES-128 | aesgcm.om | FIPS 197 | AESGCM suite, fips197=4 |
| GCM | aesgcm.om | SP 800-38D | NIST GCM vectors 47250 |
| SHA-256/384 | sha2.om | FIPS 180-4 | SHAVS + Wycheproof 1777 |
| HMAC | hkdf.om | FIPS 198-1 | RFC 4231 vectors |
| TLS 1.3 KDF (HKDF) | hkdf.om, tls.om | SP 800-56C Rev.2, SP 800-135 Rev.1 | RFC 8448 KAT (24) |
| ECC CDH P-256/P-384 | ecdh.om | SP 800-56A Rev.3 5.7.1.2, 5.6.2.3.4, 5.6.2.1.4 | ECDH suite: CAVP KAS ECC CDH 100, Wycheproof 2284, edge 74, mutants 9/9 |
| ECDSA verify P-256/P-384 | ec.om | FIPS 186-5 | CAVP SigVer 180, Wycheproof 3748 |
| RSA-PSS verify | rsa.om | FIPS 186-5 | Wycheproof 5250 |

## Still non-approved / open
1. Random source: Linux getrandom, no SP 800-90A DRBG on this branch (FipsModule lane adds tls_rand; on
   rebase tls_ecgen's draw -> tls_rand, PCT failure -> fips_fail 21 / TLESELF).
2. x509.om accepts RSASSA-PKCS1-v1_5 certificate signatures (SHA-256/384/512; SHA-1/MD5 already refused).
   PKCS#1 v1.5 verify is allowed by FIPS 186-5 for verification, but a lab must confirm scope.
3. No power-on self-tests / CASTs in this branch (FipsModule lane).
4. No ACVP KAS-ECC run (TlsProof.AcvpRun lane); CAVP vectors only. ML-KEM not included (TlsSuites).
5. ec.om ECDSA verify is variable time (public data only, by design).
6. Client EC private-key wipe is not residue-checkable (server never learns d): NOT_RUN; code review + wipe line only.
7. P-384 dudect timing NOT_RUN; P-256 MEASURED on one loaded host (timing/welch.md).
8. PSTATE.DIT not set (compiler word missing).

## Evidence (MEASURED, this host, omc 2c824805)
See SHA256SUMS in this directory: ecdh-run.log, unit-*.log, interop1.log, tls-run3.log,
tls-run2-ladder-mutant-undetected.log (negative finding: a ladder-step mutant commutes under DH and
passes all 57 interop rows; it is caught only by the ecdh unit's CAVP vectors, so run.sh uses a
Z-from-y mutant instead), timing/ (raw samples, sums.json, welch.md with Wolfram queries).
