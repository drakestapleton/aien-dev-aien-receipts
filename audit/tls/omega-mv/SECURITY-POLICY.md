# om/tls security policy (structured after NIST SP 800-140B)

Status: **draft, self-written, not reviewed by a laboratory.** om/tls has been tested against the
FIPS 140-3 / CAVP test methods; it is **not NIST-validated** and holds no CMVP or CAVP certificate.
The section order follows NIST SP 800-140B Rev. 1 and ISO/IEC 19790:2012 Annex B
(https://csrc.nist.gov/pubs/sp/800/140/b/r1/final), so a laboratory can map it to its own template.
Every evidence line names a file in this directory or a rerun command; items without evidence say
NOT_RUN or GAP.

Code under test: aien-dev/omega-mv, base `audit/tls-outside-review` @ 2d613b2d (code-identical to
c4bf4150), plus the draft branches named per section. Compiler `seed/out/omc` sha256 2c824805…029f.

## 1. General

| item | value |
|---|---|
| module name | om/tls (Omega TLS 1.3 client library) |
| type | software module, multi-chip standalone embodiment (host process) |
| intended overall level | Security Level 1 (proposal; no level is assigned without validation) |
| scope | TLS 1.3 client only; see om/tls/AUDIT_SCOPE.md for out-of-scope features (server, client certs, resumption, 0-RTT) |

## 2. Cryptographic module specification

Boundary (proposal): the compiled om/tls units `sha2.om hkdf.om aesgcm.om chacha.om x25519.om ec.om
ecdh.om rsa.om x509.om drbg.om fips.om tls.om`, linked into one executable by the pinned compiler.
The operating system, the compiler and the calling program are outside the boundary.

Approved mode: `tls_init` flag 4 (drafts #846 FipsModule, #847 ApprovedMode; integration branch
audit/tls-fips-approved). Non-approved mode: flag 4 clear (default, unchanged ClientHello).

| function | algorithm | standard | mode | evidence |
|---|---|---|---|---|
| encryption | AES-128-GCM | FIPS 197, SP 800-38D | approved | acvp/logs/run.log (ACVP-AES-GCM), unit AESGCM 47570 vectors |
| hashing | SHA-256, SHA-384, SHA-512 | FIPS 180-4 | approved | ACVP SHA2 sets, unit SHA2 1777 vectors |
| MAC | HMAC-SHA-256/384 | FIPS 198-1 | approved | ACVP HMAC sets |
| KDF | TLS 1.3 KDF (HKDF) | SP 800-56C Rev. 2, SP 800-135 Rev. 1 | approved | ACVP TLS-v1.3 KDF, RFC 8448 KAT |
| key agreement | ECC CDH P-256/P-384 | SP 800-56A Rev. 3 | approved | ECDH suite 2458 vectors (draft #847); ACVP KAS-ECC NOT_RUN |
| signature verify | ECDSA P-256/P-384 | FIPS 186-5 | approved | ACVP ECDSA SigVer, unit EC 3984 vectors |
| signature verify | RSA-PSS, RSA PKCS#1 v1.5 | FIPS 186-5 | approved (v1.5 verify scope: lab to confirm) | ACVP RSA SigVer, unit RSA 6486 vectors |
| random bits | HMAC_DRBG SHA-256 | SP 800-90A Rev. 1 | approved | DRBG 810 vectors (acvp=90, cavp=720), draft #846 |
| encryption | ChaCha20-Poly1305 | RFC 8439 | non-approved, refused in approved mode | RFC + Wycheproof, 3087 vectors |
| key agreement | X25519 | RFC 7748 | non-approved, refused in approved mode | RFC + Wycheproof, 531 vectors |

ACVP figures: `ACVP PASS algos=21 tests=7623 not_applicable=7299 not_run=NONE` (acvp/logs/run.log,
NIST ACVP-Server sample vectors pinned at 975de31e). These are self-run sample vectors, not a CAVP
certificate.

## 3. Cryptographic module interfaces

Data input: `tls_read` plaintext from the caller, records from the socket. Data output: `tls_write`
records, decrypted plaintext. Control input: `tls_init` flags, host name, trust store. Status output:
`TLS_ERR_*` return codes (`TLS_ERR_SELFTEST` 30 once the error state is latched). No power interface
(software module).

## 4. Roles, services and authentication

One role (User = the calling process); no operator authentication (permitted at Level 1). Services:
connect, write, read, close, self-test-on-first-use, status. No Crypto Officer service exists: there is
no key loading, no configuration of keys, no key export. GAP for a lab: a "show module name/version"
service is required by FIPS 140-3 and not yet implemented.

## 5. Software/firmware security

Integrity test at start: GAP. FIPS 140-3 requires an approved integrity technique (for example an
HMAC-SHA-256 over the module binary) before first use; om/tls has none. Reproducible build is
MEASURED (repro/run.log: two fresh clones, omc and 9 test binaries byte-identical at 2d613b2d), which
is the basis for computing such a value, not a substitute for it.

## 6. Operational environment

Modifiable operational environment: Linux on arm64 (tested: Ubuntu, kernel 7.0.0-1019-nvidia, NVIDIA
DGX Spark GB10). Single process, the module's state is per connection plus one process-wide
self-test/error flag. Other platforms NOT_RUN.

## 7. Physical security

Not applicable (software module).

## 8. Non-invasive security

No FIPS 140-3 requirements are in force for this area yet. Side-channel evidence: dudect-style Welch
t-tests on the secret-dependent code (TlsAudit evidence; ApprovedMode timing/welch.md; FipsModule
timing/welch.md), all |t| < 4.5 on one loaded host (MEASURED). PSTATE.DIT detected but not set
(GAP: needs a compiler word). ECDSA/RSA verification is variable-time by design (public inputs).

## 9. Sensitive security parameter (SSP) management

| SSP | generated by | stored | zeroised |
|---|---|---|---|
| ephemeral EC / X25519 private keys | DRBG (approved mode) / getrandom (default) with rejection sampling | connection state | after shared secret (tls_ecdhp), tls_wipe |
| shared secret Z | ECDH | connection state | tls_hskeys, tls_wipe |
| handshake and traffic secrets, AEAD keys and IVs | TLS 1.3 KDF | connection state | after Finished / on close (residue suite: `RESIDUE PASS secrets=18 hs_only=12`) |
| DRBG V, Key | HMAC_DRBG | connection state | tls_wipe (check 58, mutant wipe-drbg) |

Entropy: Linux getrandom, assessed with NIST's SP 800-90B tool (min-entropy non-IID 7.18, restart
non-IID 6.64 bits/byte; FipsModule entropy/run2). This grades the kernel's already conditioned
output; it is not an Omega noise source and not an ESV certificate. Claimed H = 6 bits/byte.
Health tests on every byte: repetition count cut-off 8, adaptive proportion 35 in 512 (MODELED,
Wolfram, alpha = 2^-40). Compiler limit: omc does not scrub registers or spilled locals (THREAT_MODEL
limit 1, GAP).

## 10. Self-tests

Pre-operational / first-use known-answer tests for every algorithm, the DRBG and both modes
(fips_selftest), a latched process-wide error state, a pair-wise consistency test on every new key,
and continuous RCT/APT health tests (FipsModule: `FIPS PASS checks=45 drbgerr=46 kat-mutants=14/14
code-mutants=16/16`, MEASURED). GAP: the software integrity test of section 5.

## 11. Life-cycle assurance

Source control: git, public at github.com/aien-dev/omega-mv. Build: one pinned compiler from a
committed seed, reproducible (section 5). Vulnerability handling: SECURITY.md (private reporting
on GitHub). Tests: every suite publishes a final PASS line, mutants that must fail, and NOT_RUN lists.
Guidance documents for users (how to run approved mode): om/tls/README.md on the drafts.

## 12. Mitigation of other attacks

Memory-residue scanning of secrets (section 9). Certificate path validation with x509-limbo and
Wycheproof (TlsSuites lane). Fuzzing: see fuzz/ (status stated there).
