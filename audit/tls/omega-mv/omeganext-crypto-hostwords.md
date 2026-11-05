# PROPOSED for OmegaNext batch3: ARMv8 crypto-extension host words for om/tls

From: TlsProof (2026-10-26). Status: PROPOSED, nothing implemented. Drake/integrator decides.

## Why
om/tls AES-128-GCM is bitsliced AES plus bit-by-bit GHASH (no AESE/PMULL), SHA-256/384 are plain
integer code. In the TlsProof HTTPS benchmark (PROTOCOL.md, results in TlsProof/bench/) the Omega client
loses most on AES-GCM bulk transfer: 50.7 MB/s vs 2090 MB/s (OpenSSL 3.0.13) and 2138 MB/s (rustls+aws-lc-rs)
at 16 KiB records on cpu 16 (Cortex-X925 fast core), paired ratio 0.0242; on cpu 2 (Cortex-A725) 24.3 vs 1429 MB/s, ratio 0.0168 (MEASURED, TlsProof/bench/RESULTS.md, n=30, Wolfram CIs).
Second: handshake, dominated by P-256 ECDSA verify (1.361 ms vs 0.039 ms, both on cpu 16, X925) - not a host-word issue. The GB10 cores advertise
`aes pmull sha2 sha512 sha3 dit` in /proc/cpuinfo, so the gap is a missing instruction, not the machine.

## Words (all fixed-latency, data-independent timing per Arm ARM; DIT already detected by tls_hwdit)
| word | instruction | operands (proposal) | use |
|---|---|---|---|
| `aesenc st rk` | AESE v,v ; AESMC v,v | st edit uchar 16, rk view uchar 16 | AES round (encrypt) |
| `aeslast st rk` | AESE v,v ; EOR with last key | st edit uchar 16, rk view uchar 16, k2 view uchar 16 | final round |
| `clmul a b out` | PMULL + PMULL2 | a, b view uchar 16, out edit uchar 32 | GHASH 128x128 carry-less multiply |
| `sha256x st blk` | SHA256H/H2/SU0/SU1 rounds over one 64-byte block | st edit uint 8, blk view uchar 64 | SHA-256 compress |
| `sha512x st blk` | SHA512H/H2/SU0/SU1 over one 128-byte block | st edit ulong 8, blk view uchar 128 | SHA-384/512 compress |
A batched form (`aesctr` over N blocks) is the larger win but is a second step; first the scalar words.

## Conditions (same as other host words)
1. Opt-in per call site; the bitsliced AES, bit-serial GHASH and portable SHA-2 stay as the reference
   and as the fallback when HWCAP lacks the feature (getauxval AT_HWCAP: AES bit 3, PMULL 4, SHA2 6,
   SHA512 21). Selection reported in the TLS self-test line.
2. Equality gate: every existing om/tls vector suite (SHA2 1777, AESGCM 47570, ...) passes on both paths,
   plus a differential run of the two paths on random inputs.
3. Constant-time gate: dudect run (TlsAudit harness) on the new path; the host words must not branch or
   index on data.
4. Wipe gate: no key-schedule or state copies left in vector registers or the stack after return
   (zero v0-v7 used on exit, documented clobber set).
5. Encoding oracle: each emitted word checked against an independent assembler (llvm-mc / GNU as
   disassembly of the same encoding), not against an --update golden.
6. C2 and all 811 tracked .om files byte-identical when the words are not used.
