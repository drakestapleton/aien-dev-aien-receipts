# TlsProof HTTPS benchmark: results

All figures MEASURED on the DGX Spark (GB10) on 2026-10-26 under the frozen protocol
(PROTOCOL.md sha256 fc351183906b97b9c3fb1bc90736b9943d91695af336fd06fafc4920684718b1, frozen
2026-10-26T21:25:43Z before any timed sample; FROZEN.sha256 lists every input and binary).
Raw data: results/raw.jsonl (3000 client processes, all exit 0, all with the full sample count and the
expected byte count for their workload); correctness gate results/gate.json (all 20 arm x suite x body
cases matched the body sha256). Statistics: Wolfram (wolfram-cpu*-*.wl inputs, wolfram-out-*.json outputs):
median of the 30 per-round values with a distribution-free 95.72% order-statistic CI (n = 30, ranks 10
and 21); "omega/arm" is the median of the 30 paired per-round ratios with the same CI.

Direction of the ratio, in words: for ms rows omega/arm > 1 means Omega is SLOWER; for MB/s rows
omega/arm < 1 means Omega is SLOWER. "omega" is om/tls with the TCP_NODELAY fix
(drivers/tls-nodelay.diff); "omega-asis" is om/tls exactly at PR #833 2d613b2d (code identical at the
current head c4bf4150: 2d613b2d..c4bf4150 touches only .crumb, README.md and THREAT_MODEL.md).

Shared machine: load average 16.1-30.2 during the run (env rows in raw.jsonl), run under quiet-measure.
Server: openssl s_server 3.0.13 on cpu 18 for every arm; it is the same for all arms, so its cost is
in every number. Client CPU column: GNU time has 10 ms resolution, i.e. 0.25 ms per handshake at
40 handshakes per process; it includes process start-up and is coarse.
Peak RSS is the whole client process (program + library + one connection at a time), not a
per-connection figure. Omega's per-connection TLS state is fixed by layout: TLCSZ 119296 bytes
plus a 262144-byte trust/scratch store (om/tls/tls.om constants; structural, not measured).

### cpu 16 (X925), chacha

| workload | arm | median | 95% CI | omega/arm (paired) | 95% CI |
|---|---|---|---|---|---|
| hs (ms) | omega | 3.34 | 3.32–3.51 | — | — |
| hs (ms) | omega-asis | 3.35 | 3.29–3.46 | 1 | 0.995–1.01 |
| hs (ms) | openssl | 0.469 | 0.448–0.528 | 7.19 | 6.43–7.35 |
| hs (ms) | rustls-awslc | 0.29 | 0.281–0.343 | 11.7 | 10.9–11.8 |
| hs (ms) | rustls-ring | 0.293 | 0.286–0.311 | 11.6 | 11.2–11.7 |
| get1k (ms) | omega | 3.53 | 3.39–3.82 | — | — |
| get1k (ms) | omega-asis | 42.2 | 42–42.7 | 0.083 | 0.08–0.0894 |
| get1k (ms) | openssl | 0.55 | 0.495–0.596 | 6.69 | 6.42–6.9 |
| get1k (ms) | rustls-awslc | 0.335 | 0.313–0.407 | 10.5 | 9.8–10.8 |
| get1k (ms) | rustls-ring | 0.325 | 0.32–0.35 | 10.5 | 9.87–10.9 |
| get1m (ms) | omega | 8.65 | 8.36–8.97 | — | — |
| get1m (ms) | omega-asis | 47.7 | 47.1–48.3 | 0.178 | 0.177–0.181 |
| get1m (ms) | openssl | 1.44 | 1.39–1.6 | 5.93 | 5.71–6.12 |
| get1m (ms) | rustls-awslc | 1.21 | 1.17–1.31 | 7.13 | 6.84–7.24 |
| get1m (ms) | rustls-ring | 1.2 | 1.18–1.29 | 7.08 | 6.95–7.14 |
| bulk16k (MB/s) | omega | 211 | 210–211 | — | — |
| bulk16k (MB/s) | omega-asis | 142 | 141–143 | 1.48 | 1.47–1.49 |
| bulk16k (MB/s) | openssl | 1216 | 1202–1223 | 0.174 | 0.173–0.176 |
| bulk16k (MB/s) | rustls-awslc | 1236 | 1216–1241 | 0.171 | 0.169–0.171 |
| bulk16k (MB/s) | rustls-ring | 1231 | 1207–1240 | 0.171 | 0.171–0.172 |
| bulk1k (MB/s) | omega | 158 | 156–158 | — | — |
| bulk1k (MB/s) | omega-asis | 116 | 115–116 | 1.36 | 1.35–1.36 |
| bulk1k (MB/s) | openssl | 338 | 293–408 | 0.454 | 0.378–0.537 |
| bulk1k (MB/s) | rustls-awslc | 315 | 296–339 | 0.501 | 0.466–0.536 |
| bulk1k (MB/s) | rustls-ring | 301 | 277–329 | 0.516 | 0.479–0.573 |

| arm | peak RSS KiB (get1m process) median [CI] | client CPU ms per handshake incl. startup/40, median [CI] |
|---|---|---|
| omega | 1440 [1440–1440] | 3 [3–3] |
| omega-asis | 1440 [1436–1440] | 3 [3–3] |
| openssl | 6428 [6420–6428] | 0.25 [0.25–0.25] |
| rustls-awslc | 4264 [4264–4284] | 0.5 [0.5–0.5] |
| rustls-ring | 3708 [3408–3728] | 0 [0–0] |

### cpu 16 (X925), aes128gcm

| workload | arm | median | 95% CI | omega/arm (paired) | 95% CI |
|---|---|---|---|---|---|
| hs (ms) | omega | 3.43 | 3.35–3.49 | — | — |
| hs (ms) | omega-asis | 3.38 | 3.34–3.48 | 1.01 | 0.993–1.01 |
| hs (ms) | openssl | 0.471 | 0.46–0.496 | 7.23 | 7.06–7.44 |
| hs (ms) | rustls-awslc | 0.295 | 0.281–0.307 | 11.8 | 11.4–12 |
| hs (ms) | rustls-ring | 0.293 | 0.285–0.305 | 11.7 | 11.5–11.8 |
| get1k (ms) | omega | 3.52 | 3.44–3.82 | — | — |
| get1k (ms) | omega-asis | 42.3 | 42–42.9 | 0.0833 | 0.0817–0.0906 |
| get1k (ms) | openssl | 0.518 | 0.5–0.572 | 6.77 | 6.56–7.05 |
| get1k (ms) | rustls-awslc | 0.327 | 0.318–0.356 | 10.9 | 10.8–11.1 |
| get1k (ms) | rustls-ring | 0.336 | 0.327–0.362 | 10.7 | 9.75–10.9 |
| get1m (ms) | omega | 24.4 | 24.3–24.7 | — | — |
| get1m (ms) | omega-asis | 63 | 62.9–63.1 | 0.388 | 0.385–0.389 |
| get1m (ms) | openssl | 1.09 | 1.03–1.19 | 22.6 | 20.8–23.9 |
| get1m (ms) | rustls-awslc | 0.851 | 0.813–0.917 | 29 | 26.6–30.1 |
| get1m (ms) | rustls-ring | 0.873 | 0.802–0.924 | 28.9 | 26.7–30.5 |
| bulk16k (MB/s) | omega | 50.7 | 50.5–50.8 | — | — |
| bulk16k (MB/s) | omega-asis | 45.4 | 45.3–45.5 | 1.12 | 1.11–1.12 |
| bulk16k (MB/s) | openssl | 2090 | 2039–2151 | 0.0242 | 0.0235–0.0249 |
| bulk16k (MB/s) | rustls-awslc | 2138 | 2068–2191 | 0.0238 | 0.0232–0.0244 |
| bulk16k (MB/s) | rustls-ring | 2137 | 2080–2166 | 0.0238 | 0.0234–0.0244 |
| bulk1k (MB/s) | omega | 41.8 | 41.7–41.8 | — | — |
| bulk1k (MB/s) | omega-asis | 38.1 | 38.1–38.2 | 1.1 | 1.09–1.1 |
| bulk1k (MB/s) | openssl | 367 | 338–463 | 0.11 | 0.09–0.124 |
| bulk1k (MB/s) | rustls-awslc | 349 | 340–367 | 0.118 | 0.114–0.123 |
| bulk1k (MB/s) | rustls-ring | 356 | 334–375 | 0.117 | 0.11–0.125 |

| arm | peak RSS KiB (get1m process) median [CI] | client CPU ms per handshake incl. startup/40, median [CI] |
|---|---|---|
| omega | 1440 [1436–1440] | 3 [3–3] |
| omega-asis | 1440 [1440–1440] | 3 [3–3] |
| openssl | 6428 [6424–6428] | 0.25 [0.25–0.25] |
| rustls-awslc | 3714 [3708–4216] | 0.5 [0.5–0.5] |
| rustls-ring | 3676 [3164–3676] | 0 [0–0] |

### cpu 2 (A725), chacha

| workload | arm | median | 95% CI | omega/arm (paired) | 95% CI |
|---|---|---|---|---|---|
| hs (ms) | omega | 7.31 | 7.25–7.35 | — | — |
| hs (ms) | omega-asis | 7.27 | 7.26–7.3 | 1 | 0.997–1.01 |
| hs (ms) | openssl | 0.886 | 0.875–0.9 | 8.23 | 8.15–8.33 |
| hs (ms) | rustls-awslc | 0.473 | 0.457–0.476 | 15.6 | 15.4–15.9 |
| hs (ms) | rustls-ring | 0.464 | 0.46–0.472 | 15.8 | 15.4–16 |
| get1k (ms) | omega | 7.51 | 7.39–7.57 | — | — |
| get1k (ms) | omega-asis | 42.8 | 42.8–42.9 | 0.175 | 0.173–0.177 |
| get1k (ms) | openssl | 0.967 | 0.947–0.979 | 7.83 | 7.7–7.96 |
| get1k (ms) | rustls-awslc | 0.531 | 0.514–0.542 | 14.1 | 14–14.4 |
| get1k (ms) | rustls-ring | 0.523 | 0.516–0.53 | 14.3 | 14–14.5 |
| get1m (ms) | omega | 18.3 | 18.2–18.3 | — | — |
| get1m (ms) | omega-asis | 53.9 | 53.8–53.9 | 0.34 | 0.339–0.342 |
| get1m (ms) | openssl | 2.86 | 2.79–2.9 | 6.45 | 6.25–6.56 |
| get1m (ms) | rustls-awslc | 2.23 | 2.14–2.31 | 8.15 | 7.79–8.63 |
| get1m (ms) | rustls-ring | 2.19 | 2.12–2.24 | 8.41 | 8.25–8.63 |
| bulk16k (MB/s) | omega | 98.2 | 97.6–98.7 | — | — |
| bulk16k (MB/s) | omega-asis | 81.7 | 81–81.9 | 1.2 | 1.2–1.21 |
| bulk16k (MB/s) | openssl | 610 | 606–619 | 0.161 | 0.157–0.162 |
| bulk16k (MB/s) | rustls-awslc | 712 | 706–723 | 0.137 | 0.136–0.139 |
| bulk16k (MB/s) | rustls-ring | 705 | 695–724 | 0.139 | 0.135–0.142 |
| bulk1k (MB/s) | omega | 76.4 | 76–76.8 | — | — |
| bulk1k (MB/s) | omega-asis | 66.1 | 65.9–66.2 | 1.16 | 1.15–1.16 |
| bulk1k (MB/s) | openssl | 302 | 291–307 | 0.254 | 0.249–0.264 |
| bulk1k (MB/s) | rustls-awslc | 190 | 188–222 | 0.399 | 0.342–0.404 |
| bulk1k (MB/s) | rustls-ring | 189 | 187–208 | 0.401 | 0.368–0.407 |

| arm | peak RSS KiB (get1m process) median [CI] | client CPU ms per handshake incl. startup/40, median [CI] |
|---|---|---|
| omega | 1412 [1412–1412] | 7 [7–7] |
| omega-asis | 1412 [1412–1412] | 7 [7–7] |
| openssl | 6428 [6428–6428] | 0.75 [0.5–0.75] |
| rustls-awslc | 3708 [3708–4216] | 1 [1–1.25] |
| rustls-ring | 3660 [3164–3676] | 0.25 [0.25–0.25] |

### cpu 2 (A725), aes128gcm

| workload | arm | median | 95% CI | omega/arm (paired) | 95% CI |
|---|---|---|---|---|---|
| hs (ms) | omega | 7.46 | 7.41–7.57 | — | — |
| hs (ms) | omega-asis | 7.43 | 7.37–7.52 | 1.01 | 0.999–1.02 |
| hs (ms) | openssl | 0.945 | 0.913–0.994 | 8.18 | 7.74–8.58 |
| hs (ms) | rustls-awslc | 0.487 | 0.467–0.505 | 15.9 | 15.1–16.2 |
| hs (ms) | rustls-ring | 0.479 | 0.47–0.513 | 15.7 | 14.9–16.1 |
| get1k (ms) | omega | 7.76 | 7.59–8.08 | — | — |
| get1k (ms) | omega-asis | 42.8 | 42.1–42.9 | 0.183 | 0.179–0.192 |
| get1k (ms) | openssl | 1.04 | 0.976–1.11 | 7.59 | 7.24–8.2 |
| get1k (ms) | rustls-awslc | 0.571 | 0.546–0.591 | 14.2 | 13.1–14.8 |
| get1k (ms) | rustls-ring | 0.543 | 0.531–0.597 | 14.4 | 13.8–14.6 |
| get1m (ms) | omega | 49.5 | 48.9–50.5 | — | — |
| get1m (ms) | omega-asis | 84.4 | 84–84.7 | 0.58 | 0.572–0.592 |
| get1m (ms) | openssl | 2.05 | 1.9–2.3 | 24.4 | 23.2–26.8 |
| get1m (ms) | rustls-awslc | 1.55 | 1.44–1.73 | 32 | 28.3–34.3 |
| get1m (ms) | rustls-ring | 1.45 | 1.38–1.6 | 34.6 | 31.5–36.4 |
| bulk16k (MB/s) | omega | 24.3 | 22.3–24.9 | — | — |
| bulk16k (MB/s) | omega-asis | 23.9 | 22.8–24.2 | 1.03 | 0.988–1.06 |
| bulk16k (MB/s) | openssl | 1429 | 1341–1506 | 0.0168 | 0.0159–0.0185 |
| bulk16k (MB/s) | rustls-awslc | 1509 | 1373–1555 | 0.0157 | 0.0148–0.017 |
| bulk16k (MB/s) | rustls-ring | 1484 | 1372–1569 | 0.0162 | 0.0155–0.0165 |
| bulk1k (MB/s) | omega | 20.6 | 19.8–21 | — | — |
| bulk1k (MB/s) | omega-asis | 19.7 | 19.2–20.1 | 1.04 | 0.997–1.07 |
| bulk1k (MB/s) | openssl | 232 | 206–322 | 0.0755 | 0.0613–0.0979 |
| bulk1k (MB/s) | rustls-awslc | 208 | 201–250 | 0.0889 | 0.0653–0.101 |
| bulk1k (MB/s) | rustls-ring | 207 | 201–238 | 0.0942 | 0.0688–0.104 |

| arm | peak RSS KiB (get1m process) median [CI] | client CPU ms per handshake incl. startup/40, median [CI] |
|---|---|---|
| omega | 1466 [1424–1468] | 7 [7–7.25] |
| omega-asis | 1462 [1424–1472] | 7 [7–7] |
| openssl | 6418 [6416–6424] | 0.75 [0.75–0.75] |
| rustls-awslc | 3686 [3396–3696] | 1.25 [1–1.25] |
| rustls-ring | 3140 [2976–3156] | 0.25 [0–0.25] |

## Why Omega loses, per row (each cause MEASURED or MODELED as labelled)

1. Handshake (Omega 7.2-11.8x slower on X925): two P-256 ECDSA verifications (certificate signature and
   CertificateVerify) cost 1.361 ms each in om/tls (MEASURED: ec driver, 500 verifies of one CAVP P-256
   vector, 680588757 ns, cpu 16; /tmp/tlsproof/prof) against 0.0391 ms in OpenSSL 3.0.13 (MEASURED:
   `openssl speed ecdsap256`, cpu 16, 25587 verify/s): 34.8x. X25519 costs 0.17 ms per call (MEASURED,
   RFC 7748 1000-iteration vector, 0.17 s) against 0.0229 ms (OpenSSL speed, 43615.5 op/s): 7.4x.
   MODELED (Wolfram, 2*0.17 + 2*1.361 = 3.06 ms): 92% of the 3.34 ms Omega handshake is these four
   public-key operations. ec.om uses a generic multi-curve big-integer path and is verify-only.
   Fix: P-256-specific field arithmetic (64-bit limbs with UMULH, fast reduction) - shareable with the
   constant-time P-256 ECDH being built by TlsProof.ApprovedMode.
2. First request after the handshake (as shipped, +35 to +39 ms on every HTTPS GET; Wolfram: 42.2-3.53, 42.3-3.52, 42.8-7.51): Nagle's algorithm.
   om/tls sends ChangeCipherSpec, Finished and the request as three separate small writes and never set
   TCP_NODELAY, so the request waited for the server's delayed ACK (strace, MEASURED earlier; get1k
   omega-asis 42.2 ms vs omega 3.53 ms on X925). Fixed by one setsockopt in tcp_open4; the bulk rows of
   omega-asis also contain this stall (the timer starts at the request write).
3. ChaCha20-Poly1305 bulk (Omega 0.17x of OpenSSL/rustls at 16 KiB records on X925): om/tls computes
   ChaCha20 and Poly1305 with scalar 32/64-bit code; OpenSSL, AWS-LC and ring use NEON vector code.
   [INFERENCE: library internals not profiled here.]
4. AES-128-GCM bulk (Omega 0.024x on X925): om/tls AES is bitsliced and GHASH is computed bit by bit,
   with no use of the AESE/AESMC/PMULL instructions this CPU has (/proc/cpuinfo: aes pmull). The other
   arms use them (OPENSSL_armcap=0xfd). Fix proposed to OmegaNext: crypto-extension host words
   (omeganext-crypto-hostwords.md), keeping the bitsliced path as reference and fallback.
5. 1 KiB records: the per-record cost (header, nonce, tag, one read per record) weighs more; the gap
   narrows for ChaCha (0.45-0.52x on X925) because the other arms also pay it.

Where Omega is ahead: peak memory. Omega's client process peaks at ~1.4 MiB against 3.1-4.3 MiB
(rustls) and 6.4 MiB (OpenSSL) for the same 1 MiB GET (MEASURED, whole process, see tables).
