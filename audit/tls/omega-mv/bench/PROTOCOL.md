# TlsProof HTTPS benchmark protocol (frozen before any timed sample)

## Question
How fast is the Omega TLS 1.3 client (om/tls, omega-mv PR #833 head 2d613b2d + one change below) against
widely used TLS 1.3 clients, doing the same work on the same machine?

## Arms (clients; every arm talks to the same server)
| arm | what | build |
|---|---|---|
| omega | om/tls/test/bench/bench.om, om/tls at 2d613b2d plus TCP_NODELAY in tcp_open4 | omc 2c824805 via om/tls/build.sh |
| omega-asis | the same program on om/tls exactly at 2d613b2d (no TCP_NODELAY) | same |
| openssl | drivers/ossl_client.c, system OpenSSL 3.0.13 (Ubuntu 3.0.13-0ubuntu3.16), gcc -O2 | throwaway host tool |
| rustls-awslc | drivers/rustls_client, rustls 0.23.42 + aws-lc-rs (AWS-LC, the BoringSSL-derived library) | cargo --release |
| rustls-ring | the same binary, ring 0.17 provider | cargo --release |

There is no Omega TLS server (om/tls is client-only: ECDSA/RSA verify, no signing), so the
server is fixed for every arm: `openssl s_server -WWW -tls1_3 -no_ticket -groups X25519` with one
cipher suite each, pinned to cpu 18 (X925). Only the client changes between arms.

## Matched settings
- TLS 1.3 only. Every client offers CHACHA20_POLY1305 then AES_128_GCM (the Omega offer); the server
  allows exactly one suite, so the suite is the server's: run S1 = TLS_CHACHA20_POLY1305_SHA256,
  run S2 = TLS_AES_128_GCM_SHA256.
- Key exchange X25519 only (offered and accepted). Server cert: ECDSA P-256 leaf for bench.test
  signed by one ECDSA P-256 root; every client verifies chain + hostname against that root only.
- No resumption: server `-no_ticket`, clients have no session cache; every connection is a full
  handshake. One connection per request (HTTP/1.0, server closes with close_notify).
- Record size: server default 16384-byte records; the 1 KiB rows use `-max_send_frag 1024`.
- Loopback 127.0.0.1. Client pinned with taskset to cpu 16 (X925) or cpu 2 (A725); server on cpu 18.
  Everything runs under ~/.local/bin/quiet-measure (the machine's quiet lock).

## Workloads (one client process per cell; first W samples of each process discarded as warm-up)
| id | command | samples/process | warm-up | metric per process |
|---|---|---|---|---|
| hs | handshake: TCP connect + full handshake, then close_notify | 40 | 5 | median ns of handshake |
| get1k | HTTPS GET of a 1024-byte body (connect..last byte) | 20 | 3 | median ns |
| get1m | HTTPS GET of a 1 MiB body | 8 | 2 | median ns |
| bulk16k | 16 MiB body, 16384-byte records, timed from request write to last byte (no handshake) | 3 | 1 | median MB/s (bytes/ns*1000) |
| bulk1k | 16 MiB body, 1024-byte records, same timing | 3 | 1 | median MB/s |
Each process also reports ru_maxrss (peak RSS) and user+system CPU (wait4).

## Design
- Rounds R = 30 per (cpu, suite). In every round the order of the 5 arms is shuffled (seeded
  random.Random(round_seed)); each arm runs all 5 workloads back to back. Interleaving spreads
  machine drift over all arms.
- Correctness gate before timing, per (arm, suite): mode d of 1m.bin and 16m.bin (1 KiB records) is
  hashed; body sha256 must equal the file's sha256. Any failing arm is excluded and reported.
- Any client exit != 0 during the timed run: that cell is recorded as FAIL, never dropped silently;
  the count of failures per cell is published.

## Statistics (Wolfram)
- Per cell: median of the 30 round metrics and its distribution-free 95% CI from order statistics
  (binomial, Wolfram). Ratio: paired per-round ratio omega/arm; for times > 1 means Omega slower,
  for MB/s < 1 means Omega slower. Median ratio with the same order-statistic CI.
- No verdict threshold: this is a descriptive comparison. A difference is called "clear" only when the
  ratio CI excludes 1.
- X925 (cpu 16) and A725 (cpu 2) reported separately. Handshake and bulk reported separately.
- The machine is shared (load ~24 on 20 cpus at freeze time); /proc/loadavg and per-cpu busy time of
  cpus 16, 2 and 18 are logged per round and published. Numbers are labelled "shared machine".
