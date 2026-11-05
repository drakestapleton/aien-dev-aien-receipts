# dudect-style Welch t-test, om/tls/ecdh.om P-256 ecdh_shared — MEASURED host-only (DGX Spark GB10)

Driver: om/tls/test/tls/timing.om `ecdh` class (branch audit/tls-approvedmode), compiled with omc
sha256 2c824805…029f into timing.bin (sha in SHA256SUMS). Peer point fixed (7*G); class 0 = fixed
scalar (tm_fill pattern), class 1 = random scalar; both classes call getrandom before the timed
window. Run: `nice -n 19 taskset -c 5 ./timing.bin ecdh 20000 > cpu5-ecdh.txt` (Cortex-X925) and
`nice -n 19 taskset -c 0 ./timing.bin ecdh 20000 > cpu0-ecdh.txt` (Cortex-A725, core map per
TlsAudit/evidence/timing/welch.md). The cpu0 run overlapped this branch's om/tls/test/tls/run.sh and
other agents' jobs (host not quiet), which widens the full-sample spread.
Python only counted (n, sum x, sum x^2) per class, full and cropped at the pooled 90th percentile
(sums.json); Wolfram computed means (ns), variances and t:

WolframLanguageEvaluator welch[{n0,s0,q0},{n1,s1,q1}] (means and Welch t, sums from sums.json) ->
cpu0 full   {5.62932e6, 5.68063e6, -0.204}   crop90 {4.23012e6, 4.23033e6, -0.252}
cpu5 full   {2.28797e6, 2.27442e6,  0.796}   crop90 {1.98752e6, 1.98165e6,  0.647}

Reading: every |t| < 1 (dudect flag |t| > 4.5): no evidence at 20000 samples per core that the
P-256 shared-secret time depends on the private scalar on this host. MEASURED on one host under
load; not a proof, not a hardware qualification. P-384 was not run through dudect (NOT_RUN); it
shares the ladder and field code with P-256 (ecdh.om), only the limb count differs.
