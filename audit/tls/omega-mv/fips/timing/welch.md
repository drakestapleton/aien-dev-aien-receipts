# Welch t-tests for the fips.om timing modes (dudect, fixed vs random class)

Binary: /tmp/tlsproof/fipsmodule/timing, sha256 0613f66e4961d03d2ac2b028b7895859b2e28d63cf941c7512fe47aed8711280
(built from om/tls/test/tls/timing.om with health-test cut-offs H = 7, i.e. FHRCT1 6 / FHAPT1 25;
the final code uses H = 6, FHRCT1 7 / FHAPT1 34. Only the two constants changed; fips_ht executes the
same instructions for every sample value, so the timing rows are expected to carry over — untested.)
Samples: *.txt in this directory, SHA256SUMS. N = 50000 (health, drbg), 20000 (pct).
Cores: cpu0 = Cortex-A725, cpu5 = Cortex-X925, pinned with taskset, nice -n 19.

Statistic computed in Wolfram from per-class (n, sum, sum of squares):
mv[{n_,s_,q_}]:={s/n,(q-s^2/n)/(n-1),n}; welch[a_,b_]:=(a[[1]]-b[[1]])/Sqrt[a[[2]]/a[[3]]+b[[2]]/b[[3]]]
"crop90" = samples above the pooled 90th percentile removed.

| run | full t | crop90 t | label |
|---|---|---|---|
| drbg-cpu0 | 1.13 | 1.07 (means 17866.7 vs 17865.6 ns) | MEASURED |
| drbg-cpu5 | 1.81 | -0.88 | MEASURED |
| health-cpu0 | 1.02 | 3.97 (means 1704.24 vs 1703.47 ns) | MEASURED |
| health-cpu0-run2 | -1.19 | 3.41 | MEASURED |
| health-cpu5 | -1.01 | 1.51 | MEASURED |
| pct-cpu0 | 0.03 | -0.15 | MEASURED |
| pct-cpu5 | 1.63 | -0.59 | MEASURED |

Every |t| < 4.5 (the dudect flag). The cropped health rows on cpu0 are positive in both runs
(under 1 ns of ~1700 ns): below the threshold, consistent in sign, not root-caused. A dudect pass is
evidence of no detected leak at this N, not a proof of constant time.
