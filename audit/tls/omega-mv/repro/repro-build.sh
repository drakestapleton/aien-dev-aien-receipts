#!/bin/sh
# Reproducible-build check for the Omega TLS client (host tooling; runs no network beyond git clone).
# usage: sh repro-build.sh SHA [REPO_URL] [OUTDIR]
# Clones omega-mv at SHA into two fresh directories with different paths, births omc from seed-0 in
# each (seed/omega-from-seed.sh: seed0 hex -> ... -> omc stage2 == stage3), checks the result against
# the committed seed/out/omc.sha256, then compiles every om/tls test driver with om/tls/build.sh in
# each tree. PASS only if every artifact is byte-identical across the two trees and omc equals the
# committed digest. Writes OUTDIR/hashes.txt (sha256 per artifact per tree) and prints PASS/FAIL.
set -eu
sha=${1:?usage: repro-build.sh SHA [REPO_URL] [OUTDIR]}
url=${2:-https://github.com/aien-dev/omega-mv.git}
out=${3:-$(pwd)/repro-out}
mkdir -p "$out"; : > "$out/hashes.txt"
work=$(mktemp -d "${TMPDIR:-/tmp}/omrepro.XXXXXX")
fail=0
for t in A longer-path-B; do
  d="$work/$t/omega-mv"
  git clone -q --filter=blob:none --no-checkout "$url" "$d"
  git -C "$d" checkout -q "$sha"
  (cd "$d" && nice -n 19 sh seed/omega-from-seed.sh) > "$out/birth-$t.log" 2>&1 || { echo "FAIL birth $t" >&2; fail=1; }
  want=$(git -C "$d" show "$sha:seed/out/omc.sha256" | cut -d' ' -f1)
  got=$(sha256sum "$d/seed/out/omc" | cut -d' ' -f1)
  echo "$t omc $got committed=$want" >> "$out/hashes.txt"
  [ "$got" = "$want" ] || { echo "FAIL omc $t $got != committed $want" >&2; fail=1; }
  for drv in "$d"/om/tls/test/*/driver.om "$d"/om/tls/test/tls/client.om; do
    n=$(basename "$(dirname "$drv")")
    [ "$n" = tls ] && n=tls-client
    (cd "$d" && nice -n 19 sh om/tls/build.sh seed/out/omc "${drv#$d/}" "$work/$t/$n.bin") \
      > /dev/null 2>&1 || { echo "FAIL build $t $n" >&2; fail=1; continue; }
    echo "$t $n $(sha256sum < "$work/$t/$n.bin" | cut -d' ' -f1)" >> "$out/hashes.txt"
  done
done
# every artifact must have the same digest in both trees
for n in $(awk '$1=="A"{print $2}' "$out/hashes.txt"); do
  a=$(awk -v n="$n" '$1=="A" && $2==n {print $3}' "$out/hashes.txt")
  b=$(awk -v n="$n" '$1=="longer-path-B" && $2==n {print $3}' "$out/hashes.txt")
  if [ "$a" = "$b" ]; then echo "SAME $n $a"; else echo "DIFF $n A=$a B=$b"; fail=1; fi
done | tee "$out/compare.txt"
grep -q DIFF "$out/compare.txt" && fail=1
rm -rf "$work"
[ "$fail" = 0 ] && echo "PASS reproducible build at $sha" || { echo "FAIL reproducible build at $sha"; exit 1; }
