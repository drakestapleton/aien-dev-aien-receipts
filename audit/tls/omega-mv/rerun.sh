#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Rerun the om/tls proof pack from scratch on an arm64 Linux host with git, gcc, python3 and openssl.
# Usage: sh rerun.sh [WORKDIR] [--bench]
#   1. reproducible build: two fresh clones of the tested commit, compiler and test binaries compared
#   2. every om/tls suite on the tested commit (unit suites, TLS, ACVP sample vectors)
#   3. the same on the draft branches (NODELAY + ACVP #844, FIPS self-tests #846, approved mode #847)
#   4. with --bench: the HTTPS benchmark (needs cargo for the rustls arm, about 20 min, pin cores first)
# Each step prints its suite's final line; compare them with the logs in this directory.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=${1:-$PWD/tls-proof-rerun}
url=https://github.com/aien-dev/omega-mv.git
tested=2d613b2d2f4650ae9b5a693b3fb4caffab0dea20
mkdir -p "$work"

echo "== 1. reproducible build at $tested"
sh "$here/repro/repro-build.sh" "$tested" "$url" "$work/repro"

suites() { # TREE: run every suite present in the tree, one at a time
	(cd "$1" && sh seed/omega-from-seed.sh >/dev/null && sha256sum -c seed/out/omc.sha256 >/dev/null)
	for s in sha2 x25519 chacha aesgcm ec rsa x509 ecdh drbg fips tls; do
		[ -f "$1/om/tls/test/$s/run.sh" ] || continue
		(cd "$1" && sh "om/tls/test/$s/run.sh" "$PWD/seed/out/omc" 2>&1 | tail -1)
	done
	if [ -f "$1/om/tls/test/acvp/run.sh" ]; then
		(cd "$1" && sh om/tls/test/acvp/run.sh "$PWD/seed/out/omc" 2>&1 | tail -1) || true
	fi
}

for ref in "$tested" audit/tls-proof audit/tls-fipsmodule audit/tls-approvedmode audit/tls-fips-approved; do
	d="$work/tree-$(echo "$ref" | tr / -)"
	[ -d "$d" ] || git clone -q "$url" "$d"
	git -C "$d" fetch -q origin "$ref" 2>/dev/null || true
	git -C "$d" checkout -q --detach "$( git -C "$d" rev-parse --verify -q "origin/$ref" || echo "$ref")"
	echo "== 2/3. suites at $ref ($(git -C "$d" rev-parse HEAD))"
	suites "$d"
done

if [ "${2:-}" = --bench ]; then
	echo "== 4. HTTPS benchmark (frozen protocol: bench/PROTOCOL.md; clients on cpus 16 and 2, server on 18)"
	b="$work/bench"; bin="$b/bin"; mkdir -p "$bin"
	sh "$here/bench/gen-certs.sh" "$b/www"
	t="$work/tree-audit-tls-proof"
	(cd "$t" && sh om/tls/build.sh "$PWD/seed/out/omc" om/tls/test/bench/bench.om "$bin/omega")
	a="$work/tree-asis"; [ -d "$a" ] || git clone -q "$url" "$a"
	git -C "$a" checkout -q --detach "$tested"
	cp "$t/om/tls/test/bench/bench.om" "$a/bench.om"
	(cd "$a" && sh seed/omega-from-seed.sh >/dev/null && sh om/tls/build.sh "$PWD/seed/out/omc" bench.om "$bin/omega-asis")
	gcc -O2 -o "$bin/openssl" "$here/bench/drivers/ossl_client.c" -lssl -lcrypto
	cargo build -q --release --manifest-path "$here/bench/drivers/rustls_client/Cargo.toml" --target-dir "$b/rtarget"
	cp "$b/rtarget/release/rustls_client" "$bin/rustls"
	python3 "$here/bench/run.py" "$bin" "$b/www" "$b/results" 30 16,2
	echo "Raw rows: $b/results/raw.jsonl. Statistics: bench/wolfram-*.wl, as RESULTS.md describes."
fi
