#!/bin/sh
# Benchmark PKI: one ECDSA P-256 root (trust anchor) signs one ECDSA P-256 leaf for bench.test.
# Every client arm verifies the same chain against the same root.pem.
set -eu
d=${1:-www}; mkdir -p "$d"; cd "$d"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out root.key 2>/dev/null
openssl req -x509 -new -key root.key -subj /CN=tlsproof-bench-root -days 60 -sha256 \
  -addext basicConstraints=critical,CA:true -addext keyUsage=critical,keyCertSign,cRLSign -out root.pem
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out leaf.key 2>/dev/null
openssl req -new -key leaf.key -subj /CN=bench.test -addext subjectAltName=DNS:bench.test -out leaf.csr
printf 'basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:bench.test\n' > leaf.ext
openssl x509 -req -in leaf.csr -CA root.pem -CAkey root.key -CAcreateserial -days 30 -sha256 -extfile leaf.ext -out leaf.pem 2>/dev/null
# bodies: byte i = i mod 251
python3 - <<'PY'
for name, n in (("small.bin", 1024), ("1m.bin", 1 << 20), ("16m.bin", 16 << 20)):
    open(name, "wb").write(bytes(i % 251 for i in range(n)))
PY
sha256sum root.pem leaf.pem small.bin 1m.bin 16m.bin
