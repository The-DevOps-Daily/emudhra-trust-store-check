#!/usr/bin/env bash
# Stage 9: build the same HTTPS client (tools/gotls) with Go 1.26.9 and
# Go 1.26.10, point both at the old Debian 12 bundle, and connect to the two
# public test hosts, and to jisc.ac.uk with the bundle before and after the
# fix. Then run scan-tree.py on both binaries.
#
# Each toolchain is downloaded to work/, checked against the SHA-256 that
# go.dev publishes, used once and deleted.
# Writes results/09-go.tsv and results/09-go-scan.txt.
set -eu
cd "$(dirname "$0")/.."
ARCH=$(uname -m); case "$ARCH" in aarch64) GOARCH=arm64 ;; x86_64) GOARCH=amd64 ;; *) echo "unsupported $ARCH"; exit 1 ;; esac
HOSTS="dv-g3b-emudhra.we-have-a-problem.com dv-g3b-aaa-emudhra.we-have-a-problem.com"
OUT=results/09-go.tsv
printf 'go\ttrust_source\thost\tresult\tdetail\n' > "$OUT"
for V in go1.26.9 go1.26.10; do
  T=work/$V.linux-$GOARCH.tar.gz
  SUM=$(curl -sS "https://go.dev/dl/?mode=json&include=all" | python3 -I -c "
import json,sys
for r in json.load(sys.stdin):
    if r['version']=='$V':
        for f in r['files']:
            if f['filename']=='$V.linux-$GOARCH.tar.gz': print(f['sha256'])")
  curl -sS -L -o "$T" "https://go.dev/dl/$V.linux-$GOARCH.tar.gz"
  echo "$SUM  $T" | sha256sum -c -
  rm -rf work/go && tar -xzf "$T" -C work && rm -f "$T"
  ( cd tools/gotls && env GOTOOLCHAIN=local GOCACHE="$PWD/../../work/gocache" GOPATH="$PWD/../../work/gopath" \
      CGO_ENABLED=0 GOFLAGS=-trimpath ../../work/go/bin/go build -o "../../work/gotls-$V" . )
  rm -rf work/go work/gocache
  for h in $HOSTS; do
    SSL_CERT_FILE=stores/debian-12-before.pem SSL_CERT_DIR=/nonexistent "work/gotls-$V" "$h" \
      | awk -F'\t' -v ts="SSL_CERT_FILE=stores/debian-12-before.pem" '{print $1"\t"ts"\t"$2"\t"$3"\t"$4}' | tee -a "$OUT"
  done
  # jisc.ac.uk sends only an AAA cross-sign of its intermediate (stage 7).
  for s in debian-12-before debian-12-fixed; do
    SSL_CERT_FILE=stores/$s.pem SSL_CERT_DIR=/nonexistent "work/gotls-$V" jisc.ac.uk \
      | awk -F'\t' -v ts="SSL_CERT_FILE=stores/$s.pem" '{print $1"\t"ts"\t"$2"\t"$3"\t"$4}' | tee -a "$OUT"
  done
done
( cd work && python3 -I ../scripts/scan-tree.py gotls-go1.26.9 gotls-go1.26.10 ) > results/09-go-scan.txt || true
cat results/09-go-scan.txt
