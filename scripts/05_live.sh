#!/usr/bin/env bash
# Stage 5: connect real clients to two of the public test hosts run for this
# incident (https://emudhra.we-have-a-problem.com/) and record whether each
# client accepts the chain. One host serves the emSign path, one the Sectigo
# AAA path; both leaves are signed with the compromised DV G3B key by the
# tracker's operators. We send one HEAD-sized GET per case and a distinct
# User-Agent, so the tracker's statistics can tell these runs apart.
#
# Usage: scripts/05_live.sh [path-to-an-older-node]
# Needs: curl, python3, node; stores/ from stage 2.
# Writes results/05-live.tsv.
set -u
cd "$(dirname "$0")/.."
OLD_NODE="${1:-}"
UA="emudhra-trust-store-check/1.0 (+https://github.com/The-DevOps-Daily/emudhra-trust-store-check)"
OUT=results/05-live.tsv
HOSTS="dv-g3b-emudhra.we-have-a-problem.com dv-g3b-aaa-emudhra.we-have-a-problem.com"
printf 'client\tversion\ttrust_source\thost\tresult\tdetail\n' > "$OUT"

row() { printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$@" | tee -a "$OUT"; }

curl_case() { # store
  local v; v=$(curl --version | head -1 | cut -d' ' -f2)
  for h in $HOSTS; do
    local err code
    code=$(curl -sS -o /dev/null -A "$UA" --max-time 20 -w '%{http_code}' \
      --cacert "stores/$1.pem" --capath /nonexistent "https://$h/" 2>/tmp/em-curl-err.$$) \
      && row curl "$v" "--cacert stores/$1.pem" "$h" ACCEPT "HTTP $code" \
      || { err=$(tr '\n' ' ' < /tmp/em-curl-err.$$); row curl "$v" "--cacert stores/$1.pem" "$h" reject "$err"; }
  done
  rm -f /tmp/em-curl-err.$$
}

python_case() { # store
  for h in $HOSTS; do
    python3 -I - "$h" "stores/$1.pem" "$UA" <<'EOF' | while IFS=$'\t' read -r res det; do row python3 "$(python3 -I -c 'import platform,ssl;print(platform.python_version()+" "+ssl.OPENSSL_VERSION.split()[1])')" "cafile=stores/$1.pem" "$h" "$res" "$det"; done
import ssl, sys, urllib.request
host, cafile, ua = sys.argv[1:4]
ctx = ssl.create_default_context(cafile=cafile)
try:
    r = urllib.request.urlopen(urllib.request.Request(f"https://{host}/", headers={"User-Agent": ua}), context=ctx, timeout=20)
    print(f"ACCEPT\tHTTP {r.status}")
except Exception as e:
    print(f"reject\t{type(e).__name__}: {getattr(e, 'reason', e)}")
EOF
  done
}

node_case() { # node-binary label [store]
  local bin=$1 label=$2 store=${3:-}
  local ver; ver=$("$bin" --version)
  for h in $HOSTS; do
    local res
    if [ -n "$store" ]; then
      res=$(SSL_CERT_FILE="stores/$store.pem" SSL_CERT_DIR=/nonexistent "$bin" --use-openssl-ca -e "$NODE_JS" "$h" "$UA")
      label="--use-openssl-ca, SSL_CERT_FILE=stores/$store.pem"
    else
      res=$("$bin" -e "$NODE_JS" "$h" "$UA")
    fi
    row node "$ver" "$label" "$h" "${res%%$'\t'*}" "${res#*$'\t'}"
  done
}

NODE_JS='
const https = require("https");
const [host, ua] = process.argv.slice(1);
const req = https.get({ host, path: "/", headers: { "User-Agent": ua }, timeout: 20000 }, (r) => {
  console.log(`ACCEPT\tHTTP ${r.statusCode}`); r.resume(); });
req.on("error", (e) => console.log(`reject\t${e.code}: ${e.message}`));
'

curl_case debian-12-before
curl_case debian-12-fixed
curl_case ubuntu-24.04-before
python_case debian-12-before
python_case certifi-2026.7.22
python_case certifi-2026.10.19
node_case node "bundled roots (default)"
node_case node "" debian-12-before
if [ -n "$OLD_NODE" ]; then
  node_case "$OLD_NODE" "bundled roots (default)"
  node_case "$OLD_NODE" "" debian-12-before
fi
