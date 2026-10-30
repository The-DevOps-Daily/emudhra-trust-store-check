#!/usr/bin/env python3
"""Stage 1: fetch the public eMudhra certificates and cross-check them.

Downloads the impacted intermediates, the roots they chain to and the test
chains from the tracker at emudhra.we-have-a-problem.com (Apache-2.0), then
checks every certificate against two independent sources:

  * the SHA-256 fingerprints posted in Mozilla bug 2083449 (comments 0 and 2)
  * the SPKI blocklists that Go, Node.js and CPython compiled into their fixes

Only public certificate files are used. Nothing here touches a private key.

Writes certs/ (gitignored) and results/01-certs.json.
"""

import hashlib
import io
import json
import os
import re
import sys
import urllib.request
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "lib"))
from x509lite import Cert, certs_from_pem  # noqa: E402

TRACKER = "https://emudhra.we-have-a-problem.com/"
SOURCES = {
    "impacted": TRACKER + "impacted-intermediates.json",
    "roots": TRACKER + "roots.json",
    "chains": TRACKER + "chains.zip",
    "bugzilla": "https://bugzilla.mozilla.org/rest/bug/2083449/comment",
    # The fix commits, pinned by hash.
    "go": "https://raw.githubusercontent.com/golang/go/7f86f957633ee31a1c17a1eb8452ca7a3d9bc141/src/crypto/x509/verify.go",
    "node": "https://raw.githubusercontent.com/nodejs/node/d9a3f3d150f7959f2d448d9a61aa11f5a75aa2b3/src/crypto/crypto_context.cc",
    "cpython": "https://raw.githubusercontent.com/python/cpython/7dd8b4736a1419750b94a388e6d158be15836fe6/Modules/_ssl/distrusted_spki.h",
    "bun": "https://raw.githubusercontent.com/oven-sh/bun/bun-v1.4.4/packages/bun-usockets/src/crypto/blocked_spkis.cpp",
}
UA = "emudhra-trust-store-check/1.0 (+https://github.com/The-DevOps-Daily/emudhra-trust-store-check)"


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def hexes(text, pattern=r"\b[0-9a-fA-F]{64}\b"):
    return {h.lower() for h in re.findall(pattern, text)}


def c_byte_arrays(text):
    """32-byte arrays written as {0x49, 0xdd, ...} in C source."""
    out = set()
    for block in re.findall(r"\{((?:\s*0x[0-9a-fA-F]{2}\s*,?){32})\s*\}", text):
        out.add("".join(b[2:] for b in re.findall(r"0x[0-9a-fA-F]{2}", block)).lower())
    return out


def main():
    os.makedirs(os.path.join(ROOT, "certs", "chains"), exist_ok=True)
    os.makedirs(os.path.join(ROOT, "results"), exist_ok=True)
    raw = {k: get(u) for k, u in SOURCES.items()}
    record = {"sources": {k: {"url": SOURCES[k], "sha256": hashlib.sha256(v).hexdigest()} for k, v in raw.items()}}

    impacted = json.loads(raw["impacted"])
    roots = json.loads(raw["roots"])

    # Bugzilla: the fingerprints Mozilla (comment 0) and the reporter
    # (comment 2, the Sectigo cross-signs) posted.
    comments = json.loads(raw["bugzilla"])["bugs"]["2083449"]["comments"]
    bz = {}
    for c in comments:
        if c["count"] in (0, 2):
            for name, fp in re.findall(r"(EM [A-Z]{2} (?:TLS|CS) CA - G3[BC])[^\n]*\nSHA-256 ([0-9A-F]{64})", c["text"]):
                bz.setdefault(fp.lower(), name)

    go = hexes(raw["go"].decode())
    node = c_byte_arrays(raw["node"].decode())
    cpy = c_byte_arrays(raw["cpython"].decode()) | hexes(raw["cpython"].decode())
    bun = c_byte_arrays(raw["bun"].decode())

    rows = []
    for item in impacted:
        cert = certs_from_pem(item["pem"].encode())[0]
        assert cert.sha256 == item["sha256"].lower(), item["name"]
        assert cert.spki_sha256 == item["spki_sha256"].lower(), item["name"]
        kind = "aaa" if item["issued_by"] == "AAA Certificate Services" else "emsign"
        fname = f"{item['name'].replace(' ', '-').replace('---', '-')}--{kind}.pem"
        with open(os.path.join(ROOT, "certs", fname), "w") as f:
            f.write(cert.pem())
        rows.append({
            "file": fname,
            "name": item["name"],
            "usage": item["usage"],
            "issuer": cert.issuer_cn,
            "sha256": cert.sha256,
            "spki_sha256": cert.spki_sha256,
            "not_before": cert.not_before,
            "not_after": cert.not_after,
            "in_bugzilla": cert.sha256 in bz,
            "blocked_by_go": cert.spki_sha256 in go,
            "blocked_by_node": cert.spki_sha256 in node,
            "blocked_by_cpython": cert.spki_sha256 in cpy,
            "blocked_by_bun": cert.spki_sha256 in bun,
        })

    root_rows = []
    for r in roots:
        cert = certs_from_pem(r["pem"].encode())[0]
        assert cert.sha256 == r["sha256"].lower(), r["name"]
        fname = "root--" + r["name"].replace(" ", "-").replace("---", "-") + ".pem"
        with open(os.path.join(ROOT, "certs", fname), "w") as f:
            f.write(cert.pem())
        root_rows.append({"file": fname, "name": r["name"], "role": r["role"], "sha256": cert.sha256,
                          "spki_sha256": cert.spki_sha256, "root_store_status": r["root_store_status"]})

    z = zipfile.ZipFile(io.BytesIO(raw["chains"]))
    chain_rows = []
    for n in sorted(z.namelist()):
        if not n.endswith(".pem"):
            continue
        data = z.read(n)
        certs = certs_from_pem(data)
        group = n.split("/")[1]
        out = os.path.join(ROOT, "certs", "chains", f"{group}--{os.path.basename(n)}")
        with open(out, "wb") as f:
            f.write(data)
        chain_rows.append({
            "file": os.path.relpath(out, ROOT),
            "group": group,
            "path": "aaa" if "-aaa-" in n else "emsign",
            "certs": [{"cn": c.cn, "issuer": c.issuer_cn, "spki_sha256": c.spki_sha256} for c in certs],
            "leaf_not_after": certs[0].not_after,
            "contains_blocked_spki": any(c.spki_sha256 in go for c in certs),
        })

    record.update({
        "intermediates": rows,
        "roots": root_rows,
        "chains": chain_rows,
        "bugzilla_fingerprints": len(bz),
        "go_entries": len(go),
        "node_entries": len(node),
        "cpython_entries": len(cpy),
        "bun_entries": len(bun),
        "same_list_go_node_cpython_bun": go == node == cpy == bun,
    })
    with open(os.path.join(ROOT, "results", "01-certs.json"), "w") as f:
        json.dump(record, f, indent=1)

    print(f"intermediate certificates: {len(rows)} ({sum(r['usage'] == 'tls' for r in rows)} TLS)")
    print(f"  matched to a Bugzilla fingerprint: {sum(r['in_bugzilla'] for r in rows)} of {len(rows)} ({len(bz)} fingerprints posted)")
    print(f"  distinct keys (SPKI): {len({r['spki_sha256'] for r in rows})}")
    for k in ("go", "node", "cpython", "bun"):
        print(f"  covered by the {k} blocklist: {sum(r['blocked_by_' + k] for r in rows)} of {len(rows)}")
    print(f"Go, Node.js, CPython and Bun block the same {len(go)} SPKIs: {go == node == cpy == bun}")
    print(f"test chains: {len(chain_rows)}, every one contains a blocked key: {all(c['contains_blocked_spki'] for c in chain_rows)}")


if __name__ == "__main__":
    main()
