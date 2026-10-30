#!/usr/bin/env python3
"""Stage 6: record the certificate chain that real HTTPS servers send.

Takes the first N domains of a Tranco list (default: list PYK6J, created
2026-10-29, top 20,000), opens one TLS connection to <domain>:443 with
`openssl s_client -showcerts` (and to www.<domain> if that fails), and saves
the chain exactly as served. No HTTP request is sent. IPv4 only.

Writes work/chains/<domain>.pem (gitignored) and results/06-chains.jsonl,
one line per domain: the host that answered and, for each served
certificate, its subject, issuer and SHA-256.

Usage: scripts/06_scan_chains.py [N] [workers]
"""

import concurrent.futures as cf
import io
import json
import os
import subprocess
import sys
import time
import urllib.request
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "lib"))
from x509lite import certs_from_pem  # noqa: E402

TRANCO_ID = "PYK6J"


def domains(n):
    cache = os.path.join(ROOT, "work", f"tranco-{TRANCO_ID}.csv")
    if not os.path.exists(cache):
        url = f"https://tranco-list.eu/download/{TRANCO_ID}/1000000"
        data = urllib.request.urlopen(url, timeout=120).read()
        if data[:2] == b"PK":
            data = zipfile.ZipFile(io.BytesIO(data)).read(zipfile.ZipFile(io.BytesIO(data)).namelist()[0])
        with open(cache, "wb") as f:
            f.write(data)
    out = []
    for line in open(cache):
        rank, dom = line.strip().split(",")[:2]
        out.append((int(rank), dom))
        if len(out) >= n:
            break
    return out


def fetch(host):
    try:
        p = subprocess.run(
            ["openssl", "s_client", "-4", "-connect", f"{host}:443", "-servername", host, "-showcerts"],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=7)
    except subprocess.TimeoutExpired:
        return None
    certs = certs_from_pem(p.stdout)
    return certs or None


def scan(item):
    rank, dom = item
    for host in (dom, "www." + dom):
        certs = fetch(host)
        if certs:
            with open(os.path.join(ROOT, "work", "chains", dom + ".pem"), "w") as f:
                f.write("".join(c.pem() for c in certs))
            return {"rank": rank, "domain": dom, "host": host,
                    "chain": [{"subject": c.cn, "issuer": c.issuer_cn, "sha256": c.sha256,
                               "not_after": c.not_after} for c in certs]}
    return {"rank": rank, "domain": dom, "host": None, "chain": []}


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
    workers = int(sys.argv[2]) if len(sys.argv) > 2 else 12
    os.makedirs(os.path.join(ROOT, "work", "chains"), exist_ok=True)
    items = domains(n)
    out_path = os.path.join(ROOT, "results", "06-chains.jsonl")
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    done = 0
    with open(out_path, "w") as out, cf.ThreadPoolExecutor(workers) as ex:
        out.write(json.dumps({"tranco_list": TRANCO_ID, "top": n, "started": started}) + "\n")
        for res in ex.map(scan, items):
            out.write(json.dumps(res) + "\n")
            done += 1
            if done % 1000 == 0:
                out.flush()
                print(f"{done}/{n} at {time.strftime('%H:%M:%SZ', time.gmtime())}", flush=True)
        out.write(json.dumps({"finished": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}) + "\n")
    print("done")


if __name__ == "__main__":
    main()
