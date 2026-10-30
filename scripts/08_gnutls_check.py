#!/usr/bin/env python3
"""Stage 8: check the stage 7 "strict" breaks with a second real TLS stack.

Debian's git talks HTTPS through libcurl built against GnuTLS, which builds
certificate paths its own way. For jisc.ac.uk (the one modern-mode break) and
a seeded random sample of the strict-mode breaks, run

  git ls-remote https://<host>/

once with the Debian 12 bundle before the fix and once after it. A TLS
failure shows as "server certificate verification failed"; anything else
(404, "not found", a redirect, or a host name mismatch, which curl checks after the chain) means the certificate
chain was accepted. No credentials are sent.

Reads results/07-aaa-impact.tsv. Writes results/08-gnutls.tsv.
Usage: scripts/08_gnutls_check.py [sample-size] [seed]
"""

import os
import random
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def git(host, store):
    env = dict(os.environ, GIT_SSL_CAINFO=os.path.join("stores", store + ".pem"), GIT_SSL_CAPATH="/nonexistent",
               GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="/bin/false", HOME=os.path.join(ROOT, "work"))
    try:
        p = subprocess.run(["git", "-c", "credential.helper=", "ls-remote", f"https://{host}/"], env=env, cwd=ROOT,
                           capture_output=True, text=True, timeout=40)
        out = (p.stdout + p.stderr).strip().splitlines()
    except subprocess.TimeoutExpired:
        return "timeout", "timeout"
    text = " ".join(out)[:200]
    if "certificate verification failed" in text or "SSL certificate problem" in text:
        return "chain rejected", text
    if "Could not resolve" in text or "Failed to connect" in text or "timed out" in text:
        return "no connection", text
    return "chain ok", text


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 20261030
    lines = [l.rstrip("\n").split("\t") for l in open(os.path.join(ROOT, "results", "07-aaa-impact.tsv"))]
    h = {k: i for i, k in enumerate(lines[0])}
    rows = lines[1:]
    strict = sorted({r[h["host"]] for r in rows if r[h["before_strict"]] == "ok" and r[h["after_strict"]] != "ok"})
    modern = sorted({r[h["host"]] for r in rows if r[h["before_modern"]] == "ok" and r[h["after_modern"]] != "ok"})
    pool = [x for x in strict if x not in modern]
    sample = sorted(random.Random(seed).sample(pool, min(n, len(pool))))
    gv = subprocess.run(["git", "--version"], capture_output=True, text=True).stdout.strip()
    with open(os.path.join(ROOT, "results", "08-gnutls.tsv"), "w") as out:
        out.write(f"# {gv}; seed {seed}; the {len(modern)} modern-mode break(s), plus a sample of {len(sample)} "
                  f"from the {len(pool)} other strict-mode breaks\n")
        out.write("host\tgroup\tbefore_fix\tafter_fix\tafter_fix_output\n")
        for host in modern + sample:
            group = "modern-break" if host in modern else "strict-break"
            b, _ = git(host, "debian-12-before")
            a, at = git(host, "debian-12-fixed")
            out.write(f"{host}\t{group}\t{b}\t{a}\t{at}\n")
            print(f"{group:<13} {host:<40} before: {b:<13} after: {a}")


if __name__ == "__main__":
    main()
