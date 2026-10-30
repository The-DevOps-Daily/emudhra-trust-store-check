#!/usr/bin/env python3
"""Stage 4: verify every test chain against every trust store with the
OpenSSL CLI, and compare each result with the stage 3 prediction.

  openssl verify -no-CApath -no-CAstore -CAfile STORE -untrusted CHAIN \
                 -purpose sslserver -attime 1793318400 LEAF

-no-CApath/-no-CAstore keep the machine's own /etc/ssl/certs out of it.
-attime fixes the clock at 2026-10-30T00:00:00Z, inside every test leaf's
validity, so a re-run gives the same answer. No revocation checking: plain
`openssl verify`, curl, Python's ssl and most clients do not check CRLs.

One extra store is synthetic and labelled as such: debian-12-before with
only emSign ECC Root CA - G3 removed, the fix that is enough for stores
that never held AAA Certificate Services.

Reads results/01-certs.json, results/03-inspect.json, stores/*.pem.
Writes results/04-verify.tsv and results/04-summary.json.
"""

import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "lib"))
from x509lite import certs_from_pem, load_any  # noqa: E402

ATTIME = "1793318400"  # 2026-10-30T00:00:00Z
EMSIGN_G3_SPKI = "8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782"


def verify(store, chain, leaf):
    rel = [os.path.relpath(x, ROOT) for x in (store, chain, leaf)]
    p = subprocess.run(
        ["openssl", "verify", "-no-CApath", "-no-CAstore", "-CAfile", rel[0], "-untrusted", rel[1],
         "-purpose", "sslserver", "-attime", ATTIME, rel[2]],
        capture_output=True, text=True, cwd=ROOT)
    text = (p.stdout + p.stderr).strip().replace("\n", " | ")
    return p.returncode == 0 and ": OK" in p.stdout, text


def main():
    certs = json.load(open(os.path.join(ROOT, "results", "01-certs.json")))
    inspect = json.load(open(os.path.join(ROOT, "results", "03-inspect.json")))
    work = os.path.join(ROOT, "work")
    os.makedirs(work, exist_ok=True)

    synthetic = os.path.join(work, "debian-12-before-minus-emsign-g3.pem")
    with open(synthetic, "w") as f:
        for c in load_any(os.path.join(ROOT, "stores", "debian-12-before.pem")):
            if c.spki_sha256 != EMSIGN_G3_SPKI:
                f.write(c.pem())
    stores = {sid: os.path.join(ROOT, "stores", sid + ".pem") for sid in inspect}
    stores["SYNTHETIC-debian-12-before-minus-emsign-g3"] = synthetic

    leaves = {}
    for ch in certs["chains"]:
        path = os.path.join(ROOT, ch["file"])
        leaf = certs_from_pem(open(path, "rb").read())[0]
        lp = os.path.join(work, "leaf--" + os.path.basename(path))
        with open(lp, "w") as f:
            f.write(leaf.pem())
        leaves[ch["file"]] = (path, lp, ch["path"])

    rows, summary = [], {}
    for sid, spath in stores.items():
        acc = {"emsign": 0, "aaa": 0}
        tot = {"emsign": 0, "aaa": 0}
        mismatches = 0
        for cfile, (cpath, lpath, kind) in leaves.items():
            ok, text = verify(spath, cpath, lpath)
            if sid in inspect:
                pred = inspect[sid]["predictions"][cfile]
            else:  # synthetic store: AAA is still there, emSign G3 is not
                pred = kind == "aaa"
            mismatches += ok != pred
            tot[kind] += 1
            acc[kind] += ok
            rows.append([sid, os.path.basename(cfile), kind, "ACCEPT" if ok else "reject",
                         "ACCEPT" if pred else "reject", "match" if ok == pred else "MISMATCH", text])
        summary[sid] = {"emsign_path_accepted": f"{acc['emsign']}/{tot['emsign']}",
                        "aaa_path_accepted": f"{acc['aaa']}/{tot['aaa']}", "mismatches": mismatches}

    with open(os.path.join(ROOT, "results", "04-verify.tsv"), "w") as f:
        f.write("store\tchain\tpath\topenssl\tpredicted\tcompare\topenssl_output\n")
        for r in rows:
            f.write("\t".join(r) + "\n")
    with open(os.path.join(ROOT, "results", "04-summary.json"), "w") as f:
        json.dump(summary, f, indent=1)

    ver = subprocess.run(["openssl", "version"], capture_output=True, text=True).stdout.strip()
    print(f"{ver}; {len(rows)} verifications; mismatches with prediction: {sum(r[5] == 'MISMATCH' for r in rows)}")
    print(f"{'store':<44} emsign-path  aaa-path")
    for sid, s in summary.items():
        print(f"{sid:<44} {s['emsign_path_accepted']:>11}  {s['aaa_path_accepted']:>8}")


if __name__ == "__main__":
    main()
