#!/usr/bin/env python3
"""Stage 7: what does Debian's fix (removing AAA Certificate Services and
emSign ECC Root CA - G3) do to the chains real servers send?

Verifies every chain saved by stage 6 against the Debian 12 bundle before
the fix and after it, in the three path-building modes of tools/chainverify.c,
at the moment the scan started. A chain "breaks" in a mode when it verified
before the fix and fails after it. Each break is attributed to the root the
chain was anchored at before the fix.

Reads results/06-chains.jsonl, work/chains/, stores/debian-12-*.pem.
Writes results/07-aaa-impact.tsv (one row per domain that answered) and
results/07-aaa-impact.json (the counts).
"""

import calendar
import json
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "work", "chainverify")
MODES = ["modern", "nofirst", "strict"]
BEFORE, AFTER = "debian-12-before", "debian-12-fixed"
SECTIGO = re.compile(r"Sectigo|COMODO|Comodo|USERTrust|USERTRUST|AAA Certificate Services")


def build():
    src = os.path.join(ROOT, "tools", "chainverify.c")
    if not os.path.exists(BIN) or os.path.getmtime(BIN) < os.path.getmtime(src):
        subprocess.run(["cc", "-O2", "-o", BIN, src, "-lcrypto"], check=True)


def run(store, files, epoch):
    p = subprocess.run([BIN, os.path.join("stores", store + ".pem"), str(epoch)],
                       input="\n".join(files) + "\n", capture_output=True, text=True, check=True, cwd=ROOT)
    out = {}
    for line in p.stdout.splitlines():
        f = line.split("\t")
        out[f[0]] = {m: {"ok": f[1 + 2 * i] == "ok", "result": f[1 + 2 * i], "anchor": f[2 + 2 * i]}
                     for i, m in enumerate(MODES)}
    return out


def main():
    build()
    lines = [json.loads(l) for l in open(os.path.join(ROOT, "results", "06-chains.jsonl"))]
    header = lines[0]
    epoch = calendar.timegm(time.strptime(header["started"], "%Y-%m-%dT%H:%M:%SZ"))
    rows = [r for r in lines if "rank" in r and r["host"]]
    files = {os.path.join("work", "chains", r["domain"] + ".pem"): r for r in rows}
    before = run(BEFORE, list(files), epoch)
    after = run(AFTER, list(files), epoch)

    counts = {"tranco_list": header["tranco_list"], "top": header["top"], "scan_started": header["started"],
              "scan_finished": lines[-1].get("finished"), "verified_at_epoch": epoch,
              "domains": header["top"], "answered": len(rows)}
    sect = [f for f, r in files.items() if any(SECTIGO.search(c["subject"] + " " + c["issuer"]) for c in r["chain"])]
    aaa_issued = [f for f, r in files.items() if any(c["issuer"] == "AAA Certificate Services" for c in r["chain"])]
    counts["sectigo_family_chains"] = len(sect)
    counts["chains_with_a_cert_issued_by_AAA"] = len(aaa_issued)
    per_mode = {}
    breaks = {m: [] for m in MODES}
    for m in MODES:
        ok_before = [f for f in files if before[f][m]["ok"]]
        anchored_aaa = [f for f in ok_before if before[f][m]["anchor"] == "AAA Certificate Services"]
        for f in ok_before:
            if not after[f][m]["ok"]:
                breaks[m].append(f)
        attributed = {}
        for f in breaks[m]:
            a = before[f][m]["anchor"]
            attributed[a] = attributed.get(a, 0) + 1
        per_mode[m] = {"verified_before_fix": len(ok_before),
                       "anchored_at_AAA_before_fix": len(anchored_aaa),
                       "break_after_fix": len(breaks[m]),
                       "breaks_by_anchor_before_fix": attributed,
                       "sectigo_family_verified_before_fix": sum(1 for f in sect if before[f][m]["ok"]),
                       "sectigo_family_break_after_fix": sum(1 for f in sect if f in breaks[m])}
    counts["modes"] = per_mode

    with open(os.path.join(ROOT, "results", "07-aaa-impact.tsv"), "w") as out:
        out.write("rank\tdomain\thost\tsectigo_family\tcert_issued_by_AAA\tserved_chain\t"
                  + "\t".join(f"{s}_{m}" for s in ("before", "after") for m in MODES) + "\t"
                  + "\t".join(f"anchor_before_{m}" for m in MODES) + "\n")
        for f, r in sorted(files.items(), key=lambda x: x[1]["rank"]):
            served = " > ".join(c["subject"] for c in r["chain"]) + " > [" + r["chain"][-1]["issuer"] + "]"
            cells = [str(r["rank"]), r["domain"], r["host"], str(f in sect), str(f in aaa_issued), served]
            cells += [before[f][m]["result"] for m in MODES] + [after[f][m]["result"] for m in MODES]
            cells += [before[f][m]["anchor"] for m in MODES]
            out.write("\t".join(cells) + "\n")
    counts["break_examples"] = {m: [files[f]["domain"] for f in sorted(breaks[m], key=lambda x: files[x]["rank"])[:25]]
                                for m in MODES}
    with open(os.path.join(ROOT, "results", "07-aaa-impact.json"), "w") as f:
        json.dump(counts, f, indent=1)

    print(f"Tranco {counts['tranco_list']} top {counts['top']}: {counts['answered']} answered; "
          f"{len(sect)} Sectigo-family chains; {len(aaa_issued)} send a certificate issued by AAA")
    for m in MODES:
        pm = per_mode[m]
        print(f"{m:<8} verified before fix {pm['verified_before_fix']:>6}  anchored at AAA {pm['anchored_at_AAA_before_fix']:>5}  "
              f"break after fix {pm['break_after_fix']:>4}  by anchor {pm['breaks_by_anchor_before_fix']}")


if __name__ == "__main__":
    main()
