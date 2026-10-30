# emudhra-trust-store-check

Which trust stores and runtimes still accept a TLS chain through the eight eMudhra intermediate CA keys that anyone can recover, and what Debian's fix (removing two roots, one of them Comodo's AAA Certificate Services) does to the chains real servers send. Plus a read-only scanner for container images, virtualenvs and JDKs.

```bash
python3 scripts/scan-tree.py /path/to/unpacked/image-or-venv-or-jdk
```

To scan a container image without running it:

```bash
mkdir rootfs && docker export "$(docker create IMAGE)" | tar -xf - -C rootfs
python3 scripts/scan-tree.py rootfs
```

`scan-tree.py` is stdlib-only Python 3.9+. It reports PEM bundles and Java keystores that still hold `emSign ECC Root CA - G3` or `AAA Certificate Services`, binaries that embed either root (old Node.js and Bun builds), runtimes that carry the eMudhra SPKI blocklist, and Go programs and CPython `ssl` modules that do not carry it. Exit status 1 means something still trusts a chain. [`results/scan-tree-fixture.txt`](results/scan-tree-fixture.txt) is its output on a test tree.

Only public certificate files are used. Nothing here generates, uses or stores a private key.

## Reproduce the measurements

Each stage writes a file the next stage reads, so any stage can be re-run on its own.

```bash
python3 scripts/01_fetch_certs.py   # public certs + test chains; cross-checks vs Bugzilla, Go, Node, CPython
python3 scripts/02_fetch_stores.py  # trust stores in stores.tsv, from package files (no containers)
python3 scripts/03_inspect.py       # which root each store holds; predicts every verify result
python3 scripts/04_verify.py        # openssl verify, every chain x every store, vs the prediction
scripts/05_live.sh [old-node]       # real curl, python3 and node against the public test hosts
python3 scripts/06_scan_chains.py   # chains served by the Tranco top 20,000 (list PYK6J)
python3 scripts/07_aaa_impact.py    # those chains vs the Debian 12 bundle before/after the fix
python3 scripts/08_gnutls_check.py  # jisc.ac.uk + 20 strict-mode breaks with git (GnuTLS)
scripts/09_go_check.sh              # one HTTPS client built with Go 1.26.9 and 1.26.10
python3 scripts/aaa_trust_history.py # Mozilla's TLS trust for AAA and emSign G3 over time
```

Needs Python 3.9+, the OpenSSL 3 CLI, `zstd` (for one RPM), and for stage 7 a C compiler and the OpenSSL headers (`tools/chainverify.c`). Stage 2 downloads about 150 MB (three of them JREs) and stage 9 about 130 MB (two Go toolchains); raw downloads are deleted after use.

| Stage | Output |
| --- | --- |
| 01 | `results/01-certs.json` |
| 02 | `results/02-stores.json` (URL and SHA-256 of every download) |
| 03 | `results/03-inspect.json` |
| 04 | `results/04-verify.tsv`, `results/04-summary.json` |
| 05 | `results/05-live.tsv` |
| 06 | `results/06-chains.jsonl` |
| 07 | `results/07-aaa-impact.tsv`, `results/07-aaa-impact.json` |
| 08 | `results/08-gnutls.tsv` |
| 09 | `results/09-go.tsv`, `results/09-go-scan.txt` |

## What the recorded runs show

Recorded on 30 October 2026 from one Debian 12 machine (arm64, OpenSSL 3.0.22). The post that explains the results: https://devops-daily.com/posts/emudhra-ca-compromise-trust-stores-comodo-aaa

- **Stage 1.** The 16 intermediate certificates (8 keys, each eMudhra-issued and Sectigo-cross-signed) match the 16 SHA-256 fingerprints posted in the Mozilla bug. The Go, Node.js, CPython and Bun fixes compile in the same 8 SPKI hashes, so each blocks both certificates of every key.
- **Stages 3 and 4.** 34 trust stores plus one synthetic store, 16 test chains each: 560 `openssl verify` runs, 0 different from the prediction "accepts the emSign path if and only if it holds emSign ECC Root CA - G3, the Sectigo path if and only if it holds AAA Certificate Services". Before the fix, Debian 11/12/13, Ubuntu 24.04 (release pocket), Alpine 3.18 and OpenJDK's source `cacerts` held both roots; every other pre-fix store held only the emSign root, and every fixed store held neither. Debian 12's old bundle minus only the emSign root still accepted 8 of 8 Sectigo-path chains.
- **Stage 5.** 20 connections from curl 7.88.1, Python 3.11.2 and Node.js 24.22.0 and 24.22.1 to two public test hosts, all as predicted. Node.js 24.22.1 rejected both paths (`CERT_REVOKED`) even with the old Debian 12 bundle; 24.22.0 accepted both with it.
- **Stage 6.** Tranco list PYK6J top 20,000, one TLS connection each (or `www.`), IPv4, 30 October 11:11 to 11:36 UTC: 16,348 answered.
- **Stage 7.** Against Debian 12's bundle before and after the fix (Debian 13's are the same certificates): 16,125 chains verified before the fix with OpenSSL 3 defaults, and 1 failed after it (`jisc.ac.uk`, which sends only an AAA cross-sign of `SSL.com TLS Issuing ECC CA R2`). With trusted-first off, still 1. With trusted-first and alternative chains both off ("strict"), 262. 283 chains include a certificate issued by AAA; none was anchored at emSign ECC Root CA - G3; 47 were anchored at emSign Root CA - G1.
- **Stage 8.** git 2.39.5 (GnuTLS 3.7.9) agreed: `jisc.ac.uk` rejected after the fix, a seeded sample of 20 of the other 261 strict-mode breaks all still accepted.
- **Stage 9.** The same Go client built with Go 1.26.9 accepted both test chains with the old Debian 12 bundle; built with 1.26.10 it rejected both (`x509: no valid chains built`). Both failed on `jisc.ac.uk` with the fixed bundle. `scan-tree.py` flags the 1.26.9 binary and finds the blocklist in the 1.26.10 one.

- **Mozilla's data.** NSS builtins 2.74 (January 2025) trusts `Comodo AAA Services root` for server authentication; 2.76 (NSS 3.111, April 2025) does not. Debian's `20250419` bundle is built from 2.74 ([`results/aaa-trust-history.txt`](results/aaa-trust-history.txt)).

`STAMPS.sha256` holds the SHA-256 of the code, the inputs and every result file (`scripts/stamp.sh`).

## Sources

- Mozilla incident bug: https://bugzilla.mozilla.org/show_bug.cgi?id=2083449
- Test hosts, chains and patched-version list: https://emudhra.we-have-a-problem.com/ (Apache-2.0); stage 1 downloads `chains.zip`, `impacted-intermediates.json` and `roots.json` from there.
- Go fix: https://go.dev/issue/82345 (commit `7f86f957`), Node.js: nodejs/node `d9a3f3d1`, CPython: python/cpython `7dd8b473`, Bun: oven-sh/bun #46300
- OpenJDK guidance: https://openjdk.org/emudhra
- Apple: https://support.apple.com/en-us/149555

## License

MIT
