#!/usr/bin/env python3
"""Find what still trusts the compromised eMudhra intermediates in a
directory tree: an unpacked container image, a virtualenv, a JDK, a build
output directory, or single files.

It reports:
  * CA bundles (PEM files, Java keystores) that still hold
    emSign ECC Root CA - G3 or AAA Certificate Services, the two roots the
    six compromised TLS keys chain to;
  * binaries and shared libraries that embed either root (old Node.js and
    Bun builds, Go programs built with an old x509roots/fallback);
  * runtimes that carry the SPKI blocklist the fixed Go, Node.js, Bun and
    CPython releases compile in, so they reject the keys whatever the
    trust store says;
  * Go binaries that link crypto/x509 without that blocklist.

Read only. Stdlib only. Exit status 1 if anything still trusts a chain.

Usage:
  python3 scan-tree.py PATH [PATH ...]
  docker export $(docker create IMAGE) | tar -xf - -C rootfs && python3 scan-tree.py rootfs
"""

import base64
import mmap
import os
import stat
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "lib"))
from x509lite import Cert, load_any  # noqa: E402

ROOTS = {
    "emSign ECC Root CA - G3": (
        "8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782",
        "MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQGEwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0gRzMwHhcNMTgwMjE4MTgzMDAwWhcNNDMwMjE4MTgzMDAwWjBrMQswCQYDVQQGEwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0gRzMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQjpQy4LRL1KPOxst3iAhKAnjlfSU2fySU0WXTsuwYc58Byr+iuL+FBVIcUqEqy6HyC5ltqtdyzdc6LBtCGI79G1Y4PPwT01xySfvalY8L1X44uT6EYGQIrMgqCZH0Wk9GjQjBAMB0GA1UdDgQWBBR8XQKEE9TMipuBzhccLikenEhjQjAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAwNpADBmAjEAvvNhzwIQHWSVB7gYboiFBS+DCBeQyh+KTOgNG3qxrdWBCUfvO6wIBHxcmbHtRwfSAjEAnbpV/KlK6O3t5nYBQnvI+GDZjVGLVTv7jHvrZQnD+JbNR6iC8hZVdyR+EhCVBCyj",
    ),
    "AAA Certificate Services": (
        "bd153ed7b0434f6886b17bce8bbe84ed340c7132d702a8f4fa318f756ecbd6f3",
        "MIIEMjCCAxqgAwIBAgIBATANBgkqhkiG9w0BAQUFADB7MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UEAwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTA0MDEwMTAwMDAwMFoXDTI4MTIzMTIzNTk1OVowezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNVBAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL5AnfRu4ep2hxxNRUSOvkbIgwadwSr+GB+O5AL686tdUIoWMQuaBtDFcCLNSS1UY8y2bmhGC1Pqy0wkwLxyTurxFa70VJoSCsN6sjNg4tqJVfMiWPPe3M/vg4aijJRPn2jymJBGhCfHdr/jzDUsi14HZGWCwEiwqJH5YZ92IFCokcdmtet4YgNW8IoaE+oxox6gmf049vYnMlhvB/VruPsUK6+3qszWY19zjNoFmag4qMsXeDZRrOme9Hg6jc8P2ULimAyrL58OAd7vn5lJ8S3frHRNG5i1R8XlKdH5kBjHYpy+g8cmez6KJcfA3Z3mNWgQIJ2P2N7Sw4ScDV7oL8kCAwEAAaOBwDCBvTAdBgNVHQ4EFgQUoBEKIz6W8Qfs4q8p74Klf9AwpLQwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wewYDVR0fBHQwcjA4oDagNIYyaHR0cDovL2NybC5jb21vZG9jYS5jb20vQUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNqA0oDKGMGh0dHA6Ly9jcmwuY29tb2RvLm5ldC9BQUFDZXJ0aWZpY2F0ZVNlcnZpY2VzLmNybDANBgkqhkiG9w0BAQUFAAOCAQEACFb8AvCb6P+k+tZ7xkSAzk/ExfYAWMymtrwUSWgEdujm7l3sAg9g1o1QGE8mTgHj5rCl7r+8dFRBv/38ErjHT1r0iWAFf2C3BUrz9vHCv8S5dIa2LX1rzNLzRt0vxuBqw8M0Ayx9lt1awg6nCpnBBYurDC/zXDrPbDdVCYfeU0BsWO/8tqtlbgT2G9w84FoVxp7Z8VlIMCFlA2zs6SFz7JsDoeA3raAVGI/6ugLOpyypEBMs1OUIJqsil2D4kF501KKaU73yqWjgom7C12yxow+ev+to51byrvLjKzg6CYG1a4XXvi3tPxq3smPi9WIsgtRqAEFQ8TmDn5XpNpaYbg==",
    ),
}
# SHA-256 of the SubjectPublicKeyInfo of the eight compromised keys, the
# list Go 1.26.10, Node.js 24.22.1, Bun 1.4.4 and CPython 3.14.10 compile in.
BLOCKED_SPKI = [
    "ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105",
    "49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f",
    "e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41",
    "5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0",
    "43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b",
    "63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8",
    "ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6",
    "92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30",
]
SKIP_DIRS = {"proc", "sys", "dev", "run"}
KEYSTORE_NAMES = ("cacerts", "jssecacerts")
KEYSTORE_EXT = (".jks", ".p12", ".pfx", ".keystore", ".truststore")
TEXT_LIMIT = 256 * 1024 * 1024  # largest text bundle that is parsed
BINARY_LIMIT = 512 * 1024 * 1024

ROOT_NEEDLES = {}
for name, (_, b64) in ROOTS.items():
    der = base64.b64decode(b64)
    # Raw DER (Bun, Go fallback) or the first 60 base64 characters, which come
    # before the first line break at the usual 64- and 72-column widths (Node).
    ROOT_NEEDLES[name] = [der, b64[:60].encode()]
# Each blocked key as raw bytes (Node.js, Bun, CPython) or as hex text (Go).
SPKI_NEEDLES = [(bytes.fromhex(h), h.encode()) for h in BLOCKED_SPKI]
# Strings found in every build of these runtimes, so a renamed binary is still recognised.
RUNTIME_MARKERS = [
    (b"--use-bundled-ca", "Node.js binary"),
    (b"bun:sqlite", "Bun binary"),
    (b"PyInit__ssl", "CPython ssl module"),
]


def go_version(mm):
    i = mm.find(b"\xff Go buildinf:")
    if i < 0 or i + 32 > len(mm):
        return None
    flags = mm[i + 15]
    if not flags & 0x2:  # pre-1.18 pointer format: version not inline
        return "go (pre-1.18 build info)"
    j = i + 32
    n, shift = 0, 0
    while True:
        b = mm[j]
        j += 1
        n |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            break
    return mm[j : j + n].decode(errors="replace")


def scan_binary(path):
    with open(path, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            embeds = [name for name, needles in ROOT_NEEDLES.items() if any(mm.find(n) >= 0 for n in needles)]
            keys = sum(1 for raw, hexed in SPKI_NEEDLES if mm.find(raw) >= 0 or mm.find(hexed) >= 0)
            gov = go_version(mm)
            x509 = gov is not None and mm.find(b"crypto/x509.(*Certificate).Verify") >= 0
            runtime = next((label for marker, label in RUNTIME_MARKERS if mm.find(marker) >= 0), None) or runtime_by_name(path)
    if keys == len(SPKI_NEEDLES):
        extra = f"; it also embeds {' and '.join(embeds)}, but rejects the keys" if embeds else ""
        return [("ok", f"holds all {keys} eMudhra blocklist keys (a byte match, not a runtime test){extra}")]
    found = []
    if embeds:
        found.append(("TRUSTS", f"embeds {' and '.join(embeds)} in its bundled roots"))
    if keys:
        found.append(("TRUSTS*", f"holds only {keys} of the {len(SPKI_NEEDLES)} blocked keys: check it by hand"))
    elif gov and x509:
        found.append(("TRUSTS*", f"Go program ({gov}) with crypto/x509 and no eMudhra blocklist: "
                      "it accepts whatever its trust store accepts"))
    elif runtime and not embeds:
        found.append(("TRUSTS*", f"{runtime} without the eMudhra blocklist: it accepts whatever its trust store accepts"))
    return found


def scan_bundle(path):
    try:
        certs = load_any(path)
    except Exception:
        return []
    if not certs:
        return []
    spkis = {c.spki_sha256 for c in certs}
    holds = [name for name, (spki, _) in ROOTS.items() if spki in spkis]
    if holds:
        return [("TRUSTS", f"CA bundle with {len(certs)} certificates holds {' and '.join(holds)}")]
    return []


def walk(top):
    if os.path.isfile(top):
        yield top
        return
    for d, dirs, files in os.walk(top):
        if os.path.abspath(d) == "/" or d == top:
            dirs[:] = [x for x in dirs if not (d == "/" and x in SKIP_DIRS)]
        for fn in files:
            yield os.path.join(d, fn)


def runtime_by_name(path):
    n = os.path.basename(path)
    if n in ("node", "nodejs"):
        return "Node.js binary"
    if n == "bun":
        return "Bun binary"
    if n.startswith("_ssl.") and n.endswith((".so", ".pyd")):
        return "CPython ssl module"
    return None


def classify(path, skipped):
    try:
        st = os.lstat(path)
    except OSError:
        return []
    if not stat.S_ISREG(st.st_mode) or st.st_size == 0:
        return []
    name = os.path.basename(path).lower()
    with open(path, "rb") as f:
        head = f.read(4096)
    if head[:4] in (b"\x7fELF", b"\xcf\xfa\xed\xfe", b"MZ\x90\x00"):
        if st.st_size > BINARY_LIMIT:
            skipped.append(path)
            return []
        return scan_binary(path)
    if name in KEYSTORE_NAMES or name.endswith(KEYSTORE_EXT) or head[:4] == b"\xfe\xed\xfe\xed":
        return scan_bundle(path)
    if b"\x00" in head:
        return []
    with open(path, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            has_pem = mm.find(b"-----BEGIN CERTIFICATE-----") >= 0 or mm.find(b"-----BEGIN TRUSTED CERTIFICATE-----") >= 0
    if not has_pem and not name.endswith((".pem", ".crt", ".cer")):
        return []
    if st.st_size > TEXT_LIMIT:
        skipped.append(path)
        return []
    return scan_bundle(path)


def main():
    paths = sys.argv[1:]
    if not paths or paths[0] in ("-h", "--help"):
        print(__doc__)
        return 2
    risky = starred = 0
    seen = set()
    skipped = []
    for top in paths:
        for p in walk(top):
            real = os.path.realpath(p)
            if real in seen:
                continue
            seen.add(real)
            for level, msg in classify(p, skipped):
                risky += level.startswith("TRUSTS")
                starred += level == "TRUSTS*"
                print(f"{level:<8} {p}\n         {msg}")
    for p in skipped:
        print(f"skipped  {p}\n         larger than the scan limit, not checked")
    print(f"\n{risky} finding(s) that still trust a chain through the compromised keys.")
    if starred:
        print("TRUSTS*: safe only if every trust store the program reads at run time is fixed.")
    print("No finding is not proof: only the bundle, keystore and binary formats listed in --help are checked.")
    return 1 if risky else 0


if __name__ == "__main__":
    sys.exit(main())
