#!/usr/bin/env python3
"""Stage 2: download each trust store in stores.tsv as a package file and
extract only its CA bundle. Nothing is installed and no container image is
pulled.

Writes stores/<id>.pem (gitignored, normalised to plain PEM) and
results/02-stores.json with the source URL, the SHA-256 of the download and
of the extracted file, and the certificate count. Raw downloads go to
work/ and are deleted after extraction unless --keep is given.
"""

import hashlib
import json
import os
import re
import sys
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "lib"))
from pkgfiles import apk_members, deb_members, rpm_members, targz_member, zip_members  # noqa: E402
from x509lite import Cert, certs_from_pem, load_any  # noqa: E402

UA = "emudhra-trust-store-check/1.0 (+https://github.com/The-DevOps-Daily/emudhra-trust-store-check)"
SERVER_AUTH = bytes.fromhex("06082b06010505070301")


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=300) as r:
        return r.read()


def read_tsv(path):
    rows = []
    for line in open(path):
        if line.startswith("#") or not line.strip():
            continue
        f = line.rstrip("\n").split("\t")
        f += [""] * (7 - len(f))
        rows.append(dict(zip(["id", "family", "version", "fix_status", "kind", "url", "member"], f)))
    return rows


def p11kit_server_auth(text):
    """Emulate `trust extract --format=pem-bundle --filter=ca-anchors
    --purpose=server-auth` on a p11-kit trust file: trusted certificates whose
    key has no extendedKeyUsage restriction, or one that includes serverAuth,
    minus anything marked x-distrusted."""
    ekus, distrusted, certs = {}, set(), []
    for obj in text.split("[p11-kit-object-v1]"):
        attrs = dict(re.findall(r"^([a-z0-9-]+): (.*)$", obj, re.M))
        if attrs.get("class") == "x-certificate-extension" and attrs.get("object-id") == "2.5.29.37":
            pk = re.search(r"-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----", obj, re.S)
            if pk:
                import base64
                spki = hashlib.sha256(base64.b64decode(re.sub(r"\s", "", pk.group(1)))).hexdigest()
                ekus[spki] = urllib.parse.unquote_to_bytes(attrs["value"].strip('"'))
        elif attrs.get("class", "certificate") == "certificate" and "BEGIN CERTIFICATE" in obj:
            cs = certs_from_pem(obj.encode())
            if not cs:
                continue
            if attrs.get("x-distrusted") == "true":
                distrusted.add(cs[0].spki_sha256)
            elif attrs.get("trusted") == "true":
                certs.append(cs[0])
    out = []
    for c in certs:
        if c.spki_sha256 in distrusted:
            continue
        eku = ekus.get(c.spki_sha256)
        if eku is not None and SERVER_AUTH not in eku:
            continue
        out.append(c)
    return out


def gitdir(spec, path):
    repo, ref = spec.split("@")
    api = f"https://api.github.com/repos/{repo}/contents/{path}?ref={ref}"
    listing = json.loads(get(api))
    blob = b""
    certs = []
    for item in sorted(listing, key=lambda x: x["name"]):
        data = get(item["download_url"])
        blob += item["name"].encode() + b"\n" + data
        certs += certs_from_pem(data)
    return blob, certs


def extract(row, data):
    kind, member = row["kind"], row["member"]
    if kind == "deb":
        files = deb_members(data)
        parts = sorted(k for k in files if k.startswith(member) and k.endswith(".crt"))
        blob = b"".join(files[k] for k in parts)
        return blob, certs_from_pem(blob)
    if kind == "apk":
        blob = apk_members(data)[member]
        return blob, certs_from_pem(blob)
    if kind == "rpm":
        blob = rpm_members(data)[member]
        return blob, p11kit_server_auth(blob.decode())
    if kind == "wheel":
        blob = zip_members(data)[member]
        return blob, certs_from_pem(blob)
    if kind == "pem":
        return data, certs_from_pem(data)
    if kind == "der":
        # Bun's root_certs.der: uint32 count, count+1 uint32 offsets, then the DER blobs.
        n = int.from_bytes(data[0:4], "little")
        offs = [int.from_bytes(data[4 + 4 * k : 8 + 4 * k], "little") for k in range(n + 1)]
        base = 4 + 4 * (n + 1)
        assert base + offs[-1] == len(data), "unexpected root_certs.der layout"
        return data, [Cert(data[base + offs[k] : base + offs[k + 1]]) for k in range(n)]
    if kind == "targz":
        name, blob = targz_member(data, member)
        tmp = os.path.join(ROOT, "work", row["id"] + ".keystore")
        with open(tmp, "wb") as f:
            f.write(blob)
        certs = load_any(tmp)
        os.remove(tmp)
        return blob, certs
    raise ValueError(kind)


def main():
    keep = "--keep" in sys.argv
    only = [a for a in sys.argv[1:] if not a.startswith("--")]
    os.makedirs(os.path.join(ROOT, "stores"), exist_ok=True)
    os.makedirs(os.path.join(ROOT, "work"), exist_ok=True)
    out_path = os.path.join(ROOT, "results", "02-stores.json")
    manifest = json.load(open(out_path)) if os.path.exists(out_path) else {}
    for row in read_tsv(os.path.join(ROOT, "stores.tsv")):
        if only and row["id"] not in only:
            continue
        if row["kind"] == "gitdir":
            download_sha = None
            blob, certs = gitdir(row["url"], row["member"])
        else:
            raw_path = os.path.join(ROOT, "work", row["id"] + ".download")
            data = get(row["url"])
            with open(raw_path, "wb") as f:
                f.write(data)
            download_sha = hashlib.sha256(data).hexdigest()
            blob, certs = extract(row, data)
            del data
            if not keep:
                os.remove(raw_path)
        # Normalise: unique certificates, sorted, plain PEM.
        uniq = {c.sha256: c for c in certs}
        pem = "".join(uniq[k].pem() for k in sorted(uniq))
        with open(os.path.join(ROOT, "stores", row["id"] + ".pem"), "w") as f:
            f.write(pem)
        manifest[row["id"]] = {
            **{k: row[k] for k in ("family", "version", "fix_status", "kind", "url", "member")},
            "download_sha256": download_sha,
            "extracted_sha256": hashlib.sha256(blob).hexdigest(),
            "certificates": len(uniq),
        }
        print(f"{row['id']:<22} {len(uniq):>4} certificates  {row['family']} {row['version']}")
        with open(out_path, "w") as f:
            json.dump(manifest, f, indent=1, sort_keys=True)


if __name__ == "__main__":
    main()
