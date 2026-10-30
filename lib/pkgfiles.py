"""Read single files out of .deb, .apk, .rpm, wheel and tar.gz packages
without installing them. Stdlib only, plus the zstd CLI for zstd payloads."""

import gzip
import io
import lzma
import subprocess
import tarfile
import zipfile


def _decompress(blob):
    if blob[:6] == b"\xfd7zXZ\x00":
        return lzma.decompress(blob)
    if blob[:2] == b"\x1f\x8b":
        return gzip.decompress(blob)
    if blob[:4] == b"\x28\xb5\x2f\xfd":
        return subprocess.run(["zstd", "-dc"], input=blob, capture_output=True, check=True).stdout
    return blob


def deb_members(data):
    """{path: bytes} for every regular file in a .deb's data.tar."""
    assert data[:8] == b"!<arch>\n", "not an ar archive"
    i = 8
    while i < len(data):
        name = data[i : i + 16].decode().strip().rstrip("/")
        size = int(data[i + 48 : i + 58].decode().strip())
        body = data[i + 60 : i + 60 + size]
        i += 60 + size + (size & 1)
        if name.startswith("data.tar"):
            t = tarfile.open(fileobj=io.BytesIO(_decompress(body)))
            return {m.name.lstrip("./"): t.extractfile(m).read() for m in t.getmembers() if m.isfile()}
    raise ValueError("no data.tar in .deb")


def apk_members(data):
    t = tarfile.open(fileobj=io.BytesIO(gzip.decompress(data)), ignore_zeros=True)
    return {m.name.lstrip("./"): t.extractfile(m).read() for m in t.getmembers() if m.isfile()}


def _rpm_header_end(data, off):
    assert data[off : off + 3] == b"\x8e\xad\xe8", "bad rpm header magic"
    nindex = int.from_bytes(data[off + 8 : off + 12], "big")
    hsize = int.from_bytes(data[off + 12 : off + 16], "big")
    return off + 16 + nindex * 16 + hsize


def rpm_members(data):
    assert data[:4] == b"\xed\xab\xee\xdb", "not an rpm"
    off = _rpm_header_end(data, 96)  # signature header
    off += (8 - off % 8) % 8
    off = _rpm_header_end(data, off)  # main header
    payload = _decompress(data[off:])
    out = {}
    i = 0
    while i + 110 <= len(payload):
        hdr = payload[i : i + 110]
        assert hdr[:6] in (b"070701", b"070702"), "unsupported cpio format"
        mode = int(hdr[14:22], 16)
        fsize = int(hdr[54:62], 16)
        nsize = int(hdr[94:102], 16)
        name = payload[i + 110 : i + 110 + nsize - 1].decode()
        j = i + 110 + nsize
        j += (4 - j % 4) % 4
        body = payload[j : j + fsize]
        j += fsize
        j += (4 - j % 4) % 4
        i = j
        if name == "TRAILER!!!":
            break
        if (mode & 0o170000) == 0o100000:
            out[name.lstrip("./")] = body
    return out


def zip_members(data):
    z = zipfile.ZipFile(io.BytesIO(data))
    return {n: z.read(n) for n in z.namelist() if not n.endswith("/")}


def targz_member(data, suffix):
    """First file in a .tar.gz whose path ends with suffix (streams, so large
    JDK archives are not unpacked to disk)."""
    with tarfile.open(fileobj=io.BytesIO(data), mode="r|gz") as t:
        for m in t:
            if m.isfile() and m.name.endswith(suffix):
                return m.name, t.extractfile(m).read()
    raise KeyError(suffix)
