"""Minimal, stdlib-only certificate helpers.

Enough DER parsing to get the SubjectPublicKeyInfo, subject, issuer and
validity of an X.509 certificate, and to pull certificates out of PEM
bundles, C headers that embed PEM, JKS keystores and password-less PKCS#12
keystores. It does not verify anything; verification is done by OpenSSL.
"""

import base64
import hashlib
import re
import struct

PEM_RE = re.compile(
    rb"-----BEGIN (?:TRUSTED )?CERTIFICATE-----(.*?)-----END (?:TRUSTED )?CERTIFICATE-----",
    re.S,
)


def _tlv(buf, i):
    """Return (tag, header_len, length, start_of_value) for the TLV at i."""
    tag = buf[i]
    ln = buf[i + 1]
    hl = 2
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(buf[i + 2 : i + 2 + n], "big")
        hl = 2 + n
    return tag, hl, ln, i + hl


def _children(buf, start, end):
    out = []
    i = start
    while i < end:
        tag, hl, ln, v = _tlv(buf, i)
        out.append((tag, i, v, v + ln))
        i = v + ln
    return out


OID_CN = bytes.fromhex("550403")
OID_O = bytes.fromhex("55040a")


def _name(buf, s, e):
    parts = {}
    for _, _, rv, re_ in _children(buf, s, e):  # SET
        for _, _, av, ae in _children(buf, rv, re_):  # SEQUENCE
            kids = _children(buf, av, ae)
            if len(kids) < 2:
                continue
            oid = buf[kids[0][2] : kids[0][3]]
            val = buf[kids[1][2] : kids[1][3]]
            try:
                txt = val.decode("utf-8")
            except UnicodeDecodeError:
                txt = val.decode("latin-1")
            if oid == OID_CN:
                parts["CN"] = txt
            elif oid == OID_O:
                parts["O"] = txt
    return parts


def _time(buf, s, e, tag):
    t = buf[s:e].decode()
    if tag == 0x17:  # UTCTime YYMMDDHHMMSSZ
        yy = int(t[:2])
        t = ("19" if yy >= 50 else "20") + t
    return f"{t[0:4]}-{t[4:6]}-{t[6:8]}T{t[8:10]}:{t[10:12]}:{t[12:14]}Z"


class Cert:
    def __init__(self, der):
        self.der = der
        _, _, _, cv = _tlv(der, 0)
        tag, _, tln, tv = _tlv(der, cv)  # tbsCertificate
        kids = _children(der, tv, tv + tln)
        if kids[0][0] == 0xA0:  # explicit version
            kids = kids[1:]
        # serial, sigalg, issuer, validity, subject, spki
        self.serial = der[kids[0][2] : kids[0][3]].hex()
        self.issuer = _name(der, kids[2][2], kids[2][3])
        val = _children(der, kids[3][2], kids[3][3])
        self.not_before = _time(der, val[0][2], val[0][3], val[0][0])
        self.not_after = _time(der, val[1][2], val[1][3], val[1][0])
        self.subject = _name(der, kids[4][2], kids[4][3])
        self.spki = der[kids[5][1] : kids[5][3]]

    @property
    def sha256(self):
        return hashlib.sha256(self.der).hexdigest()

    @property
    def spki_sha256(self):
        return hashlib.sha256(self.spki).hexdigest()

    @property
    def cn(self):
        return self.subject.get("CN") or self.subject.get("O") or "?"

    @property
    def issuer_cn(self):
        return self.issuer.get("CN") or self.issuer.get("O") or "?"

    def pem(self):
        b = base64.b64encode(self.der).decode()
        lines = [b[i : i + 64] for i in range(0, len(b), 64)]
        return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"


def certs_from_pem(data):
    """Certificates from PEM text, including PEM embedded in C/C++ string
    literals (node_root_certs.h, Bun's root_certs.h)."""
    out = []
    for m in PEM_RE.finditer(data):
        body = m.group(1)
        # Strip C string-literal noise: quotes, \n escapes, whitespace.
        body = re.sub(rb'\\n|"|\s', b"", body)
        try:
            der = base64.b64decode(body)
            c = Cert(der)
        except Exception:
            continue
        if b"TRUSTED CERTIFICATE" in m.group(0)[:30]:
            # OpenSSL trusted-cert format: DER cert followed by aux trust data.
            _, hl, ln, _ = _tlv(der, 0)
            c = Cert(der[: hl + ln])
        out.append(c)
    return out


def certs_from_jks(data):
    if data[:4] != b"\xfe\xed\xfe\xed":
        return None
    out = []
    _, count = struct.unpack(">II", data[4:12])
    i = 12
    for _ in range(count):
        tag = struct.unpack(">I", data[i : i + 4])[0]
        i += 4
        alen = struct.unpack(">H", data[i : i + 2])[0]
        i += 2 + alen + 8  # alias + timestamp
        if tag == 1:  # private key entry: skip key, then chain
            klen = struct.unpack(">I", data[i : i + 4])[0]
            i += 4 + klen
            n = struct.unpack(">I", data[i : i + 4])[0]
            i += 4
        else:
            n = 1
        for _ in range(n):
            tlen = struct.unpack(">H", data[i : i + 2])[0]
            i += 2 + tlen
            clen = struct.unpack(">I", data[i : i + 4])[0]
            i += 4
            out.append(Cert(data[i : i + clen]))
            i += clen
    return out


OID_DATA = bytes.fromhex("2a864886f70d010701")
OID_CERTBAG = bytes.fromhex("2a864886f70d010c0a0103")


def certs_from_pkcs12(data):
    """Password-less PKCS#12 (the JDK 18+ cacerts format). Returns None if the
    file is not PKCS#12 or its certificates are encrypted."""
    found = []

    def walk(buf, s, e, depth=0):
        if depth > 12:
            return
        try:
            kids = _children(buf, s, e)
        except Exception:
            return
        for idx, (tag, start, v, end) in enumerate(kids):
            if tag == 0x06 and buf[v:end] == OID_CERTBAG and idx + 1 < len(kids):
                # [0] { SEQUENCE { x509Certificate OID, [0] { OCTET STRING cert } } }
                _, _, cv, ce = kids[idx + 1]
                try:
                    seq = _children(buf, cv, ce)[0]
                    inner = _children(buf, seq[2], seq[3])
                    wrap = _children(buf, inner[1][2], inner[1][3])[0]
                    found.append(Cert(buf[wrap[2] : wrap[3]]))
                except Exception:
                    pass
            elif tag in (0x30, 0x31, 0xA0):
                walk(buf, v, end, depth + 1)
            elif tag == 0x04 and end - v > 16 and buf[v] == 0x30:
                walk(buf, v, end, depth + 1)

    if not data or data[0] != 0x30:
        return None
    try:
        _, hl, ln, _ = _tlv(data, 0)
    except Exception:
        return None
    walk(data, 0, min(len(data), hl + ln))
    return found or None


def load_any(path):
    """Certificates from a bundle file of any supported kind."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] == b"\xfe\xed\xfe\xed":
        return certs_from_jks(data)
    if b"-----BEGIN" in data:
        return certs_from_pem(data)
    p = certs_from_pkcs12(data)
    if p is not None:
        return p
    return []
