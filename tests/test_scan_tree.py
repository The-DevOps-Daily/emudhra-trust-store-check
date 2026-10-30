"""Tests for scripts/scan-tree.py on synthetic files.

Each test writes a small file into a temporary directory and checks what the
scanner reports. The only certificates used are the two public roots that
scan-tree.py already embeds.

Run: python3 -m unittest discover -s tests
"""

import base64
import importlib.util
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("scan_tree", os.path.join(HERE, "..", "scripts", "scan-tree.py"))
st = importlib.util.module_from_spec(spec)
spec.loader.exec_module(st)

ELF = b"\x7fELF" + b"\x00" * 60
AAA_B64 = st.ROOTS["AAA Certificate Services"][1]
EMSIGN_B64 = st.ROOTS["emSign ECC Root CA - G3"][1]


def pem(b64):
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"


class ScanTreeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def scan(self, name, data):
        path = os.path.join(self.tmp.name, name)
        with open(path, "wb") as f:
            f.write(data)
        skipped = []
        return [level for level, _ in st.classify(path, skipped)], skipped

    def test_complete_raw_blocklist_is_ok(self):
        data = ELF + b"--use-bundled-ca" + b"".join(bytes.fromhex(h) for h in st.BLOCKED_SPKI)
        self.assertEqual(self.scan("node", data)[0], ["ok"])

    def test_complete_hex_blocklist_is_ok(self):
        data = ELF + b"".join(h.encode() for h in st.BLOCKED_SPKI)
        self.assertEqual(self.scan("goprog", data)[0], ["ok"])

    def test_four_keys_in_both_encodings_is_not_ok(self):
        four = st.BLOCKED_SPKI[:4]
        data = ELF + b"".join(bytes.fromhex(h) + h.encode() for h in four)
        self.assertEqual(self.scan("libsomething.so", data)[0], ["TRUSTS*"])

    def test_renamed_node_without_blocklist(self):
        self.assertEqual(self.scan("my-service", ELF + b"--use-bundled-ca")[0], ["TRUSTS*"])

    def test_embedded_root_with_complete_blocklist_is_ok(self):
        data = ELF + base64.b64decode(AAA_B64) + b"".join(bytes.fromhex(h) for h in st.BLOCKED_SPKI)
        self.assertEqual(self.scan("runtime", data)[0], ["ok"])

    def test_embedded_pem_root_without_blocklist(self):
        node_style = EMSIGN_B64[:72] + "\\n" + EMSIGN_B64[72:144]
        self.assertEqual(self.scan("node", ELF + node_style.encode())[0], ["TRUSTS"])

    def test_bundle_with_marker_after_4kib(self):
        data = ("# comment\n" * 600 + pem(AAA_B64)).encode()
        self.assertEqual(self.scan("bundle.txt", data)[0], ["TRUSTS"])

    def test_bundle_without_the_roots_is_silent(self):
        self.assertEqual(self.scan("empty.pem", b"# no certificates here\n")[0], [])

    def test_oversized_pem_is_reported_as_skipped(self):
        levels, skipped = self.scan("huge.pem", b"x" * (st.TEXT_LIMIT + 1))
        self.assertEqual(levels, [])
        self.assertEqual(len(skipped), 1)


if __name__ == "__main__":
    unittest.main()
