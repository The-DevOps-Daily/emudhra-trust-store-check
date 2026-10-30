#!/usr/bin/env python3
"""When did Mozilla stop trusting AAA Certificate Services for TLS?

Reads Mozilla's root data (certdata.txt and nssckbi.h) at a few Firefox
commits on the GitHub mirror and prints the builtins version and the
server-auth and email trust of "Comodo AAA Services root" and of
"emSign ECC Root CA - G3". Writes results/aaa-trust-history.txt.
"""

import os
import re
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIRROR = "https://raw.githubusercontent.com/mozilla-firefox/firefox/{}/security/nss/lib/ckfw/builtins/{}"
COMMITS = [
    ("49af430cb498", "2025-01-29 land NSS_3_108_BETA5"),
    ("dff41e53a155", "2025-04-22 land NSS_3_111_BETA1"),
    ("f6dd0159931e", "2026-09-08 upgrade NSS"),
    ("7ff62457dcf1", "2026-10-21 upgrade NSS to NSS_3_132_RTM"),
]
LABELS = ["Comodo AAA Services root", "emSign ECC Root CA - G3"]


def get(url):
    return urllib.request.urlopen(url, timeout=120).read().decode("utf-8", "replace")


def main():
    lines = []
    for sha, note in COMMITS:
        cd = get(MIRROR.format(sha, "certdata.txt"))
        h = get(MIRROR.format(sha, "nssckbi.h"))
        ver = ".".join(re.findall(r"#define NSS_BUILTINS_LIBRARY_VERSION_M(?:AJOR|INOR) (\d+)", h))
        lines.append(f"{sha} ({note}): builtins {ver}")
        for label in LABELS:
            trust = None
            for block in cd.split("\n\n"):
                if f'CKA_LABEL UTF8 "{label}"' in block and "CKO_NSS_TRUST" in block:
                    sa = re.search(r"CKA_TRUST_SERVER_AUTH CK_TRUST (\S+)", block).group(1)
                    em = re.search(r"CKA_TRUST_EMAIL_PROTECTION CK_TRUST (\S+)", block).group(1)
                    trust = f"server_auth={sa} email={em}"
            lines.append(f"  {label}: {trust or 'not present'}")
    out = "\n".join(lines) + "\n"
    with open(os.path.join(ROOT, "results", "aaa-trust-history.txt"), "w") as f:
        f.write(out)
    print(out, end="")


if __name__ == "__main__":
    main()
