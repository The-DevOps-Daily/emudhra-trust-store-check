#!/usr/bin/env python3
"""Stage 3: say, for every trust store, which of the two anchors for the
compromised keys it holds, and predict which test chains it accepts.

There are two paths to a trust anchor for each of the six TLS keys:

  emsign path: leaf -> EM xx TLS CA - G3x -> emSign Root TLS CA - G3
               (cross-signed by emSign ECC Root CA - G3) -> emSign ECC Root CA - G3
  aaa path:    leaf -> EM xx TLS CA - G3x (cross-signed by Sectigo)
               -> AAA Certificate Services ("Comodo AAA Services root")

Prediction: a store accepts the emsign chains if and only if it holds
emSign ECC Root CA - G3 (or emSign Root TLS CA - G3), and accepts the aaa
chains if and only if it holds AAA Certificate Services. Stage 4 checks this
against OpenSSL.

Reads results/01-certs.json, results/02-stores.json, stores/*.pem.
Writes results/03-inspect.json.
"""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "lib"))
from x509lite import load_any  # noqa: E402

ANCHORS = {
    "emsign_ecc_root_g3": "8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782",
    "emsign_root_tls_g3": "c619e4780ed8e0abeda24ad732567de4383a7ea941338f6d1a7d1b49ac792fe9",
    "aaa_certificate_services": "bd153ed7b0434f6886b17bce8bbe84ed340c7132d702a8f4fa318f756ecbd6f3",
}


def main():
    certs = json.load(open(os.path.join(ROOT, "results", "01-certs.json")))
    stores = json.load(open(os.path.join(ROOT, "results", "02-stores.json")))
    blocked = {r["spki_sha256"] for r in certs["intermediates"]}
    out = {}
    for sid in sorted(stores):
        bundle = load_any(os.path.join(ROOT, "stores", sid + ".pem"))
        spkis = {c.spki_sha256 for c in bundle}
        has = {k: v in spkis for k, v in ANCHORS.items()}
        emsign_ok = has["emsign_ecc_root_g3"] or has["emsign_root_tls_g3"]
        aaa_ok = has["aaa_certificate_services"]
        predictions = {c["file"]: (emsign_ok if c["path"] == "emsign" else aaa_ok) for c in certs["chains"]}
        out[sid] = {
            "family": stores[sid]["family"],
            "version": stores[sid]["version"],
            "fix_status": stores[sid]["fix_status"],
            "certificates": len(bundle),
            "holds": has,
            "holds_compromised_key_itself": bool(spkis & blocked),
            "other_emsign_roots": sorted(c.cn for c in bundle if "emSign" in c.cn and c.spki_sha256 not in ANCHORS.values()),
            "predict_emsign_path": emsign_ok,
            "predict_aaa_path": aaa_ok,
            "predictions": predictions,
        }
    with open(os.path.join(ROOT, "results", "03-inspect.json"), "w") as f:
        json.dump(out, f, indent=1)
    print(f"{'store':<22} {'status':<7} {'certs':>5}  emSign-G3  AAA   predicted: emsign-path aaa-path")
    for sid, r in out.items():
        print(f"{sid:<22} {r['fix_status']:<7} {r['certificates']:>5}  {str(r['holds']['emsign_ecc_root_g3']):<9}  {str(r['holds']['aaa_certificate_services']):<5} "
              f"{'ACCEPT' if r['predict_emsign_path'] else 'reject':>21} {'ACCEPT' if r['predict_aaa_path'] else 'reject':>8}")


if __name__ == "__main__":
    main()
