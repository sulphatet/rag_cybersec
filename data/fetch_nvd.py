"""Select and fetch the CVE records that form the NVD part of the KB.

Selection is programmatic and logged (raw/nvd/selection.json) so the KB's CVE
slice is reproducible and every inclusion has a stated reason:

  named        well-known CVEs a SOC analyst would plausibly ask about
  conflict     CNA and NVD disagree on CWE and/or CVSS v3.1 base score
               (source-conflict test tier: the correct answer names both)
  v2_only      record carries CVSS v2 metrics but no v3.x (near-miss tier:
               "what is the v3.1 score?" must be abstained on)
  recent       CISA-KEV entries published in the last ~4 months
  distractor   random KEV entries — retrieval must discriminate among CVEs

Pools are two cached NVD API pages (raw/nvd_pool_p0.json = KEV sorted by id,
raw/nvd_pool_recent.json = KEV published since 2026-05-20). Keyless API,
throttled to the public 5 req / 30 s limit.

  python -m data.fetch_nvd [--limit N] [--seed 0]
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

from .common import RAW, NvdClient

NAMED = {
    "CVE-2021-44228": "Log4Shell",
    "CVE-2017-0144": "EternalBlue (SMBv1)",
    "CVE-2021-26855": "ProxyLogon (Exchange)",
    "CVE-2023-4966": "Citrix Bleed",
    "CVE-2023-34362": "MOVEit Transfer SQLi",
    "CVE-2019-19781": "Citrix ADC path traversal",
    "CVE-2020-1472": "Zerologon",
    "CVE-2021-34527": "PrintNightmare",
    "CVE-2022-30190": "Follina (MSDT)",
    "CVE-2023-23397": "Outlook NTLM leak",
    "CVE-2024-3400": "PAN-OS GlobalProtect",
    "CVE-2014-0160": "Heartbleed",
    "CVE-2014-2120": "Cisco ASA WebVPN XSS",
}

NVD_DIR = RAW / "nvd"
# Committed selection of the 300 CVE ids (id -> reason). Lets a source-only clone
# reproduce the exact CVE slice by fetching each record by id, without shipping the
# bulk NVD/KEV pool dumps. Regenerated whenever the pool-based selection is re-run.
MANIFEST = Path(__file__).with_name("cve_manifest.json")


def v31_entries(cve: dict):
    return cve.get("metrics", {}).get("cvssMetricV31", [])


def cwes_by_source(cve: dict) -> dict[str, set]:
    out = {}
    for w in cve.get("weaknesses", []):
        vals = {d["value"] for d in w["description"] if d["value"].startswith("CWE-")}
        if vals:
            out.setdefault(w["source"], set()).update(vals)
    return out


def is_conflict(cve: dict) -> str | None:
    """Return a reason string if CNA and NVD disagree on CWE or v3.1 score."""
    reasons = []
    cw = cwes_by_source(cve)
    nvd = cw.get("nvd@nist.gov")
    others = [v for s, v in cw.items() if s != "nvd@nist.gov"]
    if nvd and others and any(v != nvd for v in others):
        reasons.append("cwe")
    scores = {}
    for m in v31_entries(cve):
        scores.setdefault(m["type"], set()).add(m["cvssData"]["baseScore"])
    if scores.get("Primary") and scores.get("Secondary") and scores["Primary"] != scores["Secondary"]:
        reasons.append("cvss31_score")
    return "+".join(reasons) if reasons else None


def is_v2_only(cve: dict) -> bool:
    m = cve.get("metrics", {})
    return bool(m.get("cvssMetricV2")) and not any(k.startswith("cvssMetricV3") for k in m)


def load_pool(path) -> list[dict]:
    with open(path) as f:
        return [v["cve"] for v in json.load(f)["vulnerabilities"]]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, help="cap total CVEs (correctness check)")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--target", type=int, default=300, help="total CVE cards to assemble")
    ap.add_argument("--n-conflict", type=int, default=40)
    ap.add_argument("--n-v2only", type=int, default=15)
    ap.add_argument("--n-recent", type=int, default=60)
    ap.add_argument("--n-distractor", type=int, default=6)
    args = ap.parse_args()
    rng = random.Random(args.seed)
    NVD_DIR.mkdir(parents=True, exist_ok=True)
    client = NvdClient()

    # Assemble the candidate pool from every cached bulk NVD response.
    pool = {}
    pool_recent = []
    for f in ("nvd_pool_p0.json", "nvd_pool_recent.json", "nvd_kev_all.json"):
        p = RAW / f
        if not p.exists():
            continue
        recs = load_pool(p)
        for c in recs:
            pool[c["id"]] = c
        if f == "nvd_pool_recent.json":
            pool_recent = recs
    print(f"candidate pool: {len(pool)} unique CVEs from cached NVD bulk responses")

    selected: dict[str, dict] = {}   # id -> {"reason": ..., "cve": ...}

    def take(cve, reason):
        if cve["id"] not in selected:
            selected[cve["id"]] = {"reason": reason, "cve": cve}

    # 1. named — fetch individually (cached)
    for cid, nick in NAMED.items():
        cache = NVD_DIR / f"{cid}.json"
        if cache.exists():
            cve = json.load(open(cache))
            if "vulnerabilities" in cve:           # old full-response cache format
                cve = cve["vulnerabilities"][0]["cve"]
        else:
            cve = client.cve(cid)
            print(f"fetched {cid}")
        json.dump(cve, open(cache, "w"))
        take(cve, f"named:{nick}")
        if args.limit and len(selected) >= args.limit:
            break

    # Source-only reproduction: no bulk pool cached, so rebuild the exact selection
    # from the committed manifest by fetching each record by id (stable NVD data).
    if not pool and not args.limit and MANIFEST.exists():
        manifest = json.load(open(MANIFEST))
        print(f"no bulk pool cached; reproducing {len(manifest)} CVEs from {MANIFEST.name}")
        for cid, reason in manifest.items():
            if cid in selected:
                continue
            cache = NVD_DIR / f"{cid}.json"
            if cache.exists():
                cve = json.load(open(cache))
                if "vulnerabilities" in cve:
                    cve = cve["vulnerabilities"][0]["cve"]
            else:
                cve = client.cve(cid)
                print(f"fetched {cid}")
            json.dump(cve, open(cache, "w"))
            take(cve, reason)

    if not args.limit:
        # 2. conflict
        cands = [c for c in pool.values() if is_conflict(c) and c["id"] not in selected]
        rng.shuffle(cands)
        for c in cands[:args.n_conflict]:
            take(c, f"conflict:{is_conflict(c)}")
        # 3. v2-only
        cands = [c for c in pool.values() if is_v2_only(c) and c["id"] not in selected]
        rng.shuffle(cands)
        for c in cands[:args.n_v2only]:
            take(c, "v2_only")
        # 4. recent
        cands = [c for c in pool_recent if c["id"] not in selected]
        rng.shuffle(cands)
        for c in cands[:args.n_recent]:
            take(c, "recent")
        # 5. fill to --target with a broad KEV/recent sample (natural CWE/vendor
        #    clustering gives the retriever real near-neighbour discrimination to do).
        cands = [c for c in pool.values() if c["id"] not in selected]
        rng.shuffle(cands)
        for c in cands:
            if len(selected) >= args.target:
                break
            take(c, "distractor")

    for cid, rec in selected.items():
        json.dump(rec["cve"], open(NVD_DIR / f"{cid}.json", "w"))
    sel = {cid: {"reason": rec["reason"], "published": rec["cve"]["published"][:10],
                 "conflict": is_conflict(rec["cve"]), "v2_only": is_v2_only(rec["cve"]),
                 "kev": bool(rec["cve"].get("cisaExploitAdd"))}
           for cid, rec in selected.items()}
    json.dump(sel, open(NVD_DIR / "selection.json", "w"), indent=1)
    print(f"selected {len(sel)} CVEs -> {NVD_DIR/'selection.json'}")
    for cid, r in sel.items():
        print(f"  {cid}  {r['published']}  {r['reason']}")
    from collections import Counter
    print("selection by reason:", dict(Counter(r["reason"].split(":")[0] for r in sel.values())),
          "| conflict in pool:", sum(1 for c in pool.values() if is_conflict(c)))


if __name__ == "__main__":
    main()
