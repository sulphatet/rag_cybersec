"""Generate CVE question items with DETERMINISTIC gold from NVD fields.

CVE facts are their own authoritative answer key (NVD's metrics/weaknesses/kev
fields), so these questions need no LLM judge to score correctness --- the
cheapest way to add evaluation rigor. Emitted in the same shape as
`authored.py` items (gold as [entity_id, section] + must_contain), so
`build_testset.resolve_authored` validates each against the rendered KB.

Question types:
  score / severity / vector / cwe / kev-date / affected  -- ID in the query
      (tests retrieval among ~300 CVEs + exact structured grounding)
  conflict  -- CNA vs NVD disagree; answer must name both sources
  desc      -- ID-FREE: a vuln description (CVE id stripped) -> its CWE
      (the brief's "short incident description" case; hard semantic retrieval)

  python -m data.gen_cve_questions [--seed 0]
Writes testset/cve_questions.json.
"""
from __future__ import annotations

import argparse
import json
import random
import re

from .common import RAW, TESTSET
from .fetch_nvd import is_conflict, v31_entries, cwes_by_source

NVD_DIR = RAW / "nvd"


def nvd_v31(cve):
    for e in v31_entries(cve):
        if e.get("type") == "Primary" and e["cvssData"].get("baseScore") is not None:
            return e
    return v31_entries(cve)[0] if v31_entries(cve) else None


def nvd_cwes(cve):
    cw = cwes_by_source(cve).get("nvd@nist.gov", set())
    return sorted(c for c in cw if re.match(r"CWE-\d+$", c))


def desc_en(cve):
    return next((d["value"] for d in cve["descriptions"] if d["lang"] == "en"), "")


def item(qid, query, cve_id, section, must_contain, notes, route="answerable", beh="answer"):
    return {"qid": qid, "category": "cve_fact" if section != "Weakness" or "conflict" not in qid else "source_conflict",
            "query": query, "expected_route": route, "expected_behaviour": beh,
            "gold": [[cve_id, section]], "must_contain": must_contain,
            "gold_answer": "; ".join(must_contain), "notes": notes}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--n-score", type=int, default=4)
    ap.add_argument("--n-cwe", type=int, default=3)
    ap.add_argument("--n-vector", type=int, default=2)
    ap.add_argument("--n-kev", type=int, default=2)
    ap.add_argument("--n-affected", type=int, default=1)
    ap.add_argument("--n-conflict", type=int, default=3)
    ap.add_argument("--n-desc", type=int, default=5)
    args = ap.parse_args()
    rng = random.Random(args.seed)

    sel = json.load(open(NVD_DIR / "selection.json"))
    cves = {cid: json.load(open(NVD_DIR / f"{cid}.json")) for cid in sel}
    # Exclude the CVEs already used by the hand-authored F/G items so we don't collide.
    used = {"CVE-2021-44228", "CVE-2024-3400", "CVE-2017-0144", "CVE-2014-2120"}
    avail = [cid for cid in cves if cid not in used]
    rng.shuffle(avail)

    out, taken = [], set()

    def pick(pred, n, make):
        c = 0
        for cid in avail:
            if c >= n:
                break
            if cid in taken:
                continue
            cve = cves[cid]
            r = make(cid, cve) if pred(cve) else None
            if r:
                out.append(r); taken.add(cid); c += 1

    # score + severity
    def mk_score(cid, cve):
        e = nvd_v31(cve)
        sev = e["cvssData"].get("baseSeverity", "")
        return item(f"CV-score-{cid[-4:]}",
                    f"What CVSS v3.1 base score and severity did NVD assign to {cid}?",
                    cid, "Severity", [f"{e['cvssData']['baseScore']} {sev}"],
                    "auto: NVD primary v3.1 score+severity (deterministic gold)")
    pick(lambda c: nvd_v31(c) and nvd_v31(c).get("type") == "Primary", args.n_score, mk_score)

    # cwe
    def mk_cwe(cid, cve):
        cw = nvd_cwes(cve)
        return item(f"CV-cwe-{cid[-4:]}",
                    f"Which CWE did NVD assign to {cid}?",
                    cid, "Weakness", cw, "auto: NVD CWE (deterministic gold)")
    pick(lambda c: nvd_cwes(c), args.n_cwe, mk_cwe)

    # vector
    def mk_vec(cid, cve):
        e = nvd_v31(cve)
        return item(f"CV-vec-{cid[-4:]}",
                    f"What is the NVD CVSS v3.1 vector string for {cid}?",
                    cid, "Severity", [e["cvssData"]["vectorString"]],
                    "auto: NVD v3.1 vector (deterministic gold)")
    pick(lambda c: nvd_v31(c) and nvd_v31(c)["cvssData"].get("vectorString"), args.n_vector, mk_vec)

    # kev due date
    def mk_kev(cid, cve):
        return item(f"CV-kev-{cid[-4:]}",
                    f"By what date did CISA require federal agencies to remediate {cid}?",
                    cid, "CISA KEV", [cve["cisaActionDue"][:10]],
                    "auto: CISA KEV action-due date (deterministic gold)")
    pick(lambda c: c.get("cisaActionDue"), args.n_kev, mk_kev)

    # affected version (coarse: require a version token)
    def mk_aff(cid, cve):
        for a in cve.get("affected", []):
            for ad in a.get("affectedData", []):
                for v in ad.get("versions", []):
                    if v.get("lessThan"):
                        return item(f"CV-aff-{cid[-4:]}",
                                    f"According to its NVD record, up to which version is {ad.get('product','the product')} affected by {cid}?",
                                    cid, "Affected Versions", [v["lessThan"]],
                                    "auto: NVD affected-version upper bound (deterministic gold)")
        return None
    pick(lambda c: c.get("affected"), args.n_affected, mk_aff)

    # conflict (CNA vs NVD)
    def mk_conf(cid, cve):
        cw = cwes_by_source(cve)
        nvd = cw.get("nvd@nist.gov", set())
        other = set().union(*[v for s, v in cw.items() if s != "nvd@nist.gov"]) if len(cw) > 1 else set()
        facts = sorted({x for x in (nvd | other) if re.match(r"CWE-\d+$", x)})
        if len(facts) < 2:
            return None
        it = item(f"CV-conflict-{cid[-4:]}",
                  f"For {cid}, do the CNA and NVD agree on the CWE classification? Give both.",
                  cid, "Weakness", facts, "auto: cross-source CWE conflict (deterministic gold)")
        it["category"] = "source_conflict"
        return it
    pick(lambda c: is_conflict(c) and "cwe" in (is_conflict(c) or ""), args.n_conflict, mk_conf)

    # description-based (ID-free, hard retrieval) -> CWE
    def mk_desc(cid, cve):
        cw = nvd_cwes(cve)
        d = desc_en(cve)
        d = re.sub(re.escape(cid), "this vulnerability", d)      # strip the id
        d = d[:400]
        it = item(f"CV-desc-{cid[-4:]}",
                  f"A vulnerability is described as follows. Which CWE weakness does NVD assign to it?\n\n\"{d}\"",
                  cid, "Weakness", cw, "auto: description-based, ID-free (hard retrieval); deterministic CWE gold")
        it["category"] = "cve_desc"
        return it
    pick(lambda c: nvd_cwes(c) and len(desc_en(c)) > 80, args.n_desc, mk_desc)

    json.dump(out, open(TESTSET / "cve_questions.json", "w"), indent=1)
    from collections import Counter
    print(f"generated {len(out)} CVE questions -> {TESTSET/'cve_questions.json'}")
    print("by category:", dict(Counter(x["category"] for x in out)))


if __name__ == "__main__":
    main()
