"""Render NVD CVE records (raw/nvd/<id>.json) into compact 'CVE card' pages.

A raw NVD record is ~90 KB of JSON, most of it CPE match strings; the card keeps
only the fields a question could be about, each as its own section so a gold
fact maps to exactly one chunk:

  Description | Severity (every CVSS entry, per source) | Weakness (CWE, per
  source) | Affected Versions | CISA KEV | References (count + tags)

Outputs kb/cve/<id>.md and kb/docs_cve.jsonl.

  python -m data.render_cve
"""
from __future__ import annotations

import collections
import json

from .common import KB, RAW, write_jsonl
from .render_attack import to_markdown

NVD_DIR = RAW / "nvd"

# NVD identifies some contributing sources only by org UUID; name the known ones.
SOURCE_NAMES = {"134c704f-9b21-4f2e-91b3-4a467353bcc0": "CISA-ADP"}


def src(s: str, cna: str | None = None) -> str:
    """Human-label a source id. nvd@nist.gov is NVD; the CVE's own sourceIdentifier
    is the assigning CNA — labelling both makes CNA-vs-NVD comparison explicit."""
    if s == "nvd@nist.gov":
        return "NVD (nvd@nist.gov)"
    if cna and s == cna:
        return f"CNA ({s})"
    if s in SOURCE_NAMES:
        return f"{SOURCE_NAMES[s]} ({s[:8]}…)"
    return s


def sev_lines(cve: dict) -> list[str]:
    cna = cve.get("sourceIdentifier")
    out = []
    for key, m in cve.get("metrics", {}).items():
        if not key.startswith("cvssMetric"):
            continue
        for e in m:
            cd = e["cvssData"]
            sev = cd.get("baseSeverity") or e.get("baseSeverity") or ""
            out.append(f"CVSS {cd.get('version')} ({e.get('type')} source {src(e.get('source'), cna)}): "
                       f"base score {cd.get('baseScore')} {sev}; vector {cd.get('vectorString')}")
    for e in cve.get("metrics", {}).get("ssvcV203", []):
        opts = ", ".join(f"{k}={v}" for o in e["ssvcData"].get("options", []) for k, v in o.items())
        out.append(f"SSVC ({e['ssvcData'].get('role')}): {opts}")
    return out


def cwe_lines(cve: dict) -> list[str]:
    cna = cve.get("sourceIdentifier")
    out = []
    for w in cve.get("weaknesses", []):
        vals = ", ".join(d["value"] for d in w["description"])
        out.append(f"{src(w['source'], cna)} ({w.get('type')}): {vals}")
    return out


def affected_lines(cve: dict) -> list[str]:
    out = []
    for a in cve.get("affected", []):
        for ad in a.get("affectedData", []):
            vend, prod = ad.get("vendor", ""), ad.get("product", "")
            for v in ad.get("versions", []):
                rng = v.get("version", "")
                if v.get("lessThan"):
                    rng += f" < {v['lessThan']}"
                if v.get("lessThanOrEqual"):
                    rng += f" <= {v['lessThanOrEqual']}"
                changes = "; ".join(f"{c['status']} from {c['at']}" for c in v.get("changes", []))
                line = f"{vend} {prod}: {rng} ({v.get('status')})"
                if changes:
                    line += f" — {changes}"
                out.append(line.strip())
    return out


def render(cve: dict) -> dict:
    cid = cve["id"]
    name = cve.get("cisaVulnerabilityName") or cid
    head = [f"{cid}: {name}",
            f"Published: {cve['published'][:10]} | Last modified: {cve['lastModified'][:10]} | "
            f"Status: {cve.get('vulnStatus')} | Source identifier: {cve.get('sourceIdentifier')}"]
    desc = next((d["value"] for d in cve["descriptions"] if d["lang"] == "en"), "")
    secs = [("Description", "\n".join(head) + "\n\n" + desc)]
    if (s := sev_lines(cve)):
        secs.append(("Severity", "\n".join(s)))
    if (s := cwe_lines(cve)):
        secs.append(("Weakness", "\n".join(s)))
    if (s := affected_lines(cve)):
        secs.append(("Affected Versions", "\n".join(s)))
    if cve.get("cisaExploitAdd"):
        secs.append(("CISA KEV", f"Added to CISA Known Exploited Vulnerabilities catalog: {cve['cisaExploitAdd']}\n"
                                 f"Action due: {cve.get('cisaActionDue')}\n"
                                 f"Required action: {cve.get('cisaRequiredAction')}"))
    refs = cve.get("references", [])
    tags = collections.Counter(t for r in refs for t in r.get("tags", []))
    if refs:
        secs.append(("References", f"{len(refs)} references. Tags: "
                                   + ", ".join(f"{t} ({n})" for t, n in tags.most_common())))
    return {
        "doc_id": f"cve:{cid}",
        "source": "NVD (NIST National Vulnerability Database)",
        "entity_id": cid,
        "entity_name": name,
        "entity_type": "cve",
        "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
        "sections": [{"name": n, "text": t} for n, t in secs],
    }


def main():
    sel = json.load(open(NVD_DIR / "selection.json"))
    out_dir = KB / "cve"
    out_dir.mkdir(parents=True, exist_ok=True)
    docs = []
    for cid in sel:
        cve = json.load(open(NVD_DIR / f"{cid}.json"))
        d = render(cve)
        docs.append(d)
        (out_dir / f"{cid}.md").write_text(to_markdown(d))
    n = write_jsonl(KB / "docs_cve.jsonl", docs)
    secs = collections.Counter(s["name"] for d in docs for s in d["sections"])
    print(f"wrote {n} CVE cards -> {out_dir}; sections: {dict(secs)}")


if __name__ == "__main__":
    main()
