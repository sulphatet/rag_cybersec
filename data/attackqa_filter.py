"""Mechanical survival filter: which AttackQA rows are still supported by our KB?

AttackQA (built on ATT&CK v15.1) stores, per row, a templated `document` from
which the answer was derived. We index ATT&CK v19.2, so a row is only a valid
test item if the fact its document states is still present in *our rendered
KB*. Two purely mechanical criteria, no LLM and no domain judgment:

  prose templates   the document body (after the template's "...:\n" prefix)
                    is a verbatim substring (whitespace-insensitive) of the
                    expected KB section of the subject's page
  list templates    the set of ATT&CK IDs (or tactic names) listed in the
                    document equals the set found in the expected KB section

Every surviving row gets `gold_chunk_ids` (the chunk(s) of that section that
contain the fact). Every failing row gets a reason. Output:

  testset/attackqa_survival.jsonl   one row per AttackQA row
  testset/attackqa_survival_stats.json

  python -m data.attackqa_filter
"""
from __future__ import annotations

import collections
import json
import re

import pandas as pd

from .common import KB, PATTERNS, ROOT, TESTSET, flat, read_jsonl, write_jsonl

ATTACKQA = ROOT / "data" / "attackqa.parquet"

# template -> (kind, expected KB section, id-prefix for list comparison)
PROSE = {
    "techniques": "Description", "software": "Description", "groups": "Description",
    "campaigns": "Description", "tactics": "Description",
    "relationships_uses_software": "Procedure Examples",
    "relationships_mitigations": "Mitigations",
    "relationships_detects": None,                    # v18+ removed these notes
}
LISTS = {
    "techniques_sub": ("Sub-techniques", "T"),
    "techniques_parent": ("Description", "T"),        # parent id sits in the overview line
    "techniques_tactics": ("Description", "TACTIC"),
    "relationships_mitigations_summaries": ("Mitigations", "M"),
    "relationships_detections_summaries": (None, None),  # data-component detections gone in v18+
    "relationships_groups_for_technique": ("Procedure Examples", "G"),
    "relationships_software_for_technique": ("Procedure Examples", "S"),
    "relationships_campaigns_for_technique": ("Procedure Examples", "C"),
    "relationships_techniques_for_software": ("Techniques Used", "T"),
    "relationships_groups_for_software": ("Groups and Campaigns That Use This Software", "G"),
    "relationships_campaigns_for_software": ("Groups and Campaigns That Use This Software", "C"),
    "relationships_techniques_for_group": ("Techniques Used", "T"),
    "relationships_software_for_group": ("Software Used", "S"),
    "relationships_campaigns_for_group": ("Campaigns", "C"),
    "relationships_techniques_for_campaign": ("Techniques Used", "T"),
    "relationships_software_for_campaign": ("Software Used", "S"),
    "relationships_groups_for_campaign": ("Attributed To", "G"),
}
TACTIC_NAMES = {"Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
                "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery",
                "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact",
                "Stealth", "Defense Impairment"}


def ids_with_prefix(text: str, prefix: str) -> set[str]:
    if prefix == "TACTIC":
        return {t for t in TACTIC_NAMES if re.search(rf"\b{re.escape(t)}\b", text)}
    return {i for i in PATTERNS["attack_id"].findall(text) if i.startswith(prefix)
            and not (prefix == "T" and i.startswith("TA"))}


def doc_body(document: str) -> str:
    """Strip the template prefix ('...:\n') from a prose-template document."""
    return document.split(":\n", 1)[1] if ":\n" in document else document


class Filter:
    def __init__(self):
        chunks = read_jsonl(KB / "chunks.jsonl")
        self.sections = collections.defaultdict(list)   # (entity_id, section) -> [chunk]
        for c in chunks:
            sc = c["source_context"]
            self.sections[(sc["entity_id"], sc["section"])].append(c)
        self.entities = {sc for sc, _ in self.sections}

    def section_chunks(self, eid: str, section: str):
        return sorted(self.sections.get((eid, section), []), key=lambda c: c["source_context"]["part"])

    def check(self, row) -> dict:
        src, sid = row.source, row.subject_id
        if src in PROSE:
            sec = PROSE[src]
            if sec is None:
                return {"survived": False, "reason": "detection notes removed in ATT&CK v18+"}
            chunks = self.section_chunks(sid, sec)
            if not chunks:
                return {"survived": False, "reason": f"subject {sid} not in KB (revoked/deprecated) or no {sec} section"}
            body = flat(doc_body(row.document))
            if not body:
                return {"survived": False, "reason": "empty document body"}
            hits = [c["chunk_id"] for c in chunks if body in flat(c["original_text"])]
            if hits:
                return {"survived": True, "gold_chunk_ids": hits}
            # fact may straddle a chunk boundary of a split section
            joined = flat("\n".join(c["original_text"] for c in chunks))
            if body in joined:
                return {"survived": True, "gold_chunk_ids": [c["chunk_id"] for c in chunks],
                        "note": "fact straddles chunk boundary"}
            # looser, reported-only criterion: the answer's own supporting span (when the
            # answer is a verbatim extract of the document) is still present in the KB
            ans = flat(row.answer)
            span_ok = bool(ans) and ans in body and ans in joined
            return {"survived": False, "reason": "text changed between v15.1 and v19.2",
                    "answer_span_survives": span_ok}
        if src in LISTS:
            sec, prefix = LISTS[src]
            if sec is None:
                return {"survived": False, "reason": "data-component detections removed in ATT&CK v18+"}
            chunks = self.section_chunks(sid, sec)
            if not chunks:
                return {"survived": False, "reason": f"subject {sid} not in KB or no {sec} section"}
            want = ids_with_prefix(row.document, prefix) - {sid}   # subject appears in the template prefix
            if src == "techniques_parent":
                kb_text = chunks[0]["original_text"].split("\n")[1]     # overview line
                have = ids_with_prefix(kb_text, "T")
                return ({"survived": True, "gold_chunk_ids": [chunks[0]["chunk_id"]]} if want == have
                        else {"survived": False, "reason": f"parent changed: doc {want} vs kb {have}"})
            if src == "techniques_tactics":
                m = re.search(r"Tactics: ([^|\n]*)", chunks[0]["original_text"])
                have = ids_with_prefix(m.group(1) if m else "", "TACTIC")
                return ({"survived": True, "gold_chunk_ids": [chunks[0]["chunk_id"]]} if want == have
                        else {"survived": False, "reason": f"tactics changed: doc {sorted(want)} vs kb {sorted(have)}"})
            have = set()
            for c in chunks:
                have |= ids_with_prefix(c["original_text"], prefix)
            if want == have and want:
                return {"survived": True, "gold_chunk_ids": [c["chunk_id"] for c in chunks]}
            return {"survived": False, "reason": f"list changed: {len(want - have)} removed, {len(have - want)} added"}
        return {"survived": False, "reason": f"unknown template {src}"}


def main():
    df = pd.read_parquet(ATTACKQA)
    f = Filter()
    rows, stats = [], collections.defaultdict(collections.Counter)
    for i, r in enumerate(df.itertuples(index=False)):
        res = f.check(r)
        stats[r.source]["total"] += 1; stats[r.source]["survived"] += 0
        stats[r.source]["survived" if res["survived"] else "failed"] += 1
        if not res["survived"]:
            key = re.sub(r"\{.*\}|\[.*\]|\d+ removed, \d+ added|subject \S+", "…", res["reason"])
            stats[r.source]["reason: " + key] += 1
        rows.append({"row": i, "source": r.source, "subject_id": r.subject_id,
                     "human_question": bool(r.human_question), "human_answer": bool(r.human_answer),
                     "id_in_question": bool(PATTERNS["attack_id"].search(r.question)), **res})
    n = write_jsonl(TESTSET / "attackqa_survival.jsonl", rows)
    total = sum(s["total"] for s in stats.values())
    surv = sum(s["survived"] for s in stats.values())
    span = sum(1 for r in rows if r.get("answer_span_survives"))
    out = {"total": total, "survived": surv, "survival_rate": round(surv / total, 4),
           "answer_span_survives_among_failed": span,
           "loose_survival_rate": round((surv + span) / total, 4),
           "by_source": {k: dict(v) for k, v in sorted(stats.items(), key=lambda kv: -kv[1]["total"])}}
    json.dump(out, open(TESTSET / "attackqa_survival_stats.json", "w"), indent=1)
    print(f"{surv}/{total} rows survived ({surv/total:.1%}); +{span} more if only the answer span must survive "
          f"({(surv+span)/total:.1%}) -> {TESTSET/'attackqa_survival.jsonl'}")
    for src, s in out["by_source"].items():
        print(f"  {src:<42} {s['survived']:>5}/{s['total']:<5} ({s['survived']/s['total']:.0%})")


if __name__ == "__main__":
    main()
