"""Harness self-tests — no Worker calls, so they run offline and fast.

Checks the deterministic parts we must be able to trust before spending neurons:
index retrieval, the deterministic structured-field verifier, citation checks,
and the metric primitives. Run: python -m rag.selftest
"""
from __future__ import annotations

import sys

from data.common import read_jsonl
from .config import TESTSET
from . import verifier
from .index import HybridIndex


def check(name, cond):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    return cond


def main():
    ok = True
    idx = HybridIndex.load()
    queries = {q["qid"]: q for q in read_jsonl(TESTSET / "queries.jsonl")}

    print("index retrieval:")
    # For an ID-in-question AttackQA item, its gold chunk should be in top-5.
    a_items = [q for q in queries.values() if q["category"] == "lookup_id"]
    hits = 0
    for q in a_items:
        got = {c["chunk_id"] for c in idx.retrieve(q["query"], 5)}
        if set(q["gold_chunk_ids"]) & got:
            hits += 1
    ok &= check(f"gold chunk in top-5 for >=3/4 lookup_id items (got {hits}/{len(a_items)})", hits >= 3)

    # F1 (Log4Shell CVSS) gold chunk retrievable.
    f1 = queries.get("F1")
    if f1:
        got = {c["chunk_id"] for c in idx.retrieve(f1["query"], 5)}
        ok &= check("F1 Log4Shell severity chunk in top-5", bool(set(f1["gold_chunk_ids"]) & got))

    print("deterministic structured-field verifier:")
    chunk = [{"chunk_id": "cve:x#Severity/0",
              "original_text": "CVSS 3.1 base score 10.0 CRITICAL; vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H. Weakness CWE-917.",
              "source_context": {"entity_id": "CVE-2021-44228", "entity_name": "Log4Shell",
                                 "entity_type": "cve", "section": "Severity"}}]
    good = {"answer": "The CVSS 3.1 base score is 10.0 and the CWE is CWE-917.", "supporting_chunk_ids": ["cve:x#Severity/0"]}
    bad = {"answer": "The CVSS 3.1 base score is 7.5 and the CWE is CWE-79.", "supporting_chunk_ids": ["cve:x#Severity/0"]}
    ok &= check("correct score+CWE -> no structured mismatch",
                verifier.structured_check(good["answer"], chunk) == [])
    bad_m = verifier.structured_check(bad["answer"], chunk)
    ok &= check("wrong score (7.5) and wrong CWE (CWE-79) -> flagged",
                any(m["token"] == "7.5" for m in bad_m) and any(m["token"] == "CWE-79" for m in bad_m))

    print("citation consistency:")
    retrieved = chunk + [{"chunk_id": "cve:y#Severity/0", "original_text": "x",
                          "source_context": {"entity_id": "CVE-2, other", "entity_name": "Other",
                                             "entity_type": "cve", "section": "Severity"}}]
    cc = verifier.citation_check({"supporting_chunk_ids": ["cve:x#Severity/0"]}, retrieved)
    ok &= check("valid citation -> no mismatch", not cc["citation_mismatch"])
    cc2 = verifier.citation_check({"supporting_chunk_ids": ["cve:ZZZ#never/9"]}, retrieved)
    ok &= check("citing a non-retrieved chunk -> mismatch", cc2["citation_mismatch"])

    print("metric primitives:")
    from eval.metrics import context_recall, context_precision, wilson
    ok &= check("recall=1.0 when retrieved superset of gold (2/2)",
                context_recall(["a", "b", "c"], ["a", "b"]) == 1.0)
    ok &= check("recall=2/3 when 2 of 3 gold retrieved",
                abs(context_recall(["a", "b", "z"], ["a", "b", "c"]) - 2/3) < 1e-9)
    ok &= check("recall=0.0 when disjoint", context_recall(["a"], ["x", "y"]) == 0.0)
    ok &= check("precision=1.0 when top ranks are the relevant ones",
                abs(context_precision(["a", "b", "z"], ["a", "b"]) - 1.0) < 1e-9)
    lo, hi = wilson(8, 10)
    ok &= check("wilson(8/10) within (0,1) and lo<hi", 0 < lo < hi < 1)

    print("\n" + ("ALL SELF-TESTS PASSED" if ok else "SELF-TESTS FAILED"))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
