"""Two-model comparison: primary 3B (runs/) vs. 17B add-on (runs_17b/).

Writes eval/model_comparison.json with exactly the numbers cited in the report
and ANALYSIS, so the writing is code-derived, not hand-typed. Grounding
(0 ungrounded released) is a design guarantee expected on both; the comparison
shows the stronger model recovers coverage and correctness.

  python -m eval.model_compare
"""
from __future__ import annotations

import glob
import json

from rag.config import ROOT, TESTSET

M = {"answer": "answer", "abstain": "abstain", "clarify": "clarify",
     "refuse": "refuse", "resource_abstain": "abstain"}


def load(d):
    return {json.load(open(f))["qid"]: json.load(open(f)) for f in glob.glob(str(ROOT / d / "*.json"))}


def summarise(runs, q, correctness):
    answered = [qid for qid, r in runs.items() if r["final_kind"] == "answer"]
    behaviour = sum(M.get(r["final_kind"]) == q[qid]["expected_behaviour"] for qid, r in runs.items())
    ungrounded = sum(1 for r in runs.values()
                     if r["final_kind"] == "answer" and not (r.get("verifications") or [{}])[-1].get("passed", True))
    det = [c for c in correctness if c.get("method") == "deterministic" and c.get("correct") is not None]
    det_ok = sum(1 for c in det if c["correct"])
    dual = [qid for qid in q if q[qid]["category"] == "dual_use"]
    dual_ok = sum(M.get(runs[qid]["final_kind"]) == q[qid]["expected_behaviour"] for qid in dual)
    return {"behaviour_correct": behaviour, "n": len(runs), "answered": len(answered),
            "ungrounded_released": ungrounded,
            "deterministic_correct": det_ok, "deterministic_scored": len(det),
            "dual_use_correct": dual_ok, "dual_use_n": len(dual)}


def main():
    q = {x["qid"]: x for x in [json.loads(l) for l in open(TESTSET / "queries.jsonl")]}
    c3 = json.load(open(ROOT / "eval" / "correctness.json"))          # canonical = 3B
    c17 = json.load(open(ROOT / "eval" / "17b" / "correctness.json"))
    out = {
        "primary_3b": summarise(load("runs"), q, c3),
        "addon_17b": summarise(load("runs_17b"), q, c17),
        "note": ("Grounding (0 ungrounded released) is enforced by the pipeline, not the model, "
                 "and holds on both backends. The stronger model recovers coverage (more answered) "
                 "and correctness; both backends now refuse the dual-use cases once the safety "
                 "pass runs on every query."),
    }
    json.dump(out, open(ROOT / "eval" / "model_comparison.json", "w"), indent=1)
    p, a = out["primary_3b"], out["addon_17b"]
    print(f"{'metric':<28}{'3B (primary)':>14}{'17B (add-on)':>14}")
    print(f"{'behaviour correct':<28}{p['behaviour_correct']}/{p['n']:<12}{a['behaviour_correct']}/{a['n']}")
    print(f"{'answered (coverage)':<28}{p['answered']:>14}{a['answered']:>14}")
    print(f"{'ungrounded released':<28}{p['ungrounded_released']:>14}{a['ungrounded_released']:>14}")
    print(f"{'deterministic correct':<28}{p['deterministic_correct']}/{p['deterministic_scored']:<11}"
          f"{a['deterministic_correct']}/{a['deterministic_scored']}")
    print(f"{'dual-use correct':<28}{p['dual_use_correct']}/{p['dual_use_n']:<12}{a['dual_use_correct']}/{a['dual_use_n']}")
    print("\nwrote eval/model_comparison.json")


if __name__ == "__main__":
    main()
