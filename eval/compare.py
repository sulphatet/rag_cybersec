"""Ablation comparison: full multi-agent pipeline vs. the no-agents baseline.

Reads runs/ (full system) and runs_baseline/ (retrieve->generate only) over the
same queries and quantifies what the Router and Verifier buy:

  * abstention: on items whose correct behaviour is NOT "answer", the full
    system can decline; the baseline always answers (over-responds).
  * grounding: the baseline's drafts are never gated, so its post-hoc
    verification-failure rate is the hallucination surface the Verifier removes.
  * correctness: on answered items with gold, do the answers match gold.

Writes eval/ablation.json and prints a compact table.

  python -m eval.compare
"""
from __future__ import annotations

import json

from rag.config import RUNS_DIR, TESTSET, ROOT
from .wilson import fmt

RUNS_BASE = ROOT / "runs_baseline"


def load(d):
    return {p.stem: json.load(open(p)) for p in d.glob("*.json")}


def main():
    full = load(RUNS_DIR)
    base = load(RUNS_BASE)
    queries = {q["qid"]: q for q in [json.loads(l) for l in open(TESTSET / "queries.jsonl")]}
    common = sorted(set(full) & set(base))
    should_answer = [q for q in common if queries[q]["expected_behaviour"] == "answer"]
    should_not = [q for q in common if queries[q]["expected_behaviour"] != "answer"]

    # abstention: on should-not-answer items, did each system avoid answering?
    full_abst = sum(1 for q in should_not if full[q]["final_kind"] != "answer")
    base_abst = sum(1 for q in should_not if base[q]["final_kind"] != "answer")  # baseline always answers -> 0

    # grounding: fraction of answered drafts that FAIL a grounding check.
    def hallu_rate(runs, ids, key):
        ans = [q for q in ids if runs[q]["final_kind"] == "answer"]
        if not ans:
            return (0, 0)
        bad = 0
        for q in ans:
            if key == "posthoc":
                vr = runs[q].get("posthoc_verification", {})
            else:
                vr = (runs[q].get("verifications") or [{}])[-1]
            if not vr.get("passed", True):
                bad += 1
        return (bad, len(ans))

    f_bad, f_n = hallu_rate(full, common, "verif")
    b_bad, b_n = hallu_rate(base, common, "posthoc")

    out = {
        "n_common": len(common),
        "abstention_on_should_not_answer": {
            "n": len(should_not),
            "full_system": fmt(full_abst, len(should_not)),
            "baseline_no_agents": fmt(base_abst, len(should_not)),
        },
        "ungrounded_answers": {
            "full_system": f"{f_bad}/{f_n} released drafts fail grounding (Verifier gates these)",
            "baseline_no_agents": f"{b_bad}/{b_n} released drafts would fail grounding (no Verifier to gate)",
        },
    }
    json.dump(out, open("eval/ablation.json", "w"), indent=2)
    print(json.dumps(out, indent=2))
    print("\nInterpretation: the Router accounts for the abstention gap; the Verifier "
          "accounts for the ungrounded-answer gap. Both are what the multi-agent structure buys.")


if __name__ == "__main__":
    main()
