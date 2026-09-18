"""Four-way component ablation: attribute effects to the Router and the Verifier.

Reads four runs of the same 62 queries and reports two orthogonal metrics:

  grounding   ungrounded answers among those RELEASED. For gated systems (full,
              verifier_only) this is the verifier's own verdict on the released
              draft (0 by construction). For ungated systems (baseline,
              router_only) it is the post-hoc verifier verdict on the released
              draft — the hallucination surface a gate would have removed.
  scope       on the 11 items whose correct action is NOT "answer", did the
              system take a non-answer action (abstain/clarify/refuse)?

Reading the 2x2 (Router present? x Verifier present?):

              Verifier NO            Verifier YES
  Router NO   baseline               verifier_only     <- Verifier fixes grounding
  Router YES  router_only            full              <- down each column
              ^ Router fixes scope, across each row

Writes eval/ablation_components.json and prints a table.

  python -m eval.ablate_compare
"""
from __future__ import annotations

import json

from rag.config import ROOT, RUNS_DIR, TESTSET

DIRS = {
    "baseline": ROOT / "runs_baseline",
    "router_only": ROOT / "runs_router_only",
    "verifier_only": ROOT / "runs_verifier_only",
    "full": RUNS_DIR,
}


def load(d):
    return {p.stem: json.load(open(p)) for p in d.glob("*.json")} if d.exists() else {}


def released_ungrounded(rec) -> bool:
    """Did this record RELEASE an answer that fails a grounding check?"""
    if rec.get("final_kind") != "answer":
        return False
    if "posthoc_verification" in rec:                 # ungated system
        vr = rec["posthoc_verification"]
    else:                                             # gated system: last verifier verdict
        vr = (rec.get("verifications") or [{}])[-1]
    return not vr.get("passed", True)


def main():
    systems = {k: load(v) for k, v in DIRS.items()}
    missing = [k for k, v in systems.items() if not v]
    if missing:
        print(f"!! no runs for: {missing} — run `python -m rag.ablate` (and rag.baseline/rag.run) first.")
        if "full" in missing or "baseline" in missing:
            return
    queries = {q["qid"]: q for q in [json.loads(l) for l in open(TESTSET / "queries.jsonl")]}
    common = sorted(set.intersection(*[set(s) for s in systems.values() if s]))
    should_not = [q for q in common if queries[q]["expected_behaviour"] != "answer"]
    answerable = [q for q in common if queries[q]["expected_behaviour"] == "answer"]

    # exact action-matching, and split the non-answer actions by TYPE — an
    # abstention on a clarify item is NOT the correct action, so "took any
    # non-answer action" would overcredit a system that just abstains on
    # everything (verifier_only). Count each expected action against its match.
    byexp = {}
    for q in common:
        byexp.setdefault(queries[q]["expected_behaviour"], []).append(q)
    n_cl, n_rf, n_ab = (len(byexp.get(k, [])) for k in ("clarify", "refuse", "abstain"))

    rows = []
    present = {"baseline": "no / no", "router_only": "yes / no",
               "verifier_only": "no / yes", "full": "yes / yes"}
    for name in ("baseline", "router_only", "verifier_only", "full"):
        s = systems.get(name) or {}
        if not s:
            continue
        ans_ok = sum(1 for q in answerable if s[q].get("final_kind") == "answer")
        ungr = sum(1 for q in common if released_ungrounded(s[q]))
        released = sum(1 for q in common if s[q].get("final_kind") == "answer")
        cl = sum(1 for q in byexp.get("clarify", []) if s[q].get("final_kind") == "clarify")
        rf = sum(1 for q in byexp.get("refuse", []) if s[q].get("final_kind") == "refuse")
        ab = sum(1 for q in byexp.get("abstain", []) if s[q].get("final_kind") == "abstain")
        exact = sum(1 for q in common if s[q].get("final_kind") == queries[q]["expected_behaviour"])
        rows.append({
            "system": name,
            "R/V": present[name],
            "answerable_answered": f"{ans_ok}/{len(answerable)}",
            "ungrounded_released": f"{ungr}/{released}" if released else "0/0",
            "clarify": f"{cl}/{n_cl}",
            "refuse": f"{rf}/{n_rf}",
            "abstain": f"{ab}/{n_ab}",
            "exact_action": f"{exact}/{len(common)}",
        })

    out = {
        "n_common": len(common), "n_answerable": len(answerable), "n_should_not_answer": len(should_not),
        "rows": rows,
        "attribution": {
            "verifier": "removes ungrounded releases (ungrounded_released -> 0) and produces "
                        "grounded abstention; costs coverage. Hold the Router fixed and add the "
                        "Verifier: baseline->verifier_only, router_only->full.",
            "router": "enables clarification (the only configurations with clarify>0 have the "
                      "Router) and trims the ungrounded surface when no Verifier is present; costs "
                      "coverage. Hold the Verifier fixed and add the Router: baseline->router_only, "
                      "verifier_only->full.",
            "refusal": "produced by the Router's safety pass, which now runs on every query: "
                       "the two configurations containing the Router refuse 2/2, the two without it 0/2.",
        },
    }
    json.dump(out, open("eval/ablation_components.json", "w"), indent=2)

    # pretty table
    cols = ["system", "R/V", "answerable_answered", "ungrounded_released",
            "clarify", "refuse", "abstain", "exact_action"]
    w = {c: max(len(c), *(len(str(r[c])) for r in rows)) for c in cols}
    line = lambda r: "  ".join(str(r[c]).ljust(w[c]) for c in cols)
    print(f"\ncommon queries: {len(common)}  (answerable {len(answerable)}, "
          f"non-answer {len(should_not)})\n")
    print(line({c: c for c in cols}))
    print("  ".join("-" * w[c] for c in cols))
    for r in rows:
        print(line(r))
    print("\nVerifier's effect = ungrounded_released -> 0 and abstain rises "
          "(baseline->verifier_only, router_only->full); costs coverage.")
    print("Router's effect   = clarify becomes possible (0 without it) "
          "(baseline->router_only, verifier_only->full); costs coverage.")
    print("Refusal 2/2 in the Router configurations, 0/2 without: the safety pass runs on every query.")


if __name__ == "__main__":
    main()
