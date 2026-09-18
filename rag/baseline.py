"""Ablation baseline: naive single-shot RAG (retrieve -> generate), no Router,
no Verifier, no retry. Run on the same 42 queries, it isolates what the
multi-agent structure buys:

  * no Router  -> the baseline cannot abstain/clarify/refuse; on the 11 items
                  whose correct behaviour is not "answer", it will over-answer.
  * no Verifier-> its drafts are never grounding-checked; running LettuceDetect
                  and the deterministic field-check *post hoc* on its outputs
                  measures the hallucinations the Verifier would have caught.

Outputs runs_baseline/<qid>.json in the same schema as rag.run, so
eval.compare can diff the two systems.

  python -m rag.baseline [--qids ...] [--force]
"""
from __future__ import annotations

import argparse
import json
import time

from data.common import QuotaExceeded, read_jsonl
from . import generator, retriever, verifier
from .config import TESTSET, ROOT

RUNS_BASE = ROOT / "runs_baseline"


def run_one(item, force=False):
    qid = item["qid"]
    out = RUNS_BASE / f"{qid}.json"
    if out.exists() and not force:
        return json.load(open(out))
    t0 = time.time()
    neurons = 0.0
    chunks = retriever.retrieve(item["query"])
    draft, n = generator.generate(item["query"], chunks)
    neurons += n
    # post-hoc grounding measurement ONLY (does not gate the answer — that is the point)
    vr = verifier.verify(item["query"], draft, chunks)
    rec = {
        "qid": qid, "query": item["query"], "system": "baseline_no_agents",
        "retrieved_chunk_ids": [c["chunk_id"] for c in chunks],
        "final_kind": "answer",                      # baseline always answers
        "final_answer": draft["answer"], "final_citations": draft.get("supporting_chunk_ids", []),
        "draft_answer": draft,
        "posthoc_verification": vr,                  # what the Verifier WOULD have flagged
        "category": item.get("category"), "expected_behaviour": item.get("expected_behaviour"),
        "total_neurons": round(neurons, 2), "total_seconds": round(time.time() - t0, 3),
    }
    RUNS_BASE.mkdir(exist_ok=True)
    json.dump(rec, open(out, "w"), indent=1, ensure_ascii=False)
    print(f"  {qid:<12} answer (posthoc passed={vr['passed']}, {rec['total_neurons']:.0f} neurons)", flush=True)
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--qids")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    items = read_jsonl(TESTSET / "queries.jsonl")
    if args.qids:
        want = set(args.qids.split(","))
        items = [q for q in items if q["qid"] in want]
    print(f"baseline (no-agents) on {len(items)} queries")
    for it in items:
        try:
            run_one(it, args.force)
        except QuotaExceeded:
            print("!! quota exhausted — progress saved; resume after reset.", flush=True)
            return
        except Exception as e:
            print(f"  {it['qid']} !! {type(e).__name__}: {str(e)[:70]}", flush=True)


if __name__ == "__main__":
    main()
