"""Run the pipeline over the test set (or an ad-hoc query) and persist full state.

Each query's complete intermediate state (router decision, retrieved chunks,
drafts, verification results, latency, neuron cost, final answer) is written to
runs/<qid>.json — this is the brief's "test queries and corresponding system
outputs" deliverable, with the LangGraph state serving as the audit trail.

  python -m rag.run --qids F1,I1,J1,K1,L1     # subset
  python -m rag.run                            # all 42 (resumable; skips existing)
  python -m rag.run --query "..."              # ad-hoc, prints, no file
  python -m rag.run --force                    # re-run even if runs/<qid>.json exists
"""
from __future__ import annotations

import argparse
import json
import time

from data.common import QuotaExceeded, read_jsonl
from .config import RUNS_DIR, TESTSET
from .graph import run_query


def _serialisable(state: dict) -> dict:
    total_neurons = sum(c["neurons"] for c in state.get("costs", []))
    total_seconds = sum(t["seconds"] for t in state.get("trace", []))
    return {
        "qid": state.get("qid"), "query": state.get("query"),
        "scope": state.get("scope"),
        "router_pass1": state.get("router_pass1"), "router_pass2": state.get("router_pass2"),
        "clarifying_question": state.get("clarifying_question"),
        "retrieved_chunks": [{"chunk_id": c["chunk_id"], "rrf_score": c.get("rrf_score"),
                              "entity_id": c["source_context"]["entity_id"],
                              "section": c["source_context"]["section"],
                              "dense_rank": c.get("dense_rank"), "bm25_rank": c.get("bm25_rank")}
                             for c in state.get("retrieved_chunks", [])],
        "retrieved_chunk_ids": [c["chunk_id"] for c in state.get("retrieved_chunks", [])],
        "attempts": state.get("attempts", 0),
        "drafts": state.get("drafts", []),
        "verifications": state.get("verifications", []),
        "final_kind": state.get("final_kind"), "final_answer": state.get("final_answer"),
        "final_citations": state.get("final_citations", []),
        "trace": state.get("trace", []), "costs": state.get("costs", []),
        "total_neurons": round(total_neurons, 2), "total_seconds": round(total_seconds, 3),
    }


def run_one(item, force=False, quiet=False) -> dict:
    qid = item["qid"]
    out_path = RUNS_DIR / f"{qid}.json"
    if out_path.exists() and not force:
        rec = json.load(open(out_path))
        if not quiet:
            print(f"  [skip] {qid} (exists) -> {rec['final_kind']}")
        return rec
    state = run_query(item["query"], qid)
    rec = _serialisable(state)
    rec["category"] = item.get("category")
    rec["expected_behaviour"] = item.get("expected_behaviour")
    rec["expected_route"] = item.get("expected_route")
    RUNS_DIR.mkdir(exist_ok=True)
    json.dump(rec, open(out_path, "w"), indent=1, ensure_ascii=False)
    if not quiet:
        print(f"  {qid:<12} {rec['scope'] or '-':<12} -> {rec['final_kind']:<15} "
              f"({rec['total_neurons']:.1f} neurons, {rec['total_seconds']:.1f}s, {rec['attempts']} gen)",
              flush=True)
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--qids", help="comma-separated subset")
    ap.add_argument("--query", help="ad-hoc query (prints, no file)")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    if args.query:
        state = run_query(args.query, "adhoc")
        print(json.dumps(_serialisable(state), indent=1, ensure_ascii=False))
        return

    items = read_jsonl(TESTSET / "queries.jsonl")
    if args.qids:
        want = set(args.qids.split(","))
        items = [q for q in items if q["qid"] in want]
    print(f"running {len(items)} queries (force={args.force})", flush=True)
    t0 = time.time()
    total_neurons = 0.0
    failed = []
    for it in items:
        try:
            run_one(it, force=args.force)
        except QuotaExceeded:
            print("\n!! quota exhausted — progress saved; re-run to resume.", flush=True)
            return
        except Exception as e:                       # transient Worker/network error: log, continue
            failed.append(it["qid"])
            print(f"  {it['qid']:<12} !! error: {type(e).__name__}: {str(e)[:80]} (will retry on re-run)",
                  flush=True)
    if failed:
        print(f"\n{len(failed)} transient failures (re-run to complete): {','.join(failed)}", flush=True)
    spent = sum(json.load(open(RUNS_DIR / f"{it['qid']}.json")).get("total_neurons", 0)
                for it in items if (RUNS_DIR / f"{it['qid']}.json").exists())
    print(f"\ndone in {time.time()-t0:.0f}s; ~{spent:.0f} neurons across {len(items)} runs")


if __name__ == "__main__":
    main()
