"""Evaluate the pipeline runs (DESIGN §5), computing metrics directly from our
own components. Consumes runs/*.json + testset/gold.jsonl; writes
eval/results.jsonl, eval/eval_stats.json, and regenerates the evaluation
sections of RESULTS.md.

Layer 1 (retrieval) and Layer 3 (behaviour) are exact and use no LLM, so they
run offline. Layer 2 (faithfulness, answer-relevancy) uses the Worker + bge and
is cached per (qid, metric) in eval/judge_cache.json so a re-run or a mid-way
quota stop never recomputes.

  python -m eval.evaluate                 # all layers (spends neurons on Layer 2)
  python -m eval.evaluate --no-llm        # Layers 1,3,4 only (offline)
  python -m eval.evaluate --qids F1,D1    # subset of Layer 2
"""
from __future__ import annotations

import argparse
import collections
import json
from datetime import date

from data.common import QuotaExceeded, read_jsonl
from rag.config import KB, RUNS_DIR, TESTSET, EVAL_DIR
from rag.llm import call_json
from rag.verifier import strip_citations
from . import metrics
from .wilson import fmt, wilson

CACHE = EVAL_DIR / "judge_cache.json"


def load_chunks_text():
    return {c["chunk_id"]: c for c in read_jsonl(KB / "chunks.jsonl")}


def load_cache():
    return json.load(open(CACHE)) if CACHE.exists() else {}


def save_cache(cache):
    json.dump(cache, open(CACHE, "w"), indent=1)


# --- embedding fn for answer relevancy --------------------------------------
_model = None


def embed(texts):
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer
        from rag.config import EMBED_MODEL
        _model = SentenceTransformer(EMBED_MODEL)
    return _model.encode(texts, normalize_embeddings=True)


CAT_LABEL = {"lookup_id": "A lookup (ID in Q)", "lookup_nl": "B lookup (ID-free)",
             "aggregate": "C aggregate", "multihop": "D multi-hop", "confusability": "E confusability",
             "cve_fact": "F CVE fact", "source_conflict": "G source conflict", "nist": "H NIST",
             "near_miss": "I near-miss", "out_of_scope": "J out-of-scope", "ambiguous": "K ambiguous",
             "dual_use": "L dual-use"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-llm", action="store_true", help="skip Layer 2 (offline layers only)")
    ap.add_argument("--qids", help="restrict Layer 2 to these qids")
    args = ap.parse_args()

    chunks = load_chunks_text()
    gold = {g["qid"]: g for g in read_jsonl(TESTSET / "gold.jsonl")}
    queries = {q["qid"]: q for q in read_jsonl(TESTSET / "queries.jsonl")}
    runs = {}
    for q in queries:
        p = RUNS_DIR / f"{q}.json"
        if p.exists():
            runs[q] = json.load(open(p))
    print(f"loaded {len(runs)}/{len(queries)} runs")
    cache = load_cache()
    results = {}

    # ------------------------------------------------------------------ Layer 1
    for qid, r in runs.items():
        g = gold.get(qid, {})
        row = {"qid": qid, "category": r.get("category"), "expected_behaviour": r.get("expected_behaviour"),
               "expected_route": r.get("expected_route"), "scope": r.get("scope"),
               "final_kind": r.get("final_kind"), "attempts": r.get("attempts", 0),
               "total_neurons": r.get("total_neurons"), "total_seconds": r.get("total_seconds")}
        gold_ids = g.get("gold_chunk_ids") or []
        if gold_ids:
            ret = r.get("retrieved_chunk_ids", [])
            row["context_recall"] = round(metrics.context_recall(ret, gold_ids), 3)
            row["context_precision"] = round(metrics.context_precision(ret, gold_ids), 3)
            row["gold_retrieved"] = bool(set(ret) & set(gold_ids))
            # Entity-level recall: was ANY chunk of the gold entity retrieved, even
            # if not the exact gold section? For a description->CWE query this is
            # the meaningful "did we find the right CVE at all" signal, separate
            # from surfacing the terse Weakness chunk that carries the CWE.
            gold_ent = {chunks[c]["source_context"]["entity_id"] for c in gold_ids if c in chunks}
            ret_ent = {chunks[c]["source_context"]["entity_id"] for c in ret if c in chunks}
            row["entity_retrieved"] = bool(gold_ent & ret_ent)
        results[qid] = row

    # ------------------------------------------------------------------ Layer 3
    # scope confusion + abstention correctness handled in aggregation below.

    # ------------------------------------------------------------------ Layer 2
    if not args.no_llm:
        want = set(args.qids.split(",")) if args.qids else None
        answered = [qid for qid, r in runs.items() if r.get("final_kind") == "answer"
                    and (want is None or qid in want)]
        print(f"Layer 2 on {len(answered)} answered items (cached where possible)")
        try:
            for qid in answered:
                r = runs[qid]
                row = results[qid]
                cited_ids = r.get("final_citations") or r.get("retrieved_chunk_ids", [])
                cited = [chunks[c] for c in cited_ids if c in chunks]
                context = "\n\n".join(c["original_text"] for c in cited)
                answer = strip_citations(r["final_answer"])
                # faithfulness
                ck = f"{qid}:faith"
                if ck not in cache:
                    cache[ck] = metrics.faithfulness(answer, context, call_json, "generator")
                    save_cache(cache)
                f = cache[ck]
                row["faithfulness"] = None if f["score"] != f["score"] else round(f["score"], 3)
                row["n_claims"] = f["n_claims"]
                # answer relevancy
                rk = f"{qid}:relev"
                if rk not in cache:
                    cache[rk] = metrics.answer_relevancy(r["query"], answer, call_json, embed, "generator")
                    save_cache(cache)
                ar = cache[rk]
                row["answer_relevancy"] = None if ar["score"] != ar["score"] else round(ar["score"], 3)
                # LettuceDetect signal (from the run's final verification)
                vr = (r.get("verifications") or [{}])[-1]
                row["lettuce_flags"] = len(vr.get("flagged_spans", []))
                # source_context leakage check
                row["source_context_leak"] = metrics.source_context_leak(answer, cited)
                print(f"  {qid}: faith={row['faithfulness']} relev={row['answer_relevancy']} "
                      f"lettuce={row['lettuce_flags']} leak={len(row['source_context_leak'])}")
        except QuotaExceeded:
            print("!! quota exhausted during Layer 2 — cached progress saved; re-run to resume.")

    # ------------------------------------------------------------------ aggregate + write
    write_results(results, runs, queries, gold, args.no_llm)


def write_results(results, runs, queries, gold, no_llm):
    EVAL_DIR.mkdir(exist_ok=True)
    metrics.wilson  # noqa
    rows = list(results.values())
    from .report import build_report
    stats = build_report(results, runs, queries, gold)
    json.dump(stats, open(EVAL_DIR / "eval_stats.json", "w"), indent=1)
    with open(EVAL_DIR / "results.jsonl", "w") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"\nwrote eval/results.jsonl and eval/eval_stats.json")
    from .report import write_results_md, write_analysis_md
    write_results_md(stats)
    write_analysis_md(stats)
    print("updated RESULTS.md evaluation section and ANALYSIS.md §3")


if __name__ == "__main__":
    main()
