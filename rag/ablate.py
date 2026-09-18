"""Component ablation: isolate what the Router and the Verifier each buy.

The no-agents baseline (rag.baseline) drops BOTH the Router and the Verifier, so
it measures their *combined* effect. To attribute the effect to each component,
we run two intermediate systems that reuse the identical node functions from
`rag.graph` and change only the wiring:

  router_only    router -> retriever -> generator -> answer   (NO Verifier gate)
                 Keeps scope handling (clarify/abstain/refuse) but never grounding-
                 gates a released draft. Post-hoc verification is recorded (not
                 acted on) so ungrounded releases can be counted, exactly as the
                 baseline does. Difference vs. the full system == the Verifier.

  verifier_only  retriever -> generator -> verifier -> (answer|regenerate|abstain)
                 Keeps the grounding gate and one retry but has NO Router, so it
                 cannot clarify or refuse and never routes an out-of-scope / ID-free
                 query away before retrieval. Difference vs. full == the Router.

Outputs runs_router_only/<qid>.json and runs_verifier_only/<qid>.json in the same
schema as rag.run, so eval.ablate_compare can diff all four systems.

  python -m rag.ablate --which router_only,verifier_only [--qids ...] [--force]
"""
from __future__ import annotations

import argparse
import json
import time

from langgraph.graph import END, StateGraph

from data.common import QuotaExceeded, read_jsonl
from . import verifier
from .config import ROOT, TESTSET
from .graph import (answer_terminal, abstain_terminal, clarify_terminal,
                    generator_node, oos_terminal, refuse_terminal,
                    retriever_node, route_after_router, route_after_verifier,
                    router_node, verifier_node)
from .run import _serialisable
from .state import RAGState, new_state

RUNS = {
    "router_only": ROOT / "runs_router_only",
    "verifier_only": ROOT / "runs_verifier_only",
}


def build_router_only():
    """Router + Retriever + Generator, but the Generator's draft is released
    directly (no Verifier node, no grounding gate, no retry)."""
    g = StateGraph(RAGState)
    g.add_node("router", router_node)
    g.add_node("retriever", retriever_node)
    g.add_node("generator", generator_node)
    g.add_node("answer", answer_terminal)
    g.add_node("clarify", clarify_terminal)
    g.add_node("oos", oos_terminal)
    g.add_node("refuse", refuse_terminal)
    g.set_entry_point("router")
    g.add_conditional_edges("router", route_after_router,
                            {"retriever": "retriever", "clarify": "clarify",
                             "oos": "oos", "refuse": "refuse"})
    g.add_edge("retriever", "generator")
    g.add_edge("generator", "answer")          # <- no verifier
    for t in ("answer", "clarify", "oos", "refuse"):
        g.add_edge(t, END)
    return g.compile()


def build_verifier_only():
    """Retriever + Generator + Verifier gate (with one retry), but no Router:
    every query is treated as answerable."""
    g = StateGraph(RAGState)
    g.add_node("retriever", retriever_node)
    g.add_node("generator", generator_node)
    g.add_node("verifier", verifier_node)
    g.add_node("answer", answer_terminal)
    g.add_node("abstain", abstain_terminal)
    g.set_entry_point("retriever")             # <- no router
    g.add_edge("retriever", "generator")
    g.add_edge("generator", "verifier")
    g.add_conditional_edges("verifier", route_after_verifier,
                            {"answer": "answer", "generator": "generator", "abstain": "abstain"})
    for t in ("answer", "abstain"):
        g.add_edge(t, END)
    return g.compile()


_GRAPHS = {}


def run_query(which: str, query: str, qid: str) -> dict:
    if which not in _GRAPHS:
        _GRAPHS[which] = {"router_only": build_router_only,
                          "verifier_only": build_verifier_only}[which]()
    state = new_state(query, qid)
    try:
        state = _GRAPHS[which].invoke(state)
    except QuotaExceeded:
        state["final_kind"] = "resource_abstain"
        state["final_answer"] = ""
    # router_only releases without gating: record what the Verifier WOULD have
    # flagged, so ungrounded releases are countable (same idea as rag.baseline).
    if which == "router_only" and state.get("final_kind") == "answer":
        state["posthoc_verification"] = verifier.verify(
            query, state["draft_answer"], state["retrieved_chunks"])
    return state


def run_one(which, item, force=False):
    qid = item["qid"]
    out = RUNS[which] / f"{qid}.json"
    if out.exists() and not force:
        return json.load(open(out))
    state = run_query(which, item["query"], qid)
    rec = _serialisable(state)
    rec["system"] = which
    if "posthoc_verification" in state:
        rec["posthoc_verification"] = state["posthoc_verification"]
    rec["category"] = item.get("category")
    rec["expected_behaviour"] = item.get("expected_behaviour")
    rec["expected_route"] = item.get("expected_route")
    RUNS[which].mkdir(exist_ok=True)
    json.dump(rec, open(out, "w"), indent=1, ensure_ascii=False)
    print(f"  [{which}] {qid:<12} {rec.get('scope') or '-':<12} -> {rec['final_kind']:<12} "
          f"({rec['total_neurons']:.0f} neurons, {rec['attempts']} gen)", flush=True)
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--which", default="router_only,verifier_only",
                    help="comma-separated: router_only,verifier_only")
    ap.add_argument("--qids")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    items = read_jsonl(TESTSET / "queries.jsonl")
    if args.qids:
        want = set(args.qids.split(","))
        items = [q for q in items if q["qid"] in want]
    for which in args.which.split(","):
        which = which.strip()
        if which not in RUNS:
            print(f"!! unknown system {which}; choose from {list(RUNS)}")
            continue
        print(f"\n=== {which} on {len(items)} queries ===", flush=True)
        for it in items:
            try:
                run_one(which, it, args.force)
            except QuotaExceeded:
                print("!! quota exhausted — progress saved; resume after reset.", flush=True)
                return
            except Exception as e:
                print(f"  [{which}] {it['qid']} !! {type(e).__name__}: {str(e)[:70]}", flush=True)


if __name__ == "__main__":
    main()
