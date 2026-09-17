"""LangGraph orchestration of the 4-agent pipeline (DESIGN §3.1, §3.8).

router → (route on scope) → retriever → generator → verifier
       → (pass → answer | fail<2 → generator | fail==2 → abstain)

Every node records latency (trace) and neuron cost (costs). A QuotaExceeded
anywhere routes to a resource-abstention terminal (DESIGN §3.6).
"""
from __future__ import annotations

import time

from langgraph.graph import END, StateGraph

from data.common import QuotaExceeded
from . import generator, retriever, router, verifier
from .config import (ABSTAIN_MESSAGE, MAX_ATTEMPTS, OUT_OF_SCOPE_MESSAGE,
                     REFUSE_MESSAGE, RESOURCE_ABSTAIN_MESSAGE)
from .state import RAGState


def _timed(state, stage, fn):
    t = time.time()
    try:
        out = fn()
    finally:
        state.setdefault("trace", []).append({"stage": stage, "seconds": round(time.time() - t, 3)})
    return out


# --- nodes ------------------------------------------------------------------
def router_node(state: RAGState) -> RAGState:
    r = _timed(state, "router", lambda: router.route(state["query"]))
    state["scope"] = r["scope"]
    state["router_pass1"] = r["router_pass1"]
    state["router_pass2"] = r["router_pass2"]
    state["clarifying_question"] = r["clarifying_question"]
    state.setdefault("costs", []).append({"stage": "router", "role": "router", "neurons": r["neurons"]})
    return state


def retriever_node(state: RAGState) -> RAGState:
    chunks = _timed(state, "retriever", lambda: retriever.retrieve(state["query"]))
    state["retrieved_chunks"] = chunks
    return state


def generator_node(state: RAGState) -> RAGState:
    state["attempts"] = state.get("attempts", 0) + 1
    chunks = state["retrieved_chunks"]
    if state["attempts"] == 1:
        draft, neurons = _timed(state, "generator", lambda: generator.generate(state["query"], chunks))
    else:
        prev = state["drafts"][-1]
        flagged = verifier.flagged_claims(state["verifications"][-1])
        draft, neurons = _timed(state, "regenerate",
                                lambda: generator.regenerate(state["query"], chunks, prev["answer"], flagged))
    state["draft_answer"] = draft
    state.setdefault("drafts", []).append(draft)
    state.setdefault("costs", []).append(
        {"stage": f"generator#{state['attempts']}", "role": "generator", "neurons": neurons})
    return state


def verifier_node(state: RAGState) -> RAGState:
    vr = _timed(state, f"verifier#{state['attempts']}",
                lambda: verifier.verify(state["query"], state["draft_answer"], state["retrieved_chunks"]))
    state["verification_result"] = vr
    state.setdefault("verifications", []).append(vr)
    return state


# --- terminals --------------------------------------------------------------
def _finish(state, kind, text, citations=None):
    state["final_kind"] = kind
    state["final_answer"] = text
    state["final_citations"] = citations or []
    return state


def clarify_terminal(state):
    q = state.get("clarifying_question") or "Could you specify which vulnerability, system, or technique you mean?"
    return _finish(state, "clarify", q)


def oos_terminal(state):
    return _finish(state, "abstain", OUT_OF_SCOPE_MESSAGE)


def refuse_terminal(state):
    return _finish(state, "refuse", REFUSE_MESSAGE)


def answer_terminal(state):
    d = state["draft_answer"]
    return _finish(state, "answer", d["answer"], d.get("supporting_chunk_ids", []))


def abstain_terminal(state):
    return _finish(state, "abstain", ABSTAIN_MESSAGE)


# --- conditional edges ------------------------------------------------------
def route_after_router(state) -> str:
    return {"answerable": "retriever", "ambiguous": "clarify", "out_of_scope": "oos",
            "unsafe": "refuse"}.get(state["scope"], "retriever")


def route_after_verifier(state) -> str:
    passed = state["verification_result"]["passed"]
    cited = bool(state["draft_answer"].get("supporting_chunk_ids"))
    # A draft that passes verification but cites nothing is an ungrounded (self-
    # declining) answer — "grounded ONLY" means no citation → no answer. Abstain
    # rather than surface it (this is the correct behaviour on a near-miss where
    # the Generator itself recognised the evidence does not support an answer).
    if passed and cited:
        return "answer"
    if passed and not cited:
        return "abstain"
    if state["attempts"] < MAX_ATTEMPTS:
        return "generator"
    return "abstain"


def build_graph():
    g = StateGraph(RAGState)
    g.add_node("router", router_node)
    g.add_node("retriever", retriever_node)
    g.add_node("generator", generator_node)
    g.add_node("verifier", verifier_node)
    g.add_node("clarify", clarify_terminal)
    g.add_node("oos", oos_terminal)
    g.add_node("refuse", refuse_terminal)
    g.add_node("answer", answer_terminal)
    g.add_node("abstain", abstain_terminal)

    g.set_entry_point("router")
    g.add_conditional_edges("router", route_after_router,
                            {"retriever": "retriever", "clarify": "clarify", "oos": "oos", "refuse": "refuse"})
    g.add_edge("retriever", "generator")
    g.add_edge("generator", "verifier")
    g.add_conditional_edges("verifier", route_after_verifier,
                            {"answer": "answer", "generator": "generator", "abstain": "abstain"})
    for t in ("clarify", "oos", "refuse", "answer", "abstain"):
        g.add_edge(t, END)
    return g.compile()


_graph = None


def run_query(query: str, qid: str = "") -> RAGState:
    """Execute the pipeline on one query; resource errors degrade to abstention."""
    global _graph
    if _graph is None:
        _graph = build_graph()
    from .state import new_state
    state = new_state(query, qid)
    try:
        return _graph.invoke(state)
    except QuotaExceeded:
        return _finish(state, "resource_abstain", RESOURCE_ABSTAIN_MESSAGE)
