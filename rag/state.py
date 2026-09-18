"""LangGraph state object — the inter-agent data contract (DESIGN §3.8), verbatim.

Every field below is exactly one row of the §3.8 table. `trace` and `costs`
are added for evaluation/observability (DESIGN §5.5) and are not part of the
semantic contract between agents.
"""
from __future__ import annotations

from typing import Any, Literal, TypedDict

Scope = Literal["answerable", "ambiguous", "out_of_scope", "unsafe", "resource_error"]


class RAGState(TypedDict, total=False):
    # --- input ---
    query: str
    qid: str
    # --- Router ---
    scope: Scope
    router_pass1: dict          # {label, reason, raw}
    router_pass2: dict          # {label, reason, raw} (only if pass1 != out_of_scope)
    clarifying_question: str
    # --- Retriever ---
    retrieved_chunks: list[dict]   # [{chunk_id, original_text, source_context, ...}]
    # --- Generator ---
    draft_answer: dict             # {answer, supporting_chunk_ids, confidence}
    attempts: int
    drafts: list[dict]             # every attempt, for reporting
    # --- Verifier ---
    verification_result: dict      # {passed, structured_field_mismatches, flagged_spans,
                                   #  citation_mismatch, subject_mismatch}
    verifications: list[dict]      # every attempt's result
    # --- output ---
    final_answer: str
    final_kind: Literal["answer", "abstain", "clarify", "refuse", "resource_abstain"]
    final_citations: list[str]
    # --- observability (not part of the agent contract) ---
    trace: list[dict]              # [{stage, seconds}]
    costs: list[dict]              # [{stage, role, neurons}]


def new_state(query: str, qid: str = "") -> RAGState:
    return {"query": query, "qid": qid, "attempts": 0, "drafts": [], "verifications": [],
            "trace": [], "costs": []}
