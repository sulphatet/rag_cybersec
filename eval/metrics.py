"""RAGAS-style metrics, computed directly from our own components.

Implemented to the published RAGAS definitions, but using the gold labels we
already built (for retrieval — no LLM judge needed) and our own Worker +
bge-base for the generation metrics. Every metric documents its formula so the
report can state exactly what was computed.
"""
from __future__ import annotations

import re

from .wilson import wilson  # noqa: re-exported for selftest convenience


# --- Layer 1: retrieval (exact, gold-based, no LLM) --------------------------
def context_recall(retrieved_ids, gold_ids) -> float:
    """Fraction of gold-relevant chunks that were retrieved. |R ∩ G| / |G|."""
    gold = set(gold_ids)
    if not gold:
        return float("nan")
    return len(gold & set(retrieved_ids)) / len(gold)


def context_precision(retrieved_ranked, gold_ids) -> float:
    """RAGAS Context Precision (ranked): mean Precision@k over the ranks holding a
    relevant chunk. Σ_k (Precision@k · rel_k) / (#relevant retrieved)."""
    gold = set(gold_ids)
    if not gold:
        return float("nan")
    hits = 0
    weighted = 0.0
    for k, cid in enumerate(retrieved_ranked, start=1):
        if cid in gold:
            hits += 1
            weighted += hits / k
    return weighted / hits if hits else 0.0


# --- Layer 2: generation (Worker + bge) --------------------------------------
CLAIM_SYS = (
    "Break the ANSWER into a list of atomic factual claims — each a single, self-contained "
    "assertion. Ignore hedging or meta-statements ('I cannot answer', 'the evidence shows'). "
    'Respond with strict JSON only: {"claims": ["<claim>", ...]}. If there are no factual '
    'claims, return {"claims": []}.'
)
ENTAIL_SYS = (
    "You are a strict fact-checker. Given SOURCE text and a CLAIM, decide whether the CLAIM is fully "
    "supported by the SOURCE ALONE, no outside knowledge; every entity/number/identifier in the CLAIM "
    'must be verifiable in the SOURCE. Respond with strict JSON only: {"supported": true|false}.'
)


def _entail(source: str, claim: str, call_json, role):
    parsed, _, neurons = call_json(role, [{"role": "system", "content": ENTAIL_SYS},
                                          {"role": "user", "content": f"SOURCE:\n{source}\n\nCLAIM:\n{claim}\n\nJSON:"}],
                                   temperature=0.0, max_tokens=60)
    return bool(parsed and parsed.get("supported")), neurons


def faithfulness(answer: str, context: str, call_json, role) -> dict:
    """RAGAS Faithfulness: supported claims / total claims. Returns detail + neurons."""
    parsed, _, n0 = call_json(role, [{"role": "system", "content": CLAIM_SYS},
                                     {"role": "user", "content": f"ANSWER:\n{answer}\n\nJSON:"}],
                              temperature=0.0, max_tokens=400)
    claims = (parsed or {}).get("claims", []) if parsed else []
    claims = [c for c in claims if isinstance(c, str) and c.strip()]
    neurons = n0
    if not claims:
        return {"score": float("nan"), "n_claims": 0, "supported": 0, "neurons": neurons, "claim_detail": []}
    detail, supported = [], 0
    for c in claims:
        ok, n = _entail(context, c, call_json, role)
        neurons += n
        supported += int(ok)
        detail.append({"claim": c, "supported": ok})
    return {"score": supported / len(claims), "n_claims": len(claims), "supported": supported,
            "neurons": neurons, "claim_detail": detail}


QGEN_SYS = (
    "Given an ANSWER, generate {N} distinct questions that the answer would be a direct and complete "
    'response to. Respond with strict JSON only: {"questions": ["<q>", ...]}.'
)


def answer_relevancy(query: str, answer: str, call_json, embed_fn, role, n=3) -> dict:
    """RAGAS Answer Relevancy: mean cosine(bge(generated_question_i), bge(original_query))."""
    parsed, _, neurons = call_json(role, [{"role": "system", "content": QGEN_SYS.replace("{N}", str(n))},
                                          {"role": "user", "content": f"ANSWER:\n{answer}\n\nJSON:"}],
                                   temperature=0.2, max_tokens=200)
    qs = [q for q in (parsed or {}).get("questions", []) if isinstance(q, str) and q.strip()][:n]
    if not qs:
        return {"score": float("nan"), "n_questions": 0, "neurons": neurons}
    import numpy as np
    embs = embed_fn([query] + qs)              # normalized
    qv, gen = embs[0], embs[1:]
    sims = [float(np.dot(qv, g)) for g in gen]
    return {"score": sum(sims) / len(sims), "n_questions": len(qs), "neurons": neurons, "sims": sims}


# --- blurb / source_context leakage check (DESIGN §5.2) ----------------------
def source_context_leak(answer: str, cited_chunks) -> list[str]:
    """Any source_context field value quoted verbatim in the answer would be a
    contract violation (expected: none, by construction)."""
    leaks = []
    low = answer.lower()
    for c in cited_chunks:
        sc = c["source_context"]
        for field in ("source",):     # entity_name/id legitimately appear; the free 'source' string should not be quoted
            v = str(sc.get(field, "")).strip()
            if len(v) > 15 and v.lower() in low:
                leaks.append(v)
    return leaks
