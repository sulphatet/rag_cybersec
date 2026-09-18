"""Generator agent (DESIGN §3.4).

Drafts a grounded, cited answer from retrieved chunks under a hard use-only-
retrieved-content constraint, emitting {answer, supporting_chunk_ids,
confidence}. `source_context` is passed as explicitly non-citable framing;
only `original_text` may be cited (DESIGN §3.3). The regeneration call frames a
flagged claim as evidence to excise, not to reword (DESIGN §3.5).
"""
from __future__ import annotations

import json

from .config import GEN_MAX_TOKENS, GEN_TEMPERATURE, GENERATOR_FEWSHOT, ROLE_GENERATOR
from .llm import call_json

SYS = (
    "You are a cybersecurity analyst assistant. Answer the user's question using ONLY the retrieved "
    "chunks provided for THIS question — never use outside or prior knowledge. You may cite ONLY the "
    "`original_text` of a chunk; the `source_context` (entity name/type/section) is identifying context "
    "to help you understand what a chunk is about — never quote or cite it.\n"
    "CITATION RULES (critical):\n"
    "1. Cite ONLY chunk_ids that appear in the 'Retrieved chunks' block for THIS question below. NEVER "
    "cite a chunk_id from the worked examples above (e.g. cve:CVE-0000-0001..., attack:T9999...).\n"
    "2. Cite ONLY the chunk(s) you actually drew a claim from — do not add extra citations. If your "
    "answer is about ONE entity (one CVE / one technique), cite only that entity's chunk(s).\n"
    "3. Do NOT mention any identifier (CVE, CWE, ATT&CK id, CVSS score, version) that does not appear "
    "verbatim in a retrieved chunk. Copy structured facts exactly; never approximate or invent one.\n"
    "If the retrieved chunks do not contain enough to answer, say so explicitly and set an empty "
    "supporting_chunk_ids list — do NOT fill the gap from memory.\n"
    'Respond with strict JSON only: {"answer": "<text with inline [chunk_id] citations>", '
    '"supporting_chunk_ids": ["<chunk_id>", ...], "confidence": "high|medium|low"}.'
)


def _format_chunks(chunks: list[dict]) -> str:
    blocks = []
    for c in chunks:
        sc = c["source_context"]
        blocks.append(
            f"chunk_id: {c['chunk_id']}\n"
            f"source_context (NON-CITABLE — for understanding only): "
            f"from {sc['entity_name']} ({sc['entity_type']}), section {sc['section']}\n"
            f"original_text (the ONLY citable text):\n{c['original_text']}"
        )
    return "\n\n---\n\n".join(blocks)


def _fewshot_messages() -> list[dict]:
    msgs = []
    for ex in GENERATOR_FEWSHOT:
        msgs.append({"role": "user",
                     "content": f"Question: {ex['query']}\n\nRetrieved chunks:\n{_format_chunks(ex['chunks'])}\n\nJSON:"})
        msgs.append({"role": "assistant", "content": json.dumps(ex["answer"])})
    return msgs


def _coerce_draft(parsed, raw_text) -> dict:
    if not parsed or "answer" not in parsed:
        # Fall back: treat the whole reply as the answer with no citations.
        return {"answer": raw_text.strip()[:1500], "supporting_chunk_ids": [], "confidence": "low",
                "parse_failed": True}
    cids = parsed.get("supporting_chunk_ids") or []
    if isinstance(cids, str):
        cids = [cids]
    return {"answer": str(parsed.get("answer", "")).strip(),
            "supporting_chunk_ids": [str(c) for c in cids],
            "confidence": str(parsed.get("confidence", "medium")).lower()}


def generate(query: str, chunks: list[dict]) -> tuple[dict, float]:
    msgs = [{"role": "system", "content": SYS}, *_fewshot_messages(),
            {"role": "user",
             "content": f"Question: {query}\n\nRetrieved chunks:\n{_format_chunks(chunks)}\n\nJSON:"}]
    parsed, raw, neurons = call_json(ROLE_GENERATOR, msgs, temperature=GEN_TEMPERATURE, max_tokens=GEN_MAX_TOKENS)
    return _coerce_draft(parsed, raw), neurons


def regenerate(query: str, chunks: list[dict], prev_answer: str, flagged: list[str]) -> tuple[dict, float]:
    flagged_txt = "\n".join(f"- {s}" for s in flagged) or "- (a claim not supported by the cited chunks)"
    excise = (
        "Your previous answer contained claim(s) that could not be verified against the retrieved "
        "evidence. These must be DELETED, not reworded:\n" + flagged_txt + "\n\n"
        "Write a NEW answer using only claims supported by the `original_text` of the retrieved chunks. "
        "Do not include any claim that means the same thing as a deleted one, even in different words. "
        "If removing the unsupported claim(s) leaves nothing answerable, say you cannot answer from the "
        "knowledge base and return an empty supporting_chunk_ids list."
    )
    msgs = [{"role": "system", "content": SYS}, *_fewshot_messages(),
            {"role": "user",
             "content": f"Question: {query}\n\nRetrieved chunks:\n{_format_chunks(chunks)}\n\nJSON:"},
            {"role": "assistant", "content": prev_answer},
            {"role": "user", "content": excise + "\n\nJSON:"}]
    parsed, raw, neurons = call_json(ROLE_GENERATOR, msgs, temperature=GEN_TEMPERATURE, max_tokens=GEN_MAX_TOKENS)
    return _coerce_draft(parsed, raw), neurons
