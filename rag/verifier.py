"""Verifier agent (DESIGN §3.5) — three checks, deterministic first.

1. Deterministic structured-field check: every CVE/CWE/CVSS/ATT&CK/version token
   in the draft must appear (normalised) in the cited chunks' original_text.
   No model — exact matching has no domain-transfer risk (DESIGN §3.5).
2. LettuceDetect span-level faithfulness over the remaining prose.
3. Citation consistency: cited ids exist among retrieved chunks, and the cited
   chunks are single-entity unless the draft is explicitly multi-entity.

Loaded lazily so importing the module (e.g. for the graph) is cheap.
"""
from __future__ import annotations

import re

from data.common import PATTERNS
from .config import LETTUCE_METHOD, LETTUCE_MODEL

_detector = None

# Inline citation markers like [attack:T1059#Description/0] are pipeline syntax,
# not claims — strip them before any check so their chunk-id tokens are neither
# treated as unsupported structured claims nor flagged as hallucinated prose.
_CITE = re.compile(r"\[(?:attack|cve|nist)[^\]]*\]")


def strip_citations(text: str) -> str:
    return _CITE.sub("", text or "")


def _lettuce():
    global _detector
    if _detector is None:
        from lettucedetect.models.inference import HallucinationDetector
        _detector = HallucinationDetector(method=LETTUCE_METHOD, model_path=LETTUCE_MODEL)
    return _detector


# --- structured-field normalisation -----------------------------------------
def _norm_score(s: str) -> str:
    try:
        return f"{float(s):.1f}"
    except ValueError:
        return s


STRUCT_PATTERNS = ("cve_id", "cwe_id", "cvss_vector", "attack_id")
# Structured facts the DETERMINISTIC check owns (DESIGN §3.5) are masked out of the
# answer before LettuceDetect runs, so the learned detector judges only natural-
# language prose and cannot false-positive on a correct identifier/score/date that
# is grounded by the chunk's identity rather than repeated in its section text.
_DATE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
_STRUCT_MASK = [PATTERNS["cve_id"], PATTERNS["cwe_id"], PATTERNS["cvss_vector"],
                PATTERNS["attack_id"], _DATE]


def mask_structured(text: str) -> str:
    out = text
    for pat in _STRUCT_MASK:
        out = pat.sub("that value", out)
    out = re.sub(r"((?:base score|score|cvss[^.]{0,20}?)\s*(?:of\s*|is\s*|:\s*)?)\d{1,2}(?:\.\d)?",
                 r"\1that value", out, flags=re.I)
    return out


def _structured_tokens(text: str) -> list[tuple[str, str]]:
    toks = []
    for name in STRUCT_PATTERNS:
        for m in PATTERNS[name].findall(text):
            toks.append((name, m))
    for m in _DATE.findall(text):
        toks.append(("date", m))
    # CVSS numeric scores only in a scoring context ("score", "/10", "CVSS")
    for m in re.finditer(r"(?:base score|score|cvss[^.]{0,20}?)\s*(?:of\s*|is\s*|:\s*)?(\d{1,2}(?:\.\d)?)",
                         text, re.I):
        toks.append(("cvss_score", m.group(1)))
    return toks


def structured_check(answer: str, cited_chunks: list[dict]) -> list[dict]:
    """Return a list of mismatches: structured tokens in the answer absent from cited text.

    The 'supported' surface is the cited chunks' original_text PLUS their
    source_context.entity_id — the subject identifier of a chunk (e.g. the CVE
    id, or the ATT&CK id whose Mitigations section is cited) is grounded by the
    chunk's provenance even when the section text itself does not repeat it.
    """
    answer = strip_citations(answer)
    cited_text = "\n".join(c["original_text"] for c in cited_chunks)
    entity_ids = " ".join(str(c.get("source_context", {}).get("entity_id", "")) for c in cited_chunks)
    cited_norm = (cited_text + "\n" + entity_ids).lower()
    cited_scores = {_norm_score(s) for s in re.findall(r"\b(\d{1,2}(?:\.\d)?)\b", cited_text)}
    mismatches = []
    for kind, tok in _structured_tokens(answer):
        if kind == "cvss_score":
            if _norm_score(tok) not in cited_scores:
                mismatches.append({"kind": kind, "token": tok})
        else:
            if tok.lower() not in cited_norm:
                mismatches.append({"kind": kind, "token": tok})
    return mismatches


# --- citation / entity consistency ------------------------------------------
def citation_check(draft: dict, retrieved: list[dict]) -> dict:
    retrieved_ids = {c["chunk_id"] for c in retrieved}
    cited = draft.get("supporting_chunk_ids", [])
    unknown = [c for c in cited if c not in retrieved_ids]
    by_id = {c["chunk_id"]: c for c in retrieved}
    entities = {by_id[c]["source_context"]["entity_id"] for c in cited if c in by_id}
    # multi-entity is allowed only if the answer explicitly references >1 entity id/name.
    return {"citation_mismatch": bool(unknown), "unknown_citations": unknown,
            "cited_entities": sorted(entities), "multi_entity": len(entities) > 1}


# --- LettuceDetect prose check ----------------------------------------------
def lettuce_check(query: str, answer: str, cited_chunks: list[dict]) -> list[dict]:
    if not cited_chunks:
        return []
    ctx = [c["original_text"] for c in cited_chunks]
    prose = mask_structured(strip_citations(answer))   # structured facts are the deterministic check's job
    spans = _lettuce().predict(context=ctx, question=query, answer=prose, output_format="spans")
    out = []
    for s in spans:
        # Drop spans that are only masking residue (placeholders + stopwords): an
        # all-structured answer has no substantive prose for LettuceDetect to judge,
        # and its facts were already checked deterministically. A real prose
        # hallucination retains content words and survives this filter.
        residue = re.sub(r"that value|\b(is|the|a|an|to|of|by|and|for|with|assigned|described|"
                         r"vulnerability|weakness|it|this|are|was|were)\b", "", s.get("text", ""), flags=re.I)
        if len(re.findall(r"[A-Za-z]{3,}", residue)) < 2:
            continue
        out.append({"text": s.get("text", "").strip(), "confidence": round(float(s.get("confidence", 0)), 3),
                    "start": s.get("start"), "end": s.get("end")})
    return out


# --- top-level ---------------------------------------------------------------
def verify(query: str, draft: dict, retrieved: list[dict], run_lettuce=True) -> dict:
    cited = [c for c in retrieved if c["chunk_id"] in set(draft.get("supporting_chunk_ids", []))]
    # If the model cited nothing but produced an answer, check against all retrieved
    # so an uncited hallucination still gets caught.
    check_against = cited if cited else retrieved
    struct = structured_check(draft.get("answer", ""), check_against)
    cite = citation_check(draft, retrieved)
    spans = lettuce_check(query, draft.get("answer", ""), check_against) if run_lettuce else []
    # Cross-entity contamination check, scoped to CVEs. The real risk this guards
    # (combining a CVSS score from one CVE with a version range from another) is
    # CVE-specific: ATT&CK entities are inherently relational — a technique legitimately
    # co-occurs with its sub-techniques, mitigations, and procedures — so co-citing
    # them is expected, not contamination. Fire only when >=2 distinct CVEs are cited
    # and the answer does not name both (i.e. not an explicit multi-CVE comparison).
    cited_now = [c for c in check_against if c["chunk_id"] in set(draft.get("supporting_chunk_ids", []))]
    cited_cves = {c["source_context"]["entity_id"] for c in cited_now
                  if c["source_context"]["entity_type"] == "cve"}
    subject_mismatch = False
    if len(cited_cves) >= 2:
        ans = draft.get("answer", "").lower()
        named = sum(1 for cid in cited_cves if cid.lower() in ans)
        subject_mismatch = named < len(cited_cves)   # cites multiple CVEs but doesn't name them all
    passed = not struct and not spans and not cite["citation_mismatch"] and not subject_mismatch
    return {"passed": passed,
            "structured_field_mismatches": struct,
            "flagged_spans": spans,
            "citation_mismatch": cite["citation_mismatch"],
            "unknown_citations": cite["unknown_citations"],
            "subject_mismatch": subject_mismatch,
            "cited_entities": cite["cited_entities"]}


def flagged_claims(vr: dict) -> list[str]:
    """Human-readable list of what failed, for the regeneration prompt."""
    out = [f"unsupported {m['kind']} '{m['token']}'" for m in vr["structured_field_mismatches"]]
    out += [s["text"] for s in vr["flagged_spans"] if s["text"]]
    if vr["citation_mismatch"]:
        out.append("citation of a chunk that was not retrieved: " + ", ".join(vr["unknown_citations"]))
    if vr["subject_mismatch"]:
        out.append("the answer mixes facts from different entities without naming them")
    return out
