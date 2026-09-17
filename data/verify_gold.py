"""Verify test-set gold answers, three tiers (DESIGN.md Section 3.7).

Tier 1  deterministic — every answerable item's gold answer's structured facts
        (CVE/CWE/CVSS/ATT&CK/CSF tokens and, for AttackQA items, the document
        body) are present verbatim in the gold chunks. No model.
Tier 2  constrained entailment — for gold answers whose text is NOT already a
        verbatim substring of the gold chunks (i.e. LLM-written AttackQA answers
        and the authored synthesis answers), ask the Worker a closed-book
        entailment question: does the answer follow from the gold-chunk text
        alone? YES/NO + quoted span. This is a narrower task than open-ended
        correctness judgement (Krumdick et al. 2025).
Tier 3  micro-gold calibration — mix N genuine (answer, chunks) pairs with N
        corrupted pairs (an ATT&CK/CVE id swapped, a number changed, or the
        claim negated — all string-level, no domain knowledge) and run the same
        Tier-2 checker over them; report the confusion matrix so Tier 2's own
        reliability is measured, not assumed (DeepFact micro-gold, 2026).

  python -m data.verify_gold [--dry-run N] [--seed 0]

Writes testset/verification.jsonl and testset/verification_stats.json.
Reports Worker neuron spend from the responses' `raw.usage`.
"""
from __future__ import annotations

import argparse
import json
import random
import re

from .common import (KB, PATTERNS, TESTSET, call_llm, flat, read_jsonl,
                     write_jsonl)

ENTAIL_SYS = (
    "You are a strict fact-checking assistant. You are given SOURCE text and a CLAIM. "
    "Decide whether the CLAIM is fully supported by the SOURCE ALONE, using no outside "
    "knowledge. Every entity, number, and identifier in the CLAIM must be verifiable in "
    "the SOURCE. If the SOURCE does not address the claim, answer NO. "
    'Respond with strict JSON only: {"supported": true|false, "evidence": "<exact quote '
    'from SOURCE or empty>"}.'
)


def entail(source: str, claim: str) -> dict:
    msgs = [{"role": "system", "content": ENTAIL_SYS},
            {"role": "user", "content": f"SOURCE:\n{source}\n\nCLAIM:\n{claim}\n\nJSON:"}]
    resp = call_llm("generator", msgs, temperature=0.0, max_tokens=200)
    reply = resp.get("reply")
    usage = (resp.get("raw") or {}).get("usage", {})
    verdict = None
    if isinstance(reply, dict):               # Worker already parsed the JSON
        verdict = reply.get("supported")
        text = json.dumps(reply)
    else:
        text = str(reply or "")
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                verdict = json.loads(m.group(0)).get("supported")
            except json.JSONDecodeError:
                pass
    if verdict is None:                       # fall back to a keyword read
        verdict = bool(re.search(r"\b(supported|yes|true)\b", text, re.I)) and \
            not re.search(r"\bnot supported|no,|false\b", text, re.I)
    return {"supported": bool(verdict), "reply": text.strip()[:300],
            "neurons": usage.get("neurons", 0.0)}


def gold_text(chunks, ids):
    return "\n".join(chunks[c]["original_text"] for c in ids)


def tier1(item, chunks) -> dict:
    """Every declared gold fact (AttackQA document body / authored must_contain
    strings) must appear verbatim in the gold chunks. A secondary, reported-only
    scan notes any structured token in the gold answer that is not in the chunks
    (usually a subject/question echo or a markdown-link id the renderer strips)."""
    if not item["gold_chunk_ids"]:
        return {"tier1": "n/a"}
    src = flat(gold_text(chunks, item["gold_chunk_ids"]))
    facts = item.get("tier1_facts", [])
    missing_facts = [f for f in facts if flat(f) and flat(f) not in src]
    diag = {}
    for name, pat in PATTERNS.items():
        if name == "cvss_score" and item["category"] not in ("cve_fact", "source_conflict"):
            continue
        absent = [t for t in set(pat.findall(item["gold_answer"])) if flat(t) not in src]
        if absent:
            diag[name] = absent
    return {"tier1": "pass" if not missing_facts else "fail",
            "tier1_missing_facts": missing_facts,
            "answer_tokens_not_in_chunks": diag}


def corrupt(answer: str, rng) -> tuple[str, str] | None:
    """Return (corrupted_answer, strategy) using only string manipulation."""
    strategies = []
    ids = PATTERNS["attack_id"].findall(answer) + PATTERNS["cwe_id"].findall(answer) \
        + PATTERNS["cve_id"].findall(answer)
    if ids:
        strategies.append("id_swap")
    if re.search(r"\b\d+(\.\d+)?\b", answer):
        strategies.append("number_change")
    strategies.append("negate")
    strat = rng.choice(strategies)
    if strat == "id_swap":
        tok = rng.choice(ids)
        if tok.startswith("CWE-"):
            new = f"CWE-{int(tok[4:]) + 7}"
        elif tok.startswith("CVE-"):
            new = re.sub(r"\d{4,}$", lambda m: str(int(m.group()) + 11), tok)
        elif tok.startswith("T"):
            new = re.sub(r"\d{4}", lambda m: f"{(int(m.group()) + 100) % 9000 + 1000:04d}", tok, count=1)
        else:
            new = tok[0] + f"{(int(tok[1:5]) + 100) % 9000 + 1000:04d}" + tok[5:]
        return answer.replace(tok, new, 1), f"id_swap:{tok}->{new}"
    if strat == "number_change":
        m = re.search(r"\b(\d+)(\.\d+)?\b", answer)
        old = m.group(0)
        new = str(int(m.group(1)) + 1) + (m.group(2) or "")
        return answer[:m.start()] + new + answer[m.end():], f"number_change:{old}->{new}"
    return "It is not the case that " + answer[0].lower() + answer[1:], "negate"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", type=int, default=0, help="only run N Tier-2 + N Tier-3 calls")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    rng = random.Random(args.seed)

    chunks = {c["chunk_id"]: c for c in read_jsonl(KB / "chunks.jsonl")}
    items = read_jsonl(TESTSET / "queries.jsonl")
    neurons = 0.0
    results = []

    # Tier 1 (all) + collect Tier-2 candidates
    t2_cands = []
    for it in items:
        r = {"qid": it["qid"], "category": it["category"], **tier1(it, chunks)}
        if it["gold_chunk_ids"]:
            src = flat(gold_text(chunks, it["gold_chunk_ids"]))
            r["answer_verbatim_in_chunks"] = flat(it["gold_answer"]) in src
            if not r["answer_verbatim_in_chunks"]:
                t2_cands.append(it)
        results.append(r)
    byqid = {r["qid"]: r for r in results}

    # Tier 2
    t2_run = t2_cands[:args.dry_run] if args.dry_run else t2_cands
    for it in t2_run:
        src = gold_text(chunks, it["gold_chunk_ids"])
        v = entail(src, it["gold_answer"])
        neurons += v["neurons"]
        byqid[it["qid"]].update({"tier2": "pass" if v["supported"] else "fail",
                                 "tier2_reply": v["reply"]})

    # Tier 3 micro-gold
    genuine = [it for it in items if it["gold_chunk_ids"]]
    rng.shuffle(genuine)
    n3 = args.dry_run if args.dry_run else min(20, len(genuine))
    cm = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}   # positive = genuine(supported)
    micro = []
    for it in genuine[:n3]:
        src = gold_text(chunks, it["gold_chunk_ids"])
        v = entail(src, it["gold_answer"]); neurons += v["neurons"]
        cm["tp" if v["supported"] else "fn"] += 1
        micro.append({"qid": it["qid"], "kind": "genuine", "supported": v["supported"]})
        c = corrupt(it["gold_answer"], rng)
        if c:
            cans, strat = c
            v2 = entail(src, cans); neurons += v2["neurons"]
            cm["fp" if v2["supported"] else "tn"] += 1
            micro.append({"qid": it["qid"], "kind": "corrupted", "strategy": strat,
                          "supported": v2["supported"]})

    n = len(items)
    t1_pass = sum(1 for r in results if r.get("tier1") == "pass")
    t1_fail = [r["qid"] for r in results if r.get("tier1") == "fail"]
    t2_fail = [r["qid"] for r in results if r.get("tier2") == "fail"]
    acc = (cm["tp"] + cm["tn"]) / max(1, sum(cm.values()))
    stats = {"n_items": n, "dry_run": args.dry_run,
             "tier1": {"pass": t1_pass, "fail": t1_fail},
             "tier2": {"candidates": len(t2_cands), "ran": len(t2_run), "fail": t2_fail},
             "tier3_microgold": {"confusion": cm, "accuracy": round(acc, 3), "n_pairs": len(micro)},
             "worker_neurons": round(neurons, 2)}
    write_jsonl(TESTSET / "verification.jsonl", results)
    json.dump({**stats, "microgold_detail": micro}, open(TESTSET / "verification_stats.json", "w"), indent=1)
    print(json.dumps(stats, indent=1))


if __name__ == "__main__":
    main()
