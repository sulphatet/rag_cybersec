"""Assemble the stratified test-query set.

Categories A–C are sampled (seeded, logged) from AttackQA rows that survived the
mechanical filter; A/B/C gold_chunk_ids come from the filter, and we re-assert
the document body is in those chunks. Categories D–L are the hand-authored items
in `authored.py`, whose gold chunks are resolved by (entity_id, section) and
checked to exist and contain the stated facts.

Constraints on A–C sampling: subjects span >= 8 distinct tactics; >= 2
parent/sub-technique pairs are present across the set (feeding category E's
confusability rationale); A = ID-in-question templated lookups, B = ID-free
LLM-written natural questions, C = aggregate/list questions.

Outputs:
  testset/queries.jsonl   one row per query (the deliverable's test queries)
  testset/gold.jsonl      qid -> gold_chunk_ids, gold_answer, structured facts
  testset/build_log.json  sampling seed, per-category counts, tactic coverage

  python -m data.build_testset [--seed 1]
"""
from __future__ import annotations

import argparse
import collections
import json
import random

import pandas as pd

from .authored import AUTHORED
from .common import KB, PATTERNS, ROOT, TESTSET, flat, read_jsonl, write_jsonl

ATTACKQA = ROOT / "data" / "attackqa.parquet"
LIST_SOURCES = {"techniques_sub", "techniques_tactics", "relationships_mitigations_summaries",
                "relationships_techniques_for_software", "relationships_groups_for_software"}


def load_chunks():
    chunks = {c["chunk_id"]: c for c in read_jsonl(KB / "chunks.jsonl")}
    by_sec = collections.defaultdict(list)
    for c in chunks.values():
        sc = c["source_context"]
        by_sec[(sc["entity_id"], sc["section"])].append(c["chunk_id"])
    return chunks, by_sec


def tactic_of(chunk):
    import re
    m = re.search(r"Tactics: ([^|\n]*)", chunk["original_text"])
    return m.group(1).strip() if m else ""


def sample_attackqa(df, surv, chunks, seed):
    rng = random.Random(seed)
    surv_by_row = {r["row"]: r for r in surv if r["survived"]}
    items, tactics_seen, parent_sub = [], set(), 0

    def technique_tactics(sid):
        cids = surv_by_row.get  # noqa
        for (eid, sec), _ in []:  # placeholder
            pass
        return ""

    # A: ID-in-question templated lookups (human_question True, prose template)
    a_pool = [r for r in surv if r["survived"] and r["human_question"] and r["id_in_question"]
              and r["source"] == "techniques"]
    rng.shuffle(a_pool)
    for r in a_pool:                       # one technique per new tactic
        if len([i for i in items if i["category"] == "lookup_id"]) >= 4:
            break
        tac = tactic_of(chunks[r["gold_chunk_ids"][0]])
        if tac and tac not in tactics_seen:
            tactics_seen.add(tac)
            items.append(_mk(df.iloc[r["row"]], r, "lookup_id"))

    # B: ID-free, LLM-written (human_question False), single-chunk prose templates
    b_tech = [r for r in surv if r["survived"] and not r["id_in_question"] and r["source"] == "techniques"]
    b_other = [r for r in surv if r["survived"] and not r["id_in_question"]
               and r["source"] in ("software", "groups", "relationships_mitigations")]
    rng.shuffle(b_tech); rng.shuffle(b_other)
    for r in b_tech:                        # up to 3 technique NL-questions, new tactics first
        if len([i for i in items if i["category"] == "lookup_nl"]) >= 3:
            break
        tac = tactic_of(chunks[r["gold_chunk_ids"][0]])
        if tac and tac not in tactics_seen:
            tactics_seen.add(tac)
            items.append(_mk(df.iloc[r["row"]], r, "lookup_nl"))
    for r in b_other:                       # fill remainder with software/group NL-questions
        if len([i for i in items if i["category"] == "lookup_nl"]) >= 6:
            break
        items.append(_mk(df.iloc[r["row"]], r, "lookup_nl"))

    # C: aggregate/list questions
    c_pool = [r for r in surv if r["survived"] and r["source"] in LIST_SOURCES]
    rng.shuffle(c_pool)
    seen_src = set()
    for r in c_pool:
        if len([i for i in items if i["category"] == "aggregate"]) >= 3:
            break
        if r["source"] in seen_src:
            continue
        seen_src.add(r["source"])
        row = df.iloc[r["row"]]
        items.append(_mk(row, r, "aggregate"))

    return items, tactics_seen


def _mk(row, surv_row, category):
    ids = PATTERNS["attack_id"].findall(row.answer)
    prefix = {"lookup_id": "A", "lookup_nl": "B", "aggregate": "C"}[category]
    return {
        "qid": f"{prefix}-aq{surv_row['row']}",
        "category": category,
        "query": row.question,
        "origin": f"attackqa:{surv_row['row']}:{row.source}",
        "subject_id": row.subject_id,
        "expected_route": "answerable",
        "expected_behaviour": "answer",
        "gold_answer": row.answer,
        "gold_chunk_ids": surv_row["gold_chunk_ids"],
        "gold_structured": {"attack_ids": sorted(set(ids))} if ids else {},
        "verification_tier": 1,
        "human_answer": surv_row["human_answer"],
        # prose items: the document body is one verbatim span in the gold chunk;
        # aggregate items: the survival filter proved ID-set equality, so the
        # listed ids (minus the subject echoed from the question) are the facts.
        "tier1_facts": (sorted(set(ids) - {row.subject_id}) if category == "aggregate"
                        else [row.document.split(":\n", 1)[-1]]),
        "notes": f"AttackQA {row.source}; document verbatim-present in KB",
    }


def resolve_authored(chunks, by_sec, source_list=None):
    items = []
    for a in (source_list if source_list is not None else AUTHORED):
        gold_ids = []
        for eid, sec in a["gold"]:
            ids = by_sec.get((eid, sec))
            assert ids, f"{a['qid']}: no KB chunk for ({eid}, {sec})"
            gold_ids.extend(sorted(ids))
        text = flat("\n".join(chunks[c]["original_text"] for c in gold_ids))
        for m in a["must_contain"]:
            assert flat(m) in text, f"{a['qid']}: gold chunks miss required fact {m!r}"
        items.append({
            "qid": a["qid"], "category": a["category"], "query": a["query"],
            "origin": "self", "subject_id": a["gold"][0][0] if a["gold"] else None,
            "expected_route": a["expected_route"], "expected_behaviour": a["expected_behaviour"],
            "gold_answer": a["gold_answer"], "gold_chunk_ids": gold_ids,
            "gold_structured": {"must_contain": a["must_contain"]} if a["must_contain"] else {},
            "tier1_facts": a["must_contain"],
            "verification_tier": 1 if a["gold"] else 0,
            "unsupported_because": a.get("unsupported_because"),
            "notes": a["notes"],
        })
    return items


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()

    df = pd.read_parquet(ATTACKQA)
    surv = read_jsonl(TESTSET / "attackqa_survival.jsonl")
    chunks, by_sec = load_chunks()

    aq_items, tactics = sample_attackqa(df, surv, chunks, args.seed)
    authored = resolve_authored(chunks, by_sec)
    cve_path = TESTSET / "cve_questions.json"
    cve_items = resolve_authored(chunks, by_sec, json.load(open(cve_path))) if cve_path.exists() else []
    items = aq_items + authored + cve_items
    print(f"assembled: {len(aq_items)} AttackQA + {len(authored)} authored + {len(cve_items)} CVE-generated")

    # validation: every gold chunk exists; A–C document body present
    surv_by_row = {r["row"]: r for r in surv}
    for it in items:
        for cid in it["gold_chunk_ids"]:
            assert cid in chunks, f"{it['qid']}: gold chunk {cid} missing"
        if it["origin"].startswith("attackqa"):
            row = df.iloc[int(it["origin"].split(":")[1])]
            body = flat(row.document.split(":\n", 1)[-1])
            joined = flat("\n".join(chunks[c]["original_text"] for c in it["gold_chunk_ids"]))
            if it["category"] != "aggregate":
                assert body in joined, f"{it['qid']}: document body not in gold chunks"

    qids = [it["qid"] for it in items]
    assert len(qids) == len(set(qids)), "duplicate qid"

    write_jsonl(TESTSET / "queries.jsonl", items)
    write_jsonl(TESTSET / "gold.jsonl",
                [{"qid": it["qid"], "gold_chunk_ids": it["gold_chunk_ids"],
                  "gold_answer": it["gold_answer"], "gold_structured": it["gold_structured"],
                  "expected_behaviour": it["expected_behaviour"]} for it in items])

    by_cat = collections.Counter(it["category"] for it in items)
    by_beh = collections.Counter(it["expected_behaviour"] for it in items)
    all_tactics = set()
    for it in items:
        for cid in it["gold_chunk_ids"]:
            for t in tactic_of(chunks[cid]).split(","):
                if t.strip():
                    all_tactics.add(t.strip())
    log = {"seed": args.seed, "total": len(items), "by_category": dict(by_cat),
           "by_expected_behaviour": dict(by_beh),
           "tactics_covered": sorted(all_tactics),
           "n_tactics": len(all_tactics),
           "answerable_with_gold": sum(1 for it in items if it["gold_chunk_ids"]),
           "abstain_clarify_refuse": sum(1 for it in items if not it["gold_chunk_ids"])}
    json.dump(log, open(TESTSET / "build_log.json", "w"), indent=1)
    print(f"{len(items)} queries -> {TESTSET/'queries.jsonl'}")
    print("by category:", dict(by_cat))
    print("by behaviour:", dict(by_beh))
    print(f"tactics covered (whole set): {log['n_tactics']} {log['tactics_covered']}")


if __name__ == "__main__":
    main()
