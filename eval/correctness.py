"""Answer correctness vs. gold — the metric the four RAGAS-style layers omit.

Faithfulness asks "is the answer supported by the retrieved chunk"; correctness
asks "is the answer *right*". They diverge exactly on the near-miss failures
(I2/I5: faithful to a chunk that answers the wrong question). We score:

  structured categories (cve_fact, source_conflict, nist, aggregate,
  confusability, cve_desc): DETERMINISTIC — every gold fact must appear in the
  answer (cve_desc gold is the NVD CWE, an exact token, so a description->CWE
  answer is scored the same way as an id-bearing CVE fact — no judge needed)
  under the verifier's own normalization (so "8.8 (HIGH)" == "8.8 HIGH",
  "10.0" == "10"). No LLM, fully independent of the generator.

  prose categories (lookup_id, lookup_nl, multihop): EQUIVALENCE JUDGE — the
  system answer must convey the gold answer's facts (bidirectional entailment),
  via the Worker, calibrated with micro-gold so its own reliability is reported
  (run separately, needs the Worker; deterministic part runs offline).

  python -m eval.correctness            # deterministic now; prose judged if --llm
  python -m eval.correctness --llm      # also run the equivalence judge (neurons)
"""
from __future__ import annotations

import argparse
import json
import re

from data.common import PATTERNS, flat
from rag.config import RUNS_DIR, TESTSET
from rag.verifier import strip_citations

STRUCTURED_CATS = {"cve_fact", "source_conflict", "nist", "aggregate", "confusability", "cve_desc"}
PROSE_CATS = {"lookup_id", "lookup_nl", "multihop"}


def _norm_num(s: str) -> str:
    try:
        return f"{float(s):.1f}"
    except ValueError:
        return s.lower()


def fact_present(fact: str, answer: str) -> bool:
    """Is one gold fact present in the answer, tolerant of formatting?

    A fact may be a structured token (CWE-917, CVSS vector, 8.8 HIGH, a date, an
    ATT&CK id) or a short phrase. Structured tokens are matched by normalized
    extraction; phrases fall back to whitespace-insensitive substring, and to a
    token-recall threshold for multiword source labels."""
    a = flat(answer).lower()
    ff = flat(fact)
    if not ff:
        return True
    # direct, formatting-insensitive
    if ff.lower() in a:
        return True
    # structured tokens anywhere in the fact must each appear in the answer
    toks = []
    for name in ("cve_id", "cwe_id", "cvss_vector", "attack_id"):
        toks += [(name, m) for m in PATTERNS[name].findall(fact)]
    toks += [("date", m) for m in re.findall(r"\b\d{4}-\d{2}-\d{2}\b", fact)]
    if toks:
        return all(t.lower() in a for _, t in toks)
    # "8.8 HIGH" style score+severity: check the number (normalized) and the word
    m = re.match(r"^\s*(\d{1,2}(?:\.\d)?)\s+([a-z]+)\s*$", ff, re.I)
    if m:
        num, sev = _norm_num(m.group(1)), m.group(2).lower()
        return sev in a and (num in a or m.group(1) in a)
    # email-style source identifier (nvd@nist.gov, secure@citrix.com): the
    # organisation is conveyed by its local-part OR first domain label; an answer
    # that names the org ("NVD", "Citrix") satisfies it.
    em = re.match(r"^([a-z0-9._-]+)@([a-z0-9-]+)\.", ff.lower())
    if em:
        return em.group(1) in a or em.group(2) in a
    # multiword label or name: token recall
    words = [w for w in re.findall(r"[a-z0-9._-]+", ff.lower()) if len(w) > 2]
    if words:
        hit = sum(1 for w in words if w in a)
        return hit / len(words) >= 0.6
    return False


def deterministic_correct(item, answer) -> dict:
    facts = [f for f in item.get("tier1_facts", []) if flat(f)]
    if not facts:
        return {"method": "deterministic", "correct": None, "detail": "no structured gold facts"}
    ans = strip_citations(answer)
    present = [(f, fact_present(f, ans)) for f in facts]
    return {"method": "deterministic", "correct": all(p for _, p in present),
            "facts_present": sum(p for _, p in present), "n_facts": len(present),
            "misses": [f for f, p in present if not p]}


# --- equivalence judge (prose; needs the Worker) ----------------------------
EQUIV_SYS = (
    "You compare a REFERENCE answer with a CANDIDATE answer to the same question. "
    "Say whether the CANDIDATE conveys the same key facts as the REFERENCE (it may add "
    "correct detail or paraphrase, but must not omit a key fact, contradict it, or answer "
    "about a different entity). Judge facts, not wording. "
    'Respond with strict JSON only: {"equivalent": true|false, "reason": "<short>"}.'
)


def equivalence_correct(question, gold_answer, answer, call_json, role):
    from rag.verifier import strip_citations as sc
    parsed, _, neurons = call_json(role, [{"role": "system", "content": EQUIV_SYS},
        {"role": "user", "content": f"QUESTION:\n{question}\n\nREFERENCE:\n{gold_answer}\n\n"
                                    f"CANDIDATE:\n{sc(answer)}\n\nJSON:"}],
        temperature=0.0, max_tokens=120)
    ok = bool(parsed and parsed.get("equivalent"))
    return {"method": "equivalence", "correct": ok, "neurons": neurons,
            "reason": (parsed or {}).get("reason", "")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--llm", action="store_true", help="also run the prose equivalence judge (neurons)")
    ap.add_argument("--runs", default=str(RUNS_DIR), help="runs directory to score (default: the 3B runs/)")
    ap.add_argument("--out", default="eval/correctness.json", help="output path")
    args = ap.parse_args()
    from pathlib import Path
    runs_dir = Path(args.runs)
    queries = {q["qid"]: q for q in [json.loads(l) for l in open(TESTSET / "queries.jsonl")]}
    gold = {g["qid"]: g for g in [json.loads(l) for l in open(TESTSET / "gold.jsonl")]}
    faith = {}
    try:
        jc = json.load(open("eval/judge_cache.json"))
        faith = {k[:-6]: v.get("score") for k, v in jc.items() if k.endswith(":faith")}
    except Exception:
        pass

    call_json = None
    if args.llm:
        from rag.llm import call_json as cj
        call_json = cj

    rows, neurons = [], 0.0
    for f in sorted(runs_dir.glob("*.json")):
        r = json.load(open(f))
        qid = r["qid"]
        if r["final_kind"] != "answer":
            continue
        item = queries[qid]
        cat = item["category"]
        if cat in STRUCTURED_CATS:
            res = deterministic_correct(item, r["final_answer"])
        elif cat in PROSE_CATS and args.llm:
            res = equivalence_correct(item["query"], gold[qid]["gold_answer"], r["final_answer"],
                                      call_json, "generator")
            neurons += res.get("neurons", 0)
        else:
            res = {"method": "pending_judge" if cat in PROSE_CATS else "n/a", "correct": None}
        rows.append({"qid": qid, "category": cat, "faithfulness": faith.get(qid), **res})

    json.dump(rows, open(args.out, "w"), indent=1)
    scored = [r for r in rows if r["correct"] is not None]
    corr = sum(1 for r in scored if r["correct"])
    det = [r for r in scored if r["method"] == "deterministic"]
    det_c = sum(1 for r in det if r["correct"])
    print(f"scored {len(scored)}/{len(rows)} answered items | correct {corr}/{len(scored)}")
    print(f"  deterministic (structured cats): {det_c}/{len(det)} correct")
    # faithfulness vs correctness divergence
    div = [r for r in scored if isinstance(r["faithfulness"], (int, float))
           and r["faithfulness"] >= 0.9 and not r["correct"]]
    print(f"\nFAITHFUL (>=0.9) BUT NOT CORRECT: {len(div)}")
    for r in div:
        print(f"  {r['qid']:<10}{r['category']:<15} faith={r['faithfulness']} misses={r.get('misses', r.get('reason',''))}")
    if args.llm:
        print(f"\nequivalence-judge neurons: {neurons:.0f}")
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
