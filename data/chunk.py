"""Section-aware chunker over the rendered KB documents.

Reads every kb/docs_*.jsonl and writes kb/chunks.jsonl with one row per chunk:

  chunk_id        "attack:T1053.007#Mitigations/0"
  doc_id          "attack:T1053.007"
  original_text   the rendered section text (or a line-boundary slice of it) — the ONLY citable field
  source_context  {source, entity_id, entity_name, entity_type, section, part, n_parts, url}
                  deterministic identifying metadata; never LLM-generated
  n_words

One chunk per section; sections longer than --max-words are split greedily at
line boundaries (lists are one item per line, so items are never cut), and a
single over-long line (a long paragraph) is split at sentence boundaries.

  python -m data.chunk [--max-words 350]
"""
from __future__ import annotations

import argparse
import collections
import re
import statistics

from .common import KB, read_jsonl, write_jsonl

_SENT = re.compile(r"(?<=[.!?])\s+(?=[A-Z(])")


def split_long_line(line: str, max_words: int) -> list[str]:
    sents = _SENT.split(line)
    out, cur, n = [], [], 0
    for s in sents:
        w = len(s.split())
        if cur and n + w > max_words:
            out.append(" ".join(cur))
            cur, n = [], 0
        cur.append(s)
        n += w
    if cur:
        out.append(" ".join(cur))
    return out


def split_section(text: str, max_words: int) -> list[str]:
    if len(text.split()) <= max_words:
        return [text]
    lines = []
    for ln in text.split("\n"):
        if len(ln.split()) > max_words:
            lines.extend(split_long_line(ln, max_words))
        else:
            lines.append(ln)
    parts, cur, n = [], [], 0
    for ln in lines:
        w = len(ln.split())
        if cur and n + w > max_words:
            parts.append("\n".join(cur).strip())
            cur, n = [], 0
        cur.append(ln)
        n += w
    if cur:
        parts.append("\n".join(cur).strip())
    return [p for p in parts if p]


def chunk_doc(doc: dict, max_words: int):
    for sec in doc["sections"]:
        parts = split_section(sec["text"], max_words)
        for i, p in enumerate(parts):
            yield {
                "chunk_id": f"{doc['doc_id']}#{sec['name'].replace(' ', '_')}/{i}",
                "doc_id": doc["doc_id"],
                "original_text": p,
                "source_context": {
                    "source": doc["source"],
                    "entity_id": doc["entity_id"],
                    "entity_name": doc["entity_name"],
                    "entity_type": doc["entity_type"],
                    "section": sec["name"],
                    "part": i,
                    "n_parts": len(parts),
                    "url": doc.get("url", ""),
                },
                "n_words": len(p.split()),
            }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-words", type=int, default=350)
    args = ap.parse_args()

    docs = []
    for f in sorted(KB.glob("docs_*.jsonl")):
        d = read_jsonl(f)
        print(f"{f.name}: {len(d)} docs")
        docs.extend(d)
    chunks = [c for d in docs for c in chunk_doc(d, args.max_words)]

    ids = [c["chunk_id"] for c in chunks]
    assert len(ids) == len(set(ids)), "duplicate chunk ids"
    assert all(c["original_text"].strip() for c in chunks), "empty chunk"
    assert all(c["source_context"]["entity_id"] and c["source_context"]["section"] for c in chunks)
    mx = max(c["n_words"] for c in chunks)
    assert mx <= args.max_words, f"chunk exceeds max words: {mx}"

    n = write_jsonl(KB / "chunks.jsonl", chunks)
    words = [c["n_words"] for c in chunks]
    print(f"wrote {n} chunks -> {KB/'chunks.jsonl'}")
    print(f"words/chunk: min {min(words)} median {statistics.median(words)} mean {statistics.mean(words):.0f} max {mx}")
    by_src = collections.Counter(c["source_context"]["source"] for c in chunks)
    by_type = collections.Counter(c["source_context"]["entity_type"] for c in chunks)
    by_sec = collections.Counter(c["source_context"]["section"] for c in chunks)
    print("by source:", dict(by_src))
    print("by entity type:", dict(by_type))
    print("by section:", dict(by_sec.most_common()))
    multi = sum(1 for c in chunks if c["source_context"]["n_parts"] > 1)
    print(f"chunks from split sections: {multi}")


if __name__ == "__main__":
    main()
