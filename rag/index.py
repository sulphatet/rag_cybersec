"""Hybrid retrieval index (the Retriever agent's backend).

Dense (bge-base-en-v1.5 + FAISS inner-product over normalized vectors) and
sparse (BM25) indexes are built over the same KB chunks and fused with
Reciprocal Rank Fusion (RRF), which combines two rankings without needing the
cosine and BM25 score scales to be comparable.

  python -m rag.index --rebuild      # build + persist (one-time, ~minutes CPU)
  python -m rag.index --query "..."  # ad-hoc retrieval check

Persisted to index/: faiss.bin, embeddings.npy, chunks.pkl, bm25.pkl, meta.json
"""
from __future__ import annotations

import argparse
import json
import pickle
import re
import time

import numpy as np

from .config import (BGE_QUERY_PREFIX, BM25_POOL, DENSE_POOL, EMBED_MODEL,
                     INDEX_DIR, KB, RRF_K, TOP_K)

_WORD = re.compile(r"[a-z0-9][a-z0-9.\-/]*")


def tokenize(text: str) -> list[str]:
    return _WORD.findall(text.lower())


def embed_text(chunk: dict) -> str:
    """Document-side text: entity id + name + section give deterministic context
    (DESIGN §3.3). The entity_id is included because many chunks (a CVE's
    Severity/Weakness sections, a technique's Mitigations section) do not repeat
    their own identifier in the section text, so without this a query naming the
    entity by id could not retrieve those sections."""
    sc = chunk["source_context"]
    return f"{sc['entity_id']} {sc['entity_name']} [{sc['section']}]\n{chunk['original_text']}"


class HybridIndex:
    def __init__(self, chunks, embeddings, faiss_index, bm25):
        self.chunks = chunks
        self.by_id = {c["chunk_id"]: c for c in chunks}
        self.embeddings = embeddings
        self.faiss = faiss_index
        self.bm25 = bm25
        self._model = None

    # -- build / persist -------------------------------------------------
    @classmethod
    def build(cls, verbose=True):
        import faiss
        from rank_bm25 import BM25Okapi
        from sentence_transformers import SentenceTransformer

        chunks = [json.loads(l) for l in open(KB / "chunks.jsonl") if l.strip()]
        if verbose:
            print(f"embedding {len(chunks)} chunks with {EMBED_MODEL} ...")
        model = SentenceTransformer(EMBED_MODEL)
        t = time.time()
        emb = model.encode([embed_text(c) for c in chunks], batch_size=64,
                           normalize_embeddings=True, show_progress_bar=verbose).astype("float32")
        if verbose:
            print(f"  embedded in {time.time()-t:.1f}s; dim={emb.shape[1]}")
        faiss_index = faiss.IndexFlatIP(emb.shape[1])
        faiss_index.add(emb)
        bm25 = BM25Okapi([tokenize(embed_text(c)) for c in chunks])
        idx = cls(chunks, emb, faiss_index, bm25)
        idx._model = model
        return idx

    def save(self):
        import faiss
        INDEX_DIR.mkdir(exist_ok=True)
        faiss.write_index(self.faiss, str(INDEX_DIR / "faiss.bin"))
        np.save(INDEX_DIR / "embeddings.npy", self.embeddings)
        with open(INDEX_DIR / "chunks.pkl", "wb") as f:
            pickle.dump(self.chunks, f)
        with open(INDEX_DIR / "bm25.pkl", "wb") as f:
            pickle.dump(self.bm25, f)
        json.dump({"model": EMBED_MODEL, "n_chunks": len(self.chunks),
                   "dim": int(self.embeddings.shape[1])},
                  open(INDEX_DIR / "meta.json", "w"), indent=1)

    @classmethod
    def load(cls):
        import faiss
        chunks = pickle.load(open(INDEX_DIR / "chunks.pkl", "rb"))
        emb = np.load(INDEX_DIR / "embeddings.npy")
        faiss_index = faiss.read_index(str(INDEX_DIR / "faiss.bin"))
        bm25 = pickle.load(open(INDEX_DIR / "bm25.pkl", "rb"))
        return cls(chunks, emb, faiss_index, bm25)

    @property
    def model(self):
        if self._model is None:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(EMBED_MODEL)
        return self._model

    # -- retrieval -------------------------------------------------------
    def _dense_ranking(self, query: str, n: int) -> list[int]:
        q = self.model.encode([BGE_QUERY_PREFIX + query], normalize_embeddings=True).astype("float32")
        _, idx = self.faiss.search(q, n)
        return list(idx[0])

    def _bm25_ranking(self, query: str, n: int) -> list[int]:
        scores = self.bm25.get_scores(tokenize(query))
        return list(np.argsort(scores)[::-1][:n])

    def retrieve(self, query: str, k: int = TOP_K) -> list[dict]:
        """Return top-k fused chunks with provenance (chunk_id, original_text, source_context)."""
        dense = self._dense_ranking(query, DENSE_POOL)
        sparse = self._bm25_ranking(query, BM25_POOL)
        dense_rank = {ci: r for r, ci in enumerate(dense)}
        sparse_rank = {ci: r for r, ci in enumerate(sparse)}
        rrf = {}
        for ci in set(dense) | set(sparse):
            s = 0.0
            if ci in dense_rank:
                s += 1.0 / (RRF_K + dense_rank[ci])
            if ci in sparse_rank:
                s += 1.0 / (RRF_K + sparse_rank[ci])
            rrf[ci] = s
        order = sorted(rrf, key=lambda ci: rrf[ci], reverse=True)[:k]
        out = []
        for ci in order:
            c = self.chunks[ci]
            out.append({"chunk_id": c["chunk_id"], "original_text": c["original_text"],
                        "source_context": c["source_context"],
                        "rrf_score": round(rrf[ci], 5),
                        "dense_rank": dense_rank.get(ci), "bm25_rank": sparse_rank.get(ci)})
        return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rebuild", action="store_true")
    ap.add_argument("--query")
    ap.add_argument("-k", type=int, default=TOP_K)
    args = ap.parse_args()

    if args.rebuild or not (INDEX_DIR / "faiss.bin").exists():
        idx = HybridIndex.build()
        idx.save()
        print(f"index built and saved to {INDEX_DIR} ({len(idx.chunks)} chunks)")
    else:
        idx = HybridIndex.load()
        print(f"loaded index ({len(idx.chunks)} chunks)")

    if args.query:
        for r in idx.retrieve(args.query, args.k):
            print(f"  {r['rrf_score']:.4f}  {r['chunk_id']:<45} (d{r['dense_rank']}/b{r['bm25_rank']})")
            print(f"        {r['original_text'][:110].splitlines()[0]}")


if __name__ == "__main__":
    main()
