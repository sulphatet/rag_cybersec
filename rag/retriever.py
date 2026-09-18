"""Retriever agent (DESIGN §3.3) — the only component that touches the index.

Loads the persisted hybrid index once and returns top-k chunks with provenance.
"""
from __future__ import annotations

from .config import TOP_K
from .index import HybridIndex

_index = None


def _get_index():
    global _index
    if _index is None:
        _index = HybridIndex.load()
    return _index


def retrieve(query: str, k: int = TOP_K) -> list[dict]:
    return _get_index().retrieve(query, k)
