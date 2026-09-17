"""Wilson score interval for a binomial proportion (DESIGN §5 sample-size framing).

Chosen over the Wald interval because it stays well-behaved at small n and at
proportions near 0 or 1 — both expected here.
"""
from __future__ import annotations

import math


def wilson(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def fmt(successes: int, n: int) -> str:
    if n == 0:
        return "n/a"
    lo, hi = wilson(successes, n)
    return f"{successes}/{n}={successes/n:.0%} (95% CI {lo:.0%}–{hi:.0%})"
