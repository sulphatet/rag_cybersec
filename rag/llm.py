"""Thin wrapper over data.common.call_llm that also parses JSON replies and
returns the neuron cost, so every agent handles the Worker identically.

The Worker's `reply` is sometimes a str and sometimes an already-parsed dict
(JSON mode) — `call_json` normalises both.
"""
from __future__ import annotations

import json
import re

from data.common import call_llm as _call_llm


def call(role: str, messages: list[dict], temperature=None, max_tokens=None) -> tuple[str, float, dict]:
    """Return (text_reply, neurons, raw)."""
    resp = _call_llm(role, messages, temperature=temperature, max_tokens=max_tokens)
    reply = resp.get("reply")
    text = json.dumps(reply) if isinstance(reply, dict) else str(reply or "")
    neurons = ((resp.get("raw") or {}).get("usage") or {}).get("neurons", 0.0) or 0.0
    return text, float(neurons), resp


def _coerce(reply):
    if isinstance(reply, dict):
        return reply
    text = str(reply or "")
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    return None


def call_json(role: str, messages: list[dict], temperature=None, max_tokens=None) -> tuple[dict | None, str, float]:
    """Return (parsed_json_or_None, raw_text, neurons)."""
    resp = _call_llm(role, messages, temperature=temperature, max_tokens=max_tokens)
    reply = resp.get("reply")
    parsed = _coerce(reply)
    text = json.dumps(reply) if isinstance(reply, dict) else str(reply or "")
    neurons = ((resp.get("raw") or {}).get("usage") or {}).get("neurons", 0.0) or 0.0
    return parsed, text, float(neurons)
