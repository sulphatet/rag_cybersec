"""Shared helpers for the dataset-construction scripts.

Everything here is deliberately deterministic and dependency-light. The text
normalisation in `normalise_text` is the *only* transformation applied to
source prose before it is rendered into the KB, so it is defined once and
reused by the renderers, the AttackQA survival filter, and the verifier.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "raw"
KB = ROOT / "kb"
TESTSET = ROOT / "testset"

ATTACK_VERSION = "19.2"
ATTACK_BUNDLE = RAW / f"enterprise-attack-{ATTACK_VERSION}.json"
ATTACK_BUNDLE_OLD = RAW / "enterprise-attack-15.1.json"  # AttackQA's source version
ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack-{ver}.json"
)
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NIST_PDF_URL = "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf"
ATTACKQA_URL = "https://huggingface.co/datasets/sambanovasystems/attackqa/resolve/main/attackqa.parquet"

# ---------------------------------------------------------------------------
# Text normalisation
# ---------------------------------------------------------------------------
_CITATION = re.compile(r"\s*\(Citation: [^)]*\)")
_MD_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
_HTML = re.compile(r"<[^>]+>")
_WS = re.compile(r"[ \t]+")


def normalise_text(s: str | None) -> str:
    """Strip ATT&CK citation markers, markdown links and HTML; collapse spaces.

    Paragraph breaks are preserved (so rendered pages stay readable); use
    `flat()` when comparing strings.
    """
    s = s or ""
    s = _CITATION.sub("", s)
    s = _MD_LINK.sub(r"\1", s)
    s = _HTML.sub("", s)
    s = s.replace("\r\n", "\n")
    s = _WS.sub(" ", s)
    s = re.sub(r" *\n *", "\n", s)
    s = re.sub(r"\n{3,}", "\n\n", s)
    return s.strip()


def flat(s: str | None) -> str:
    """Whitespace-insensitive form used for substring/equality checks."""
    return re.sub(r"\s+", " ", normalise_text(s)).strip()


# ---------------------------------------------------------------------------
# Structured-fact patterns (shared with the runtime Verifier later)
# ---------------------------------------------------------------------------
PATTERNS = {
    "attack_id": re.compile(r"\b(?:T\d{4}(?:\.\d{3})?|TA\d{4}|M\d{4}|S\d{4}|G\d{4}|C\d{4}|DET\d{4}|AN\d{4})\b"),
    "cve_id": re.compile(r"\bCVE-\d{4}-\d{4,}\b"),
    "cwe_id": re.compile(r"\bCWE-\d+\b"),
    "cvss_vector": re.compile(r"\bCVSS:[234]\.\d/[A-Z]{1,3}:[A-Z](?:/[A-Z]{1,3}:[A-Z])+\b"),
    "cvss_score": re.compile(r"\b(?:10(?:\.0)?|[0-9](?:\.[0-9])?)\b(?=\s*(?:/10|\(|,|\.|$|\s))"),
    "csf_id": re.compile(r"\b[A-Z]{2}\.[A-Z]{2}(?:-\d{2})?\b"),
}


# ---------------------------------------------------------------------------
# STIX helpers
# ---------------------------------------------------------------------------
def ext_id(obj: dict) -> str | None:
    for r in obj.get("external_references", []):
        if r.get("source_name") == "mitre-attack" and r.get("external_id"):
            return r["external_id"]
    return None


def is_live(obj: dict) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def load_bundle(path: Path = ATTACK_BUNDLE) -> list[dict]:
    with open(path) as f:
        return json.load(f)["objects"]


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------
def download(url: str, dest: Path, force: bool = False) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and not force:
        return dest
    with requests.get(url, stream=True, timeout=120) as r:
        r.raise_for_status()
        with open(dest, "wb") as f:
            for chunk in r.iter_content(1 << 20):
                f.write(chunk)
    return dest


class NvdClient:
    """Keyless NVD API 2.0 client honouring the public 5 req / 30 s limit."""

    def __init__(self, min_interval: float = 6.5):
        self.min_interval = min_interval
        self._last = 0.0

    def _throttle(self):
        wait = self.min_interval - (time.time() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.time()

    def get(self, **params) -> dict:
        for attempt in range(5):
            self._throttle()
            try:
                r = requests.get(NVD_URL, params=params, timeout=60)
            except requests.exceptions.RequestException:
                time.sleep(5 * (attempt + 1))     # transient network error (timeout/reset): back off
                continue
            if r.status_code == 200:
                return r.json()
            if r.status_code in (403, 429, 503):
                time.sleep(15 * (attempt + 1))
                continue
            r.raise_for_status()
        raise RuntimeError(f"NVD request failed after retries: {params}")

    def cve(self, cve_id: str) -> dict:
        d = self.get(cveId=cve_id)
        vulns = d.get("vulnerabilities", [])
        if not vulns:
            raise KeyError(cve_id)
        return vulns[0]["cve"]


# ---------------------------------------------------------------------------
# Cloudflare Worker LLM client
# ---------------------------------------------------------------------------
class QuotaExceeded(RuntimeError):
    pass


def load_env():
    load_dotenv(ROOT / ".env")
    key, url = os.environ.get("WORKER_AUTH_KEY"), os.environ.get("WORKER_URL")
    if not key or not url:
        raise RuntimeError("WORKER_AUTH_KEY / WORKER_URL missing from .env")
    return key, url


LOCAL_LLM_URL = os.environ.get("LOCAL_LLM_URL", "http://127.0.0.1:8080/v1/chat/completions")


def _call_local(role, messages, temperature, max_tokens, retries):
    """Backend for a self-hosted OpenAI-compatible server (llama.cpp on the M4).

    One model serves every role (role is recorded, not used to switch models).
    Returns the Worker's response shape so callers are backend-agnostic; token
    counts stand in for the Worker's `neurons` cost field."""
    body = {"model": "local", "messages": messages,
            "temperature": 0.0 if temperature is None else temperature,
            "max_tokens": max_tokens or 700}
    for attempt in range(retries + 1):
        try:
            r = requests.post(LOCAL_LLM_URL, json=body, timeout=300)
        except requests.exceptions.RequestException as e:
            if attempt < retries:
                time.sleep(2 ** attempt); continue
            raise RuntimeError(f"local LLM error after retries: {e}")
        if r.status_code == 200:
            d = r.json()
            reply = d["choices"][0]["message"]["content"]
            usage = d.get("usage", {})
            return {"role": role, "model": "local:qwen2.5-3b-instruct-q4", "reply": reply,
                    "raw": {"usage": {"neurons": 0.0,
                                      "total_tokens": usage.get("total_tokens", 0),
                                      "completion_tokens": usage.get("completion_tokens", 0)}}}
        if attempt < retries:
            time.sleep(2 ** attempt)
    raise RuntimeError(f"local LLM {r.status_code}: {r.text[:200]}")


def call_llm(role: str, messages: list[dict], temperature: float | None = None,
             max_tokens: int | None = None, retries: int = 3) -> dict:
    """POST to the Worker. `role` selects the model; `messages` fully controls
    the prompt. Set LLM_BACKEND=local to route to a self-hosted OpenAI-compatible
    server instead (same response shape)."""
    if os.environ.get("LLM_BACKEND") == "local":
        return _call_local(role, messages, temperature, max_tokens, retries)
    key, url = load_env()
    body = {"role": role, "messages": messages}
    if temperature is not None:
        body["temperature"] = temperature
    if max_tokens is not None:
        body["max_tokens"] = max_tokens
    last_err = None
    for attempt in range(retries + 1):
        try:
            r = requests.post(url, json=body, timeout=120,
                              headers={"Content-Type": "application/json",
                                       "Authorization": f"Bearer {key}"})
        except requests.exceptions.RequestException as e:
            # Transient network failure (ReadTimeout, ConnectionError): back off and retry.
            last_err = e
            if attempt < retries:
                time.sleep(2 ** attempt)
                continue
            raise RuntimeError(f"Worker network error after retries: {type(e).__name__}: {e}")
        if r.status_code == 200:
            return r.json()
        if r.status_code in (401, 400):
            raise RuntimeError(f"Worker {r.status_code}: {r.text[:300]}")
        if r.status_code == 429 and r.json().get("likely_quota_exceeded"):
            raise QuotaExceeded(r.text[:300])
        if attempt < retries:
            time.sleep(2 ** attempt)
    raise RuntimeError(f"Worker {r.status_code} after retries: {r.text[:300]}")


# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------
def write_jsonl(path: Path, rows) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
            n += 1
    return n


def read_jsonl(path: Path) -> list[dict]:
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]
