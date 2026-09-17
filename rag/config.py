"""Central configuration for the runtime RAG pipeline.

One place for paths, model ids, retrieval knobs and the Generator's few-shot
examples, so every agent and the evaluator read the same constants.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KB = ROOT / "kb"
TESTSET = ROOT / "testset"
INDEX_DIR = ROOT / "index"
RUNS_DIR = ROOT / "runs"
EVAL_DIR = ROOT / "eval"

# --- retrieval ---------------------------------------------------------------
EMBED_MODEL = "BAAI/bge-base-en-v1.5"
TOP_K = 5                     # chunks handed to the Generator
RRF_K = 60                    # reciprocal-rank-fusion constant
DENSE_POOL = 50              # candidates from each retriever before fusion
BM25_POOL = 50
# bge asks for this prefix on the *query* side only (not the documents).
BGE_QUERY_PREFIX = "Represent this sentence for searching relevant passages: "

# --- verification ------------------------------------------------------------
LETTUCE_MODEL = "KRLabsOrg/lettucedect-base-modernbert-en-v1"
LETTUCE_METHOD = "transformer"

# --- Worker roles (models selected server-side; see worker.ts) ---------------
ROLE_ROUTER1 = "router_pass1"
ROLE_ROUTER2 = "router_pass2_unsafe_check"
ROLE_GENERATOR = "generator"

# --- generation --------------------------------------------------------------
GEN_TEMPERATURE = 0.1
GEN_MAX_TOKENS = 700
MAX_ATTEMPTS = 2             # initial draft + one regeneration (DESIGN §3.5)

ABSTAIN_MESSAGE = ("I cannot answer this from the knowledge base: the retrieved evidence does "
                   "not support a grounded answer. (Insufficient grounded evidence.)")
OUT_OF_SCOPE_MESSAGE = ("This question is outside the scope of the cybersecurity knowledge base "
                        "(MITRE ATT&CK, NVD/CVE, NIST SP 800-61r3), so I cannot answer it from "
                        "retrieved evidence.")
REFUSE_MESSAGE = ("I can't help with operational assistance for conducting an attack. I can "
                  "explain a vulnerability or technique and how to defend against it, grounded "
                  "in the knowledge base.")
RESOURCE_ABSTAIN_MESSAGE = ("I cannot answer right now: the language-model backend is unavailable "
                            "(quota exhausted). This is a resource limit, not a knowledge-base gap.")

# Few-shot examples for the Generator (DESIGN §3.4: few-shot > zero-shot, Deka 2024).
# Each shows the exact JSON contract and grounded, cited behaviour incl. abstention.
GENERATOR_FEWSHOT = [
    {
        "chunks": [
            {"chunk_id": "cve:CVE-0000-0001#Severity/0",
             "source_context": {"entity_name": "CVE-0000-0001", "entity_type": "cve", "section": "Severity"},
             "original_text": "CVSS 3.1 (Primary source nvd@nist.gov): base score 9.8 CRITICAL; "
                              "vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "query": "What is the NVD CVSS v3.1 base score of CVE-0000-0001?",
        "answer": {"answer": "The NVD (primary) CVSS v3.1 base score of CVE-0000-0001 is 9.8 "
                             "(CRITICAL) [cve:CVE-0000-0001#Severity/0].",
                   "supporting_chunk_ids": ["cve:CVE-0000-0001#Severity/0"], "confidence": "high"},
    },
    {
        "chunks": [
            {"chunk_id": "attack:T9999#Description/0",
             "source_context": {"entity_name": "Example Technique", "entity_type": "technique", "section": "Description"},
             "original_text": "T9999: Example Technique\nType: technique | Tactics: Discovery\n\n"
                              "Adversaries may enumerate running services on remote hosts."}],
        "query": "What CVSS score does this technique have?",
        "answer": {"answer": "The retrieved evidence does not contain a CVSS score for this "
                             "technique (CVSS scores apply to CVEs, not ATT&CK techniques), so I "
                             "cannot provide one from the knowledge base.",
                   "supporting_chunk_ids": [], "confidence": "low"},
    },
]
