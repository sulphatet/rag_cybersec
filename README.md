# Multi-Agent RAG for Cybersecurity Question Answering

A four-agent retrieval-augmented generation (RAG) system that answers a cybersecurity
**question or short incident description** using **only** retrieved evidence from a curated
knowledge base (MITRE ATT&CK, NVD/CVE, NIST SP 800-61r3), cites its sources, and
**abstains / clarifies / refuses** when the evidence is insufficient. Grounding is enforced by a
verification stage that gates every answer before release — not merely prompted for.

The generation backend is **pluggable**: a self-hosted local model (`llama.cpp`, no API cost) or a
hosted Cloudflare Worker (Workers AI). The rest of the pipeline is identical either way.

## Architecture

```
input ──▶ Router ──▶ Retriever ──▶ Generator ──▶ Verifier ──▶ answer (+citations)
           │                                          │
           │ (scope: answerable / ambiguous /         │ (fail → one revision → re-check;
           │  out-of-scope; + safety on every input)  │  second failure → abstain)
           └─▶ clarify / abstain / refuse
```

- **Router** — classifies the input as answerable, ambiguous, or out of scope (one LLM call), and a
  separate safety call runs on *every* input to catch unsafe requests. In-scope inputs go to retrieval;
  the rest return clarification, abstention, or refusal.
- **Retriever** — hybrid search: dense (`bge-base-en-v1.5` + FAISS) for paraphrased descriptions and
  BM25 for exact identifiers, fused with Reciprocal Rank Fusion; returns the top 5 passages.
- **Generator** — writes a structured answer (text + supporting passage ids) using only the retrieved passages.
- **Verifier** — matches exact values (identifiers, CVSS scores, dates) against the cited passages,
  runs LettuceDetect over the remaining prose, and checks citation consistency. A failed draft gets one
  revision to remove unsupported content; a second failure abstains.

## Requirements

- Python 3.12
- A generation backend — **either** local `llama.cpp` (default, `$0`) **or** a Cloudflare Worker.
- First run downloads `bge-base-en-v1.5` (~0.4 GB) and LettuceDetect ModernBERT (~0.6 GB).

```bash
python -m venv venv && ./venv/bin/pip install -r requirements.txt
```

## 1. Build the knowledge base (from source)

The KB is not committed; build it from the authoritative sources (needs network access):

```bash
./scripts/build_kb.sh            # fetch ATT&CK / NVD / NIST -> render -> chunk -> kb/chunks.jsonl
```

KB pages are **deterministic renderings** of source fields (STIX relationship joins + light
normalisation), not new text — which is what lets gold facts be checked against them by exact match.
The test set (`testset/queries.jsonl`, `gold.jsonl`) is already committed; regenerating it additionally
requires the AttackQA dataset (see `scripts/build_kb.sh`).

## 2. Build the retrieval index

```bash
./venv/bin/python -m rag.index --rebuild        # hybrid bge-base + BM25 over kb/chunks.jsonl
```

## 3. Run — choose a backend

**Local (`$0`, default):** an OpenAI-compatible `llama.cpp` server.

```bash
brew install llama.cpp                          # provides `llama-server`
mkdir -p models && curl -L -o models/qwen2.5-3b-instruct-q4.gguf \
  https://huggingface.co/bartowski/Qwen2.5-3B-Instruct-GGUF/resolve/main/Qwen2.5-3B-Instruct-Q4_K_M.gguf
llama-server -m models/qwen2.5-3b-instruct-q4.gguf -ngl 999 --host 127.0.0.1 --port 8080 -c 8192 &

export LLM_BACKEND=local
./venv/bin/python -m rag.run --qids F1,I1,K1,L1  # a few queries; full state -> runs/<qid>.json
```

**Hosted (Cloudflare Worker):** copy `.env.example` to `.env`, set `WORKER_URL` and `WORKER_AUTH_KEY`,
and leave `LLM_BACKEND` unset. The Worker source is in `worker/worker.ts`.

Offline sanity check (no LLM, no KB): `./venv/bin/python -m rag.selftest`.

## 4. Evaluate

```bash
./scripts/run_eval.sh            # pipeline -> baseline -> component ablation -> correctness -> reports
```

Metrics are computed directly (not via a library): retrieval recall/precision from gold chunks;
answer correctness vs. gold (deterministic, no LLM judge); LettuceDetect groundedness; behavioural
correctness; and a four-way ablation isolating what the Router and Verifier each contribute. Rates
carry 95% Wilson intervals.

## Test queries and system outputs (deliverable)

- **`testset/outputs.md`** (human-readable) and **`testset/outputs.jsonl`** (machine-readable) — the
  **62 test queries with their system outputs**: query, Router decision, outcome, final answer, and
  citations (from the local 3B run).
- `testset/queries.jsonl` — the 62 queries with gold labels and category; `testset/gold.jsonl` — gold
  chunks/answers.

## Repository map

```
data/        knowledge-base + test-set construction (fetch, render, chunk, build, verify)
rag/         the multi-agent pipeline (router, retriever, generator, verifier, graph, index, run)
eval/        evaluation (retrieval, correctness, behaviour, ablation, Wilson intervals)
worker/      Cloudflare Worker for the hosted backend (worker.ts)
testset/     the test queries and system outputs (deliverable)
scripts/     build_kb.sh, run_eval.sh
```

## Data sources and licences

| Source | Use | Licence |
|---|---|---|
| MITRE ATT&CK Enterprise v19.2 (STIX) | knowledge base | MITRE ATT&CK Terms of Use (attribution required) |
| NVD / CVE (NIST) | knowledge base (300 CVE records) | U.S. Government public domain |
| NIST SP 800-61r3 | knowledge base (prose + CSF profile) | U.S. Government public domain |
| AttackQA (`sambanovasystems/attackqa`) | source of lookup queries (v19.2-filtered) | Apache-2.0 (derived from ATT&CK) |
| CTI-Bench CTI-RCM | inspected and **excluded** | CC-BY-NC-SA-4.0 (not redistributed) |

## Tools, models, and AI assistance

LangGraph (orchestration); `bge-base-en-v1.5` (embeddings); FAISS + Okapi BM25 (retrieval);
LettuceDetect / ModernBERT (prose verification); generation via a pluggable backend —
`llama.cpp` with Qwen2.5-3B-Instruct (Q4) locally and Cloudflare Workers AI with Llama-4-Scout-17B
hosted. AI assistants: Claude (implementation, literature review) and OpenAI Codex (editorial
revision of the report), disclosed per the project brief.
