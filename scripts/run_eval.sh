#!/usr/bin/env bash
# Evaluation driver: full multi-agent pipeline, no-agents baseline, component
# ablation (router-only / verifier-only), correctness-vs-gold, and reports.
# Every stage is resumable (existing per-query run files are skipped).
#
# Backend: set LLM_BACKEND=local for a local llama.cpp server on :8080 (no API
# cost), or leave it unset and provide WORKER_URL/WORKER_AUTH_KEY in .env for the
# hosted Cloudflare Worker. See README for the llama.cpp setup.
set -e
cd "$(dirname "$0")/.."
PY=./venv/bin/python
export LLM_BACKEND="${LLM_BACKEND:-local}"

echo "== 0. backend preflight ($LLM_BACKEND) =="
if [ "$LLM_BACKEND" = "local" ]; then
  curl -s http://127.0.0.1:8080/health | grep -q ok \
    || { echo "local llama-server not responding on :8080 (see README > Run)"; exit 1; }
  echo "local llama-server OK"
else
  $PY - <<'EOF'
from data.common import call_llm, QuotaExceeded
try:
    call_llm('router_pass1', [{'role': 'user', 'content': 'ok'}], max_tokens=2)
    print("hosted backend OK")
except QuotaExceeded:
    raise SystemExit("hosted backend quota exhausted")
EOF
fi

echo "== 1. multi-agent pipeline (62 queries) -> runs/ =="
$PY -u -m rag.run

echo "== 2. no-agents baseline -> runs_baseline/ =="
$PY -u -m rag.baseline

echo "== 3. component ablation (router-only, verifier-only) -> runs_router_only/, runs_verifier_only/ =="
$PY -u -m rag.ablate

echo "== 4. answer correctness vs. gold (deterministic; prose judge reported but not trusted) =="
$PY -m eval.correctness --llm

echo "== 5. retrieval / behaviour / cost reports =="
$PY -m eval.evaluate --no-llm

echo "== 6. ablation tables =="
$PY -m eval.ablate_compare

echo
echo "done. Per-query outputs are in runs/; summaries in eval/."
