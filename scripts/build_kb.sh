#!/usr/bin/env bash
# Build the knowledge base from source. Requires network access:
#   - MITRE ATT&CK Enterprise STIX bundles (GitHub)
#   - NVD CVE records (NVD REST API, throttled; an API key speeds this up)
#   - NIST SP 800-61r3 PDF
# Output: kb/chunks.jsonl (the retrievable corpus). ~10-15 min depending on the NVD throttle.
set -e
cd "$(dirname "$0")/.."
PY=./venv/bin/python

echo "== 1/3  fetch authoritative sources =="
$PY -m data.fetch_attack              # ATT&CK Enterprise v19.2 (+ v15.1 for version-drift checks)
$PY -m data.fetch_nist                # NIST SP 800-61r3
$PY -m data.fetch_nvd --target 300    # 300 CVE records (NVD API)

echo "== 2/3  render entities to Markdown (relationship joins) =="
$PY -m data.render_attack
$PY -m data.render_cve
$PY -m data.render_nist

echo "== 3/3  chunk by section =="
$PY -m data.chunk                     # -> kb/chunks.jsonl

echo
echo "KB built -> kb/chunks.jsonl"
echo "Next: $PY -m rag.index --rebuild   (builds the hybrid dense+BM25 index)"
echo
echo "The test set (testset/queries.jsonl, gold.jsonl) is already committed. To"
echo "regenerate it you also need the AttackQA dataset (data/attackqa.parquet), then:"
echo "  $PY -m data.attackqa_filter && $PY -m data.gen_cve_questions && $PY -m data.build_testset"
