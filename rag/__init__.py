"""Runtime RAG package.

Set OpenMP/tokenizer guards before torch/faiss/transformers import, to avoid a
duplicate-libomp segfault on macOS when faiss and torch are loaded together.
"""
import os

os.environ.setdefault("KMP_DUPLICATE_LIB_OK", "TRUE")
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
