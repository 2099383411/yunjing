"""Download BGE models for Docker build"""
import sys
sys.stdout.reconfigure(line_buffering=True)

print("[BGE] 下载 BGE-large-zh-v1.5 ...", flush=True)
from sentence_transformers import SentenceTransformer
SentenceTransformer("BAAI/bge-large-zh-v1.5")
print("[BGE] BGE-large-zh-v1.5 下载完成", flush=True)

print("[BGE] 下载 BGE-reranker-v2-m3 ...", flush=True)
from sentence_transformers import CrossEncoder
CrossEncoder("BAAI/bge-reranker-v2-m3")
print("[BGE] BGE-reranker-v2-m3 下载完成", flush=True)

print("[BGE] 所有模型下载完成", flush=True)
