import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional dependency may be missing
    def load_dotenv() -> bool:
        return False

load_dotenv()

RAG_ROOT = Path(__file__).resolve().parents[1]
KB_ROOT = RAG_ROOT / "data" / "knowledge_base"
CHROMA_PATH = RAG_ROOT / "chromadb"
COLLECTION_NAME = "argus_security_kb"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"
EMBEDDING_DIM = 384
EMBEDDING_BATCH_SIZE = 64
CHUNK_SIZE = 500         
CHUNK_OVERLAP = 100       
TOP_K_VECTOR = 20         
TOP_K_BM25 = 20           
TOP_K_RERANK = 5          
BM25_WEIGHT = 0.3         
VECTOR_WEIGHT = 0.7       

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
GEMINI_MAX_TOKENS = 2048
GEMINI_TEMPERATURE = 0.2
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
RAG_MEMORY_PREFIX = os.environ.get("RAG_MEMORY_PREFIX", "argus:rag:memory")
RAG_MEMORY_WINDOW = int(os.environ.get("RAG_MEMORY_WINDOW", "6"))

CHROMA_PATH.mkdir(parents=True, exist_ok=True)
KB_ROOT.mkdir(parents=True, exist_ok=True)
