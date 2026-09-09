import hashlib
import pickle
from typing import Any, List, Optional
import numpy as np

try:
    from sentence_transformers import SentenceTransformer
except ImportError:  # pragma: no cover - optional dependency may be missing
    SentenceTransformer = None  # type: ignore[assignment]

try:
    from .config import EMBEDDING_MODEL, EMBEDDING_BATCH_SIZE, EMBEDDING_DIM, CHROMA_PATH
except ImportError:  # pragma: no cover - fallback for direct script execution
    from config import EMBEDDING_MODEL, EMBEDDING_BATCH_SIZE, EMBEDDING_DIM, CHROMA_PATH


class Embedder:
    def __init__(self, model_name: str = EMBEDDING_MODEL):
        self.model_name = model_name
        self.model: Optional[Any] = None
        self.dim = int(EMBEDDING_DIM)
        self.cache_path = CHROMA_PATH / "embed_cache.pkl"
        self.cache = self._load_cache()
        print(f"[embed] ready model={model_name}, dim={self.dim}, cache size={len(self.cache)}")

    def _ensure_model(self):
        if self.model is None:
            if SentenceTransformer is None:
                raise ImportError("sentence-transformers is required for embeddings")
            print(f"[embed] loading {self.model_name}...")
            self.model = SentenceTransformer(self.model_name)
            assert self.model is not None
            self.dim = int(self.model.get_sentence_embedding_dimension() or self.dim)

    def _load_cache(self) -> dict:
        if self.cache_path.exists():
            try:
                with open(self.cache_path, "rb") as f:
                    return pickle.load(f)
            except Exception:
                return {}
        return {}

    def _save_cache(self):
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.cache_path, "wb") as f:
            pickle.dump(self.cache, f)

    @staticmethod
    def _hash(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def embed(self, texts: List[str], use_cache: bool = True) -> np.ndarray:
        """
        Embed a list of texts. Caches by content hash.
        Returns numpy array of shape (len(texts), dim).
        """
        if not texts:
            return np.zeros((0, self.dim), dtype=np.float32)

        self._ensure_model()
        assert self.model is not None
        hashes = [self._hash(t) for t in texts]
        uncached_idx = [i for i, h in enumerate(hashes) if not use_cache or h not in self.cache]

        results: List[Optional[np.ndarray]] = [None] * len(texts)
        for i, h in enumerate(hashes):
            if h in self.cache:
                cached_value = self.cache[h]
                if cached_value is not None:
                    results[i] = np.asarray(cached_value, dtype=np.float32)

        if uncached_idx:
            uncached_texts = [texts[i] for i in uncached_idx]
            print(f"[embed] computing {len(uncached_texts)} new embeddings...")
            new_emb = self.model.encode(
                uncached_texts,
                batch_size=EMBEDDING_BATCH_SIZE,
                show_progress_bar=False,
                normalize_embeddings=True,
                convert_to_numpy=True,
            )
            if isinstance(new_emb, np.ndarray) and new_emb.ndim == 1:
                new_emb = np.expand_dims(new_emb, axis=0)
            for idx, emb in zip(uncached_idx, new_emb):
                emb_array = np.asarray(emb, dtype=np.float32)
                results[idx] = emb_array
                self.cache[hashes[idx]] = emb_array

            self._save_cache()

        filled = []
        for item in results:
            if item is None:
                filled.append(np.zeros((self.dim,), dtype=np.float32))
            else:
                filled.append(np.asarray(item, dtype=np.float32))
        return np.vstack(filled).astype(np.float32)

    def embed_query(self, query: str) -> np.ndarray:
        return self.embed([query], use_cache=False)[0]


if __name__ == "__main__":
    e = Embedder()
    v = e.embed(["Failed password for invalid user", "successful authentication"])
    print(f"shape: {v.shape}, dtype: {v.dtype}")
    sim = float(np.dot(v[0], v[1]))
    print(f"similarity: {sim:.3f}")
