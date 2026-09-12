import re
from typing import Any, Dict, List, Optional

try:
    import chromadb
    from chromadb.config import Settings
except ImportError:  # pragma: no cover - optional dependency may be missing
    chromadb = None  # type: ignore[assignment]
    Settings = None  # type: ignore[assignment]

try:
    from rank_bm25 import BM25Okapi
except ImportError:  # pragma: no cover - optional dependency may be missing
    BM25Okapi = None  # type: ignore[assignment]

try:
    from sentence_transformers import CrossEncoder
except ImportError:  # pragma: no cover - optional dependency may be missing
    CrossEncoder = None  # type: ignore[assignment]

try:
    from .config import (
        CHROMA_PATH, COLLECTION_NAME,
        TOP_K_VECTOR, TOP_K_BM25, TOP_K_RERANK,
        BM25_WEIGHT, VECTOR_WEIGHT
    )
    from .embed import Embedder
except ImportError:  # pragma: no cover - fallback for direct script execution
    from config import (
        CHROMA_PATH, COLLECTION_NAME,
        TOP_K_VECTOR, TOP_K_BM25, TOP_K_RERANK,
        BM25_WEIGHT, VECTOR_WEIGHT
    )
    from embed import Embedder


class Retriever:
    def __init__(self, collection_name: str = COLLECTION_NAME):
        if chromadb is None or Settings is None:
            raise ImportError("chromadb is required for retrieval")

        # Vector store
        self.chroma = chromadb.PersistentClient(
            path=str(CHROMA_PATH),
            settings=Settings(anonymized_telemetry=False),
        )
        self.collection = self.chroma.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"}
        )
        print(f"[retrieve] chroma collection '{collection_name}': {self.collection.count()} docs")

        # Embedder
        self.embedder = Embedder()

        # Re-ranker (loads lazily, ~250MB)
        self._reranker = None

        # BM25 index (built on demand or loaded from disk)
        self._bm25 = None
        self._bm25_corpus = []
        self._bm25_meta = []
        self._bm25_available = BM25Okapi is not None
        if not self._bm25_available:
            print("[retrieve] rank_bm25 unavailable; using vector-only retrieval")

    @property
    def reranker(self):
        if self._reranker is None:
            if CrossEncoder is None:
                raise ImportError("sentence-transformers is required for reranking")
            print("[retrieve] loading cross-encoder reranker...")
            self._reranker = CrossEncoder("cross-encoder/ms-marco-MiniLM-L-6-v2")
        return self._reranker

    def _build_bm25_index(self) -> None:
        """Build BM25 index from current collection."""
        all_data = self.collection.get(include=["documents", "metadatas"])  # type: ignore[arg-type]
        documents = all_data.get("documents") or []
        metadatas = all_data.get("metadatas") or []
        self._bm25_corpus = []
        self._bm25_meta = []
        for doc, meta in zip(documents, metadatas):
            tokens = self._tokenize(doc)
            self._bm25_corpus.append(tokens)
            self._bm25_meta.append({"doc": doc, "meta": meta})
        if BM25Okapi is None:
            raise ImportError("rank_bm25 is required for BM25 search")
        if self._bm25_corpus:
            self._bm25 = BM25Okapi(self._bm25_corpus)
            print(f"[retrieve] BM25 index built: {len(self._bm25_corpus)} docs")

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        # Lowercase, split on non-alphanumeric, keep terms with length > 1
        return [t for t in re.split(r'\W+', text.lower()) if len(t) > 1]

    def _bm25_search(self, query: str, k: int) -> List[Dict]:
        if not self._bm25_available:
            return []
        if self._bm25 is None:
            self._build_bm25_index()
        if self._bm25 is None or not self._bm25_corpus:
            return []

        tokens = self._tokenize(query)
        scores = self._bm25.get_scores(tokens)
        top_idx = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:k]

        results = []
        for idx in top_idx:
            if scores[idx] > 0:
                results.append({
                    "text": self._bm25_meta[idx]["doc"],
                    "metadata": self._bm25_meta[idx]["meta"],
                    "bm25_score": float(scores[idx]),
                })
        return results

    @staticmethod
    def _matches_source_filter(metadata: Dict[str, Any], filter_source: Optional[str]) -> bool:
        if not filter_source:
            return True
        return metadata.get("source") == filter_source

    def _vector_search(self, query: str, k: int,
                       where: Optional[Dict] = None) -> List[Dict]:
        query_emb = self.embedder.embed_query(query).tolist()
        kwargs: Dict[str, Any] = {
            "query_embeddings": [query_emb],
            "n_results": k,
            "include": ["documents", "metadatas", "distances"],
        }
        if where:
            kwargs["where"] = where

        results = self.collection.query(**kwargs)  # type: ignore[arg-type]

        documents = results.get("documents") or [[]]
        metadatas = results.get("metadatas") or [[]]
        distances = results.get("distances") or [[]]

        out = []
        for doc, meta, dist in zip(documents[0], metadatas[0], distances[0]):
            out.append({
                "text": doc,
                "metadata": meta,
                "vector_score": 1.0 - float(dist),
            })
        return out


    @staticmethod
    def _normalize(scores: List[float]) -> List[float]:
        if not scores:
            return []
        mn, mx = min(scores), max(scores)
        if mx == mn:
            return [0.5] * len(scores)
        return [(s - mn) / (mx - mn) for s in scores]

    def retrieve(self, query: str, top_k: int = TOP_K_RERANK,
                 filter_source: Optional[str] = None,
                 use_rerank: bool = True) -> List[Dict]:
        """
        Hybrid retrieval with optional re-ranking.

        Args:
            query: search text
            top_k: final number of results
            filter_source: only return from this source (mitre_attack, sigma_rules, etc.)
            use_rerank: apply cross-encoder re-ranking
        """
        where = {"source": filter_source} if filter_source else None

        # 1. Vector search
        vec_results = self._vector_search(query, TOP_K_VECTOR, where=where)
        # 2. BM25 search
        bm25_results = [
            result for result in self._bm25_search(query, TOP_K_BM25)
            if self._matches_source_filter(result.get("metadata", {}), filter_source)
        ]

        # 3. Merge by metadata doc_id (or text hash)
        merged: Dict[str, Dict] = {}
        for r in vec_results:
            key = r["metadata"].get("technique_id") or r["metadata"].get("rule_id") or r["text"][:50]
            merged[key] = {**r, "vector_score": r.get("vector_score", 0.0), "bm25_score": 0.0}
        for r in bm25_results:
            key = r["metadata"].get("technique_id") or r["metadata"].get("rule_id") or r["text"][:50]
            if key in merged:
                merged[key]["bm25_score"] = r.get("bm25_score", 0.0)
            else:
                merged[key] = {**r, "vector_score": 0.0, "bm25_score": r.get("bm25_score", 0.0)}

        # 4. Normalize and combine
        vec_scores = [m["vector_score"] for m in merged.values()]
        bm25_scores = [m["bm25_score"] for m in merged.values()]
        vec_norm = self._normalize(vec_scores)
        bm25_norm = self._normalize(bm25_scores)

        candidates = []
        for (key, m), vn, bn in zip(merged.items(), vec_norm, bm25_norm):
            hybrid = VECTOR_WEIGHT * vn + BM25_WEIGHT * bn
            candidates.append({
                **m,
                "hybrid_score": hybrid,
            })
        candidates.sort(key=lambda x: x["hybrid_score"], reverse=True)

        # 5. Re-rank top candidates
        if use_rerank and candidates:
            top_cands = candidates[:max(top_k * 3, 10)]
            pairs = [(query, c["text"]) for c in top_cands]
            rerank_scores = self.reranker.predict(pairs)
            for c, rs in zip(top_cands, rerank_scores):
                c["rerank_score"] = float(rs)
            top_cands.sort(key=lambda x: x["rerank_score"], reverse=True)
            return top_cands[:top_k]

        return candidates[:top_k]


if __name__ == "__main__":
    r = Retriever()
    print("\n--- Test query: brute force SSH ---")
    results = r.retrieve("multiple failed SSH login attempts from same IP", top_k=5)
    for i, res in enumerate(results):
        print(f"\n{i+1}. {res['metadata'].get('technique_id') or res['metadata'].get('rule_id', '?')}")
        print(f"   source: {res['metadata'].get('source', '?')}")
        print(f"   score: hybrid={res.get('hybrid_score', 0):.3f} rerank={res.get('rerank_score', 0):.3f}")
        print(f"   {res['text'][:150]}...")
