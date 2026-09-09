"""
build_index.py - One-shot script to build the ChromaDB index from the knowledge base.

Run once after adding new documents. Re-runs clear and rebuild the entire index.
"""
import sys
import json
from pathlib import Path

# Add Ai/ to path so we can import rag.core modules
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from rag.core.ingest import load_all
from rag.core.embed import Embedder
from rag.core.config import CHROMA_PATH, COLLECTION_NAME


def main():
    print("=" * 60)
    print("ARGUS RAG Index Builder")
    print("=" * 60)

    # 1. Load all knowledge base documents
    print("\n[1/4] Loading knowledge base...")
    chunks = load_all()
    if not chunks:
        print("ERROR: No chunks loaded. Check your knowledge_base/ directory.")
        print("Expected: knowledge_base/mitre/enterprise-attack-*.json")
        return False

    print(f"  Loaded {len(chunks)} chunks total")

    # 2. Initialize embedder
    print("\n[2/4] Loading embedding model (first run downloads model)...")
    embedder = Embedder()

    # 3. Initialize ChromaDB
    print(f"\n[3/4] Initializing ChromaDB at {CHROMA_PATH}...")
    import chromadb
    from chromadb.config import Settings

    client = chromadb.PersistentClient(
        path=str(CHROMA_PATH),
        settings=Settings(anonymized_telemetry=False)
    )

    # Clear existing collection if it exists
    try:
        client.delete_collection(COLLECTION_NAME)
        print(f"  Deleted existing collection '{COLLECTION_NAME}'")
    except Exception:
        print(f"  No existing collection to delete")

    collection = client.create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"}
    )

    # 4. Embed and add in batches
    print(f"\n[4/4] Indexing {len(chunks)} chunks (this takes 2-5 min first time)...")
    batch_size = 100

    for i in range(0, len(chunks), batch_size):
        batch = chunks[i:i + batch_size]

        ids = [c.id for c in batch]
        docs = [c.text for c in batch]
        metas = []

        for c in batch:
            m = dict(c.metadata)
            # Flatten any list/dict values to JSON strings (Chroma requirement)
            for k, v in list(m.items()):
                if isinstance(v, (list, dict)):
                    m[k] = json.dumps(v)
            metas.append(m)

        # Embed the batch
        embs = embedder.embed(docs).tolist()

        # Add to ChromaDB
        collection.add(
            ids=ids,
            documents=docs,
            metadatas=metas,
            embeddings=embs
        )

        progress = min(i + batch_size, len(chunks))
        print(f"  Indexed {progress}/{len(chunks)} chunks")

    # Verify
    final_count = collection.count()
    print("\n" + "=" * 60)
    print(f"SUCCESS: {final_count} chunks in '{COLLECTION_NAME}'")
    print("=" * 60)

    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
