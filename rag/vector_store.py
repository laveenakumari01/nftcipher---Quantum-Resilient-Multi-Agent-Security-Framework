"""
rag/vector_store.py

Vector Database wrapper for RAG (Retrieval Augmented Generation).
Used by the AI Research Agent to store and search threat intelligence.

ChromaDB is used as the vector database.
  - Stores CVE data, threat intel, malware reports
  - Converts text to vectors using sentence-transformers
  - Similarity search finds relevant documents for any query

If ChromaDB is not installed, falls back to simple keyword search.

Install: pip install chromadb sentence-transformers
"""

import time
import json
from logger import log_info, log_error

# Try to load ChromaDB — fall back to simple keyword store if not available
_CHROMA_AVAILABLE = False
try:
    import chromadb
    from chromadb.config import Settings
    _CHROMA_AVAILABLE = True
    log_info("[VectorStore] ChromaDB loaded — real vector search active")
except ImportError:
    log_error("[VectorStore] ChromaDB not found — using keyword fallback. Install: pip install chromadb")

# Try to load sentence-transformers for embeddings
_EMBEDDINGS_AVAILABLE = False
try:
    from sentence_transformers import SentenceTransformer
    _EMBEDDINGS_AVAILABLE = True
    log_info("[VectorStore] sentence-transformers loaded — semantic embeddings active")
except ImportError:
    log_error("[VectorStore] sentence-transformers not found. Install: pip install sentence-transformers")


class VectorStore:
    """
    Wraps ChromaDB for threat intelligence storage and retrieval.

    How RAG works here:
      1. add()    — convert threat doc to vector and store
      2. search() — convert query to vector, find closest docs
      3. LLM gets those docs as context — grounded, not hallucinated

    Collection names map to threat categories:
      "cve_database"     — CVE records
      "threat_intel"     — MITRE ATT&CK, threat feeds
      "malware_reports"  — malware analysis reports
    """

    def __init__(self, collection_name: str = "threat_intel", db_path: str = "./chroma_db"):
        self.collection_name = collection_name
        self.db_path         = db_path
        self._client         = None
        self._collection     = None
        self._embedder       = None
        self._fallback_docs: list = []  # used if ChromaDB not available

        self._initialize()

    def _initialize(self):
        """Connect to ChromaDB and load embedding model."""
        if _CHROMA_AVAILABLE:
            try:
                self._client = chromadb.PersistentClient(
                    path     = self.db_path,
                    settings = Settings(anonymized_telemetry=False),
                )
                self._collection = self._client.get_or_create_collection(
                    name     = self.collection_name,
                    metadata = {"description": "NFTCipher threat intelligence database"},
                )
                log_info(
                    f"[VectorStore] Connected | collection={self.collection_name} | "
                    f"docs={self._collection.count()}"
                )
            except Exception as e:
                log_error(f"[VectorStore] ChromaDB init error: {e} — using fallback")
                _CHROMA_AVAILABLE_local = False

        if _EMBEDDINGS_AVAILABLE:
            try:
                from config.settings import EMBEDDING_MODEL
                self._embedder = SentenceTransformer(EMBEDDING_MODEL)
                log_info(f"[VectorStore] Embeddings ready | model={EMBEDDING_MODEL}")
            except Exception as e:
                log_error(f"[VectorStore] Embedder init error: {e}")

    def add(self, doc_id: str, content: str, metadata: dict = None) -> bool:
        """
        Add a document to the vector store.
        Content is automatically converted to a vector for similarity search.
        doc_id must be unique — duplicate IDs update the existing document.
        """
        metadata = metadata or {}
        metadata["added_at"] = str(time.time())

        if _CHROMA_AVAILABLE and self._collection:
            try:
                # Generate embedding if available, else let ChromaDB use default
                embedding = None
                if self._embedder:
                    embedding = self._embedder.encode(content).tolist()

                self._collection.upsert(
                    ids        = [doc_id],
                    documents  = [content],
                    metadatas  = [metadata],
                    embeddings = [embedding] if embedding else None,
                )
                log_info(f"[VectorStore] Added doc | id={doc_id} | collection={self.collection_name}")
                return True
            except Exception as e:
                log_error(f"[VectorStore] add error: {e}")

        # Fallback — simple in-memory list
        self._fallback_docs = [d for d in self._fallback_docs if d["id"] != doc_id]
        self._fallback_docs.append({
            "id":       doc_id,
            "content":  content.lower(),
            "metadata": metadata,
        })
        return True

    def search(self, query: str, top_k: int = 3) -> list:
        """
        Find the most relevant documents for a query.
        ChromaDB mode: real semantic vector similarity search.
        Fallback mode: keyword overlap scoring.
        Returns list of {"id", "content", "metadata", "score"} dicts.
        """
        if _CHROMA_AVAILABLE and self._collection and self._collection.count() > 0:
            try:
                # Use embedding for semantic search if available
                query_embedding = None
                if self._embedder:
                    query_embedding = self._embedder.encode(query).tolist()

                results = self._collection.query(
                    query_texts      = None if query_embedding else [query],
                    query_embeddings = [query_embedding] if query_embedding else None,
                    n_results        = min(top_k, self._collection.count()),
                )

                docs = []
                for i, doc_id in enumerate(results["ids"][0]):
                    docs.append({
                        "id":       doc_id,
                        "content":  results["documents"][0][i],
                        "metadata": results["metadatas"][0][i],
                        "score":    1 - results["distances"][0][i] if results.get("distances") else 0.5,
                    })
                return docs

            except Exception as e:
                log_error(f"[VectorStore] search error: {e} — using fallback")

        # Fallback — keyword overlap
        q_words = set(query.lower().split())
        scored  = []
        for doc in self._fallback_docs:
            doc_words = set(doc["content"].split())
            score     = len(q_words & doc_words) / max(len(q_words), 1)
            if score > 0:
                scored.append((score, doc))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [
            {"id": d["id"], "content": d["content"], "metadata": d["metadata"], "score": s}
            for s, d in scored[:top_k]
        ]

    def delete(self, doc_id: str) -> bool:
        """Remove a document from the store."""
        if _CHROMA_AVAILABLE and self._collection:
            try:
                self._collection.delete(ids=[doc_id])
                return True
            except Exception as e:
                log_error(f"[VectorStore] delete error: {e}")

        self._fallback_docs = [d for d in self._fallback_docs if d["id"] != doc_id]
        return True

    def count(self) -> int:
        """Return total number of documents in the store."""
        if _CHROMA_AVAILABLE and self._collection:
            try:
                return self._collection.count()
            except Exception:
                pass
        return len(self._fallback_docs)

    def get_status(self) -> dict:
        doc_count = self.count()
        # Get recent document IDs for dashboard top CVEs display
        if _CHROMA_AVAILABLE and self._collection:
            try:
                recent = self._collection.get(limit=5, include=["metadatas"])
                recent_ids = recent.get("ids", [])
            except Exception:
                recent_ids = list(self._fallback_docs.keys())[-5:]
        else:
            recent_ids = list(self._fallback_docs.keys())[-5:]

        return {
            "collection":           self.collection_name,
            "chroma_available":     _CHROMA_AVAILABLE,
            "embeddings_available": _EMBEDDINGS_AVAILABLE,
            "document_count":       doc_count,
            "total_docs":           doc_count,
            "collections":          1,
            "recent_ids":           recent_ids,
            "mode":                 "chromadb" if (_CHROMA_AVAILABLE and self._collection) else "keyword_fallback",
        }