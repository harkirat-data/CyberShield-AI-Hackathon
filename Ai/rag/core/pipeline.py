from __future__ import annotations

from typing import Any, Dict, List

try:
    from .config import GEMINI_API_KEY, RAG_MEMORY_WINDOW
    from .llm import GeminiClient, SOC_ANALYST_SYSTEM, build_soc_prompt
    from .memory import RedisMemory
    from .retrieve import Retriever
except ImportError:  # pragma: no cover - fallback for direct script execution
    from config import GEMINI_API_KEY, RAG_MEMORY_WINDOW
    from llm import GeminiClient, SOC_ANALYST_SYSTEM, build_soc_prompt
    from memory import RedisMemory
    from retrieve import Retriever


class RAGPipeline:
    def __init__(self, enable_retrieval: bool = True, enable_llm: bool = True):
        self.enable_retrieval = enable_retrieval
        self.enable_llm = enable_llm and bool(GEMINI_API_KEY)
        self.retriever = None
        self.llm = None
        self.memory = RedisMemory()

        if self.enable_retrieval:
            try:
                self.retriever = Retriever()
            except Exception as exc:
                print(f"[pipeline] retrieval unavailable: {exc}")

        if self.enable_llm:
            try:
                self.llm = GeminiClient()
            except Exception as exc:
                print(f"[pipeline] llm unavailable: {exc}")

        print(
            f"[pipeline] ready retrieval={self.retriever is not None} "
            f"llm={self.llm is not None} memory={self.memory.backend}"
        )

    def analyze(
        self,
        event: Any,
        threat_intel_dict: Dict[str, Any] | None = None,
        correlation_dict: Dict[str, Any] | None = None,
        mitre_dict: Dict[str, Any] | None = None,
        risk_dict: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        event_dict = event.to_dict() if hasattr(event, "to_dict") else dict(event or {})
        context = {
            "threat_intel": threat_intel_dict or {},
            "correlated_events": (correlation_dict or {}).get("related_events", []),
            "mitre": mitre_dict or {},
            "risk": risk_dict or {},
        }

        query = self._build_query(event_dict, context)
        rag_chunks = self._retrieve_chunks(query)
        rag_mitre_techniques = self._extract_mitre_techniques(rag_chunks)
        analysis = self._generate_analysis(event_dict, context, rag_chunks)

        return {
            "query": query,
            "rag_chunks": rag_chunks,
            "rag_mitre_techniques": rag_mitre_techniques,
            "analysis": analysis,
        }

    def answer_query(self, query: str, session_id: str = "default", top_k: int = 5) -> Dict[str, Any]:
        clean_query = (query or "").strip()
        if not clean_query:
            return {
                "query": "",
                "answer": "Please enter a query.",
                "rag_chunks": [],
                "history": self.memory.get_history(session_id, limit=RAG_MEMORY_WINDOW),
                "memory": self.memory.stats(session_id),
            }

        history = self.memory.get_history(session_id, limit=RAG_MEMORY_WINDOW)
        retrieval_query = self._build_memory_augmented_query(clean_query, history)
        rag_chunks = self._retrieve_chunks(retrieval_query)[:top_k]
        answer = self._answer_with_context(clean_query, history, rag_chunks)

        self.memory.add_message(session_id, "user", clean_query)
        self.memory.add_message(
            session_id,
            "assistant",
            answer,
            metadata={"references": len(rag_chunks)},
        )

        return {
            "query": clean_query,
            "answer": answer,
            "rag_chunks": rag_chunks,
            "history": self.memory.get_history(session_id, limit=RAG_MEMORY_WINDOW),
            "memory": self.memory.stats(session_id),
        }

    def _retrieve_chunks(self, query: str) -> List[Dict[str, Any]]:
        if self.retriever is None:
            return []
        try:
            return self.retriever.retrieve(query, top_k=5)
        except Exception as exc:
            print(f"[pipeline] retrieval failed: {exc}")
            return []

    def _generate_analysis(
        self,
        event_dict: Dict[str, Any],
        context: Dict[str, Any],
        rag_chunks: List[Dict[str, Any]],
    ) -> Dict[str, Any] | None:
        if self.llm is None:
            return None

        prompt = build_soc_prompt(event_dict, context, rag_chunks)
        schema_hint = """Return JSON with keys:
{
  "summary": "string",
  "severity": "critical|high|medium|low|info",
  "findings": ["string"],
  "mitre_techniques": ["Txxxx"],
  "remediation": {
    "immediate": ["string"],
    "short_term": ["string"],
    "long_term": ["string"]
  }
}"""
        try:
            return self.llm.generate(SOC_ANALYST_SYSTEM, f"{prompt}\n\n# OUTPUT SCHEMA\n{schema_hint}")
        except Exception as exc:
            print(f"[pipeline] llm generation failed: {exc}")
            return {"error": str(exc), "fallback": True}

    def _answer_with_context(
        self,
        query: str,
        history: List[Dict[str, Any]],
        rag_chunks: List[Dict[str, Any]],
    ) -> str:
        if self.llm is None:
            return self._fallback_answer(rag_chunks)

        prompt = self._build_query_prompt(query, history, rag_chunks)
        system = (
            "You are a SOC knowledge assistant. Answer only from the supplied references and "
            "recent chat memory. If the answer is uncertain, say so clearly. Keep answers concise "
            "and actionable."
        )
        try:
            response = self.llm.complete(system=system, user=prompt, response_mime_type="text/plain")
            return response or self._fallback_answer(rag_chunks)
        except Exception as exc:
            print(f"[pipeline] query generation failed: {exc}")
            return self._fallback_answer(rag_chunks)

    @staticmethod
    def _extract_mitre_techniques(rag_chunks: List[Dict[str, Any]]) -> List[str]:
        seen = set()
        ordered: List[str] = []
        for chunk in rag_chunks:
            metadata = chunk.get("metadata", {}) or {}
            technique_id = metadata.get("technique_id")
            if technique_id and technique_id not in seen:
                seen.add(technique_id)
                ordered.append(technique_id)
        return ordered

    @staticmethod
    def _build_memory_augmented_query(query: str, history: List[Dict[str, Any]]) -> str:
        recent_user_messages = [
            item.get("content", "").strip()
            for item in history
            if item.get("role") == "user" and item.get("content")
        ]
        context_tail = recent_user_messages[-2:]
        if not context_tail:
            return query
        return " ".join([*context_tail, query])

    @staticmethod
    def _build_query_prompt(query: str, history: List[Dict[str, Any]], rag_chunks: List[Dict[str, Any]]) -> str:
        history_lines = []
        for item in history[-RAG_MEMORY_WINDOW:]:
            role = item.get("role", "unknown")
            content = item.get("content", "")
            history_lines.append(f"{role}: {content}")

        refs = []
        for index, chunk in enumerate(rag_chunks, 1):
            metadata = chunk.get("metadata", {}) or {}
            title = metadata.get("technique_id") or metadata.get("rule_id") or metadata.get("file") or f"ref-{index}"
            refs.append(f"[{index}] {title}\n{chunk.get('text', '')}")

        return (
            "Answer the user's SOC/security query.\n\n"
            f"# USER QUERY\n{query}\n\n"
            f"# RECENT MEMORY\n{chr(10).join(history_lines) if history_lines else 'No prior memory'}\n\n"
            f"# REFERENCES\n{chr(10).join(refs) if refs else 'No references found'}\n"
        )

    @staticmethod
    def _fallback_answer(rag_chunks: List[Dict[str, Any]]) -> str:
        if not rag_chunks:
            return "I could not find supporting RAG references for that query yet."
        lines = []
        for index, chunk in enumerate(rag_chunks[:3], 1):
            metadata = chunk.get("metadata", {}) or {}
            label = metadata.get("technique_id") or metadata.get("rule_id") or metadata.get("file") or f"reference-{index}"
            snippet = chunk.get("text", "").strip().replace("\n", " ")
            lines.append(f"{index}. {label}: {snippet[:260]}")
        return "Top RAG references:\n" + "\n".join(lines)

    @staticmethod
    def _build_query(event_dict: Dict[str, Any], context: Dict[str, Any]) -> str:
        actor = event_dict.get("actor", {}) or {}
        target = event_dict.get("target", {}) or {}
        details = event_dict.get("details", {}) or {}

        parts = [
            event_dict.get("event_type", ""),
            event_dict.get("source", ""),
            event_dict.get("host", ""),
            actor.get("user", ""),
            actor.get("source_ip", ""),
            target.get("service", ""),
            target.get("host", ""),
            event_dict.get("raw", ""),
        ]

        for key in ("service_name", "image_path", "command", "process", "attempts"):
            value = details.get(key)
            if value not in (None, ""):
                parts.append(str(value))

        if context.get("threat_intel", {}).get("is_malicious"):
            parts.append("malicious source ip")
        if context.get("correlated_events"):
            parts.append("correlated repeated activity")

        return " ".join(str(part).strip() for part in parts if str(part).strip())
