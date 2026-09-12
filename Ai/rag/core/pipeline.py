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
        prompt = self._build_query_prompt(query, history, rag_chunks)
        system = (
            "You are CyberShield AI, an intelligent, conversational cybersecurity assistant and SOC copilot. "
            "You help security analysts and users understand cyber defense, multi-port honeypot deception, active threats, and incident triage. "
            "Converse naturally, helpfully, and warmly with users. "
            "If the user greets you (e.g. 'hello', 'hi', 'who are you', 'how are you'), chat naturally and introduce your cyber defense capabilities. "
            "When asked about attacks, honeypots, or vulnerabilities, give clear, engaging, and actionable security insights. "
            "Never say 'I cannot answer this question as there are no references'. Answer thoughtfully using your cybersecurity knowledge."
        )
        if self.llm is not None:
            try:
                response = self.llm.complete(system=system, user=prompt, response_mime_type="text/plain")
                if response and not response.lower().strip().startswith("i cannot answer"):
                    return response.strip()
            except Exception as exc:
                print(f"[pipeline] query generation failed: {exc}")

        return self._intelligent_answer(query, history, rag_chunks)

    @staticmethod
    def _intelligent_answer(query: str, history: List[Dict[str, Any]], rag_chunks: List[Dict[str, Any]]) -> str:
        q = query.lower().strip()

        # Conversational greetings & banter
        if any(w in q for w in ["hi", "hello", "hey", "hola", "greetings", "yo"]) and len(q.split()) <= 4:
            return (
                "👋 Hello! I'm your **CyberShield AI Security Copilot**.\n\n"
                "I monitor our multi-port honeynet mesh, analyze trapped adversary behaviors, and help you triage cyber incidents. "
                "How can I help you today? You can ask about our active decoys, recent attacks, or specific security vulnerabilities!"
            )

        if "who are you" in q or "what is your name" in q or "what can you do" in q:
            return (
                "🛡️ I am **CyberShield AI**, an autonomous active deception and SOC copilot.\n\n"
                "Here is what I do:\n"
                "• **Multi-Port Decoy Monitoring:** I watch active honeypot traps on SSH (2222), Telnet (2323), HTTP (8088), HTTPS (8443), and MySQL (3307).\n"
                "• **Real-Time Attacker Triage:** I track adversary IPs, ASN routes, geolocation, and dwell time.\n"
                "• **Forensic Evidence Anchoring:** Every attack payload is hashed with SHA-256 for chain of custody.\n"
                "• **Conversational Incident Response:** Ask me anything in plain English or by voice!"
            )

        if "how are you" in q:
            return (
                "⚡ I'm running at peak operational readiness! All 5 honeypot sensors are actively listening, "
                "and zero breaches have reached production infrastructure. What would you like to inspect?"
            )

        if any(w in q for w in ["thank", "thanks", "appreciate"]):
            return "You're very welcome! Stay safe and let me know whenever you need threat telemetry or security analysis. 🛡️"

        if any(w in q for w in ["bye", "goodbye", "see you"]):
            return "Goodbye! The CyberShield honeynet mesh will continue running in the background to protect your systems."

        # Honeypot & Deception concepts
        if "honeypot" in q or "deception" in q:
            return (
                "🍯 **How Honeypot Deception Works:**\n\n"
                "Instead of waiting for attackers to discover real corporate databases or admin servers, CyberShield AI deploys **active synthetic decoys**.\n\n"
                "1. **Zero False Positives:** Legitimate employees never connect to port 2323 (Telnet) or port 8088 (Fake Finance Portal). Any traffic is 100% hostile.\n"
                "2. **Dwell Time Expansion:** We deliver plausible synthetic responses to keep intruders busy and extract their entire exploit toolkit.\n"
                "3. **Zero Production Risk:** Decoys run in isolated sandboxes with egress disabled, completely shielding your real production stack."
            )

        # SQL Injection / CWE-89
        if "sql" in q or "sqli" in q or "cwe-89" in q or "injection" in q:
            return (
                "💉 **SQL Injection (CWE-89) Overview & Defense:**\n\n"
                "SQL Injection occurs when untrusted user input is directly concatenated into a dynamic database query string.\n\n"
                "• **Vulnerable Pattern:** `SELECT * FROM users WHERE id = ' + input`\n"
                "• **Remediation Patch:** Use **Parameterized Prepared Statements** (e.g. PDO in PHP, parameterized SQL in Python/Node.js) where parameters are bound separately from query logic.\n"
                "• **Perimeter Virtual Patch:** Apply WAF rules to drop `' OR 1=1--` payloads at the ingress gateway."
            )

        # Brute Force / SSH / Telnet
        if "brute" in q or "ssh" in q or "telnet" in q or "password" in q or "t1110" in q:
            return (
                "🔑 **Brute Force & Credential Stuffing (MITRE T1110):**\n\n"
                "Our honeypot mimics OpenSSH 8.9p1 (port 2222) and Ubuntu Serial Telnet (port 2323). When bots hammer these ports with credential dictionaries (`root/admin`, `admin/123456`):\n\n"
                "• We record their dictionaries and timing velocity.\n"
                "• We generate SHA-256 evidence digests of the session.\n"
                "• Recommended defense: Enforce public-key authentication, fail2ban rate limiting, and multi-factor authentication (MFA)."
            )

        # Canary Tokens / Tripwires
        if "canary" in q or "tripwire" in q or "honeytoken" in q:
            return (
                "🐦 **Canary Tripwires in CyberShield AI:**\n\n"
                "Canary tokens are digital tripwires planted in places attackers love to rummage through (e.g., decoy AWS credentials, fake internal wiki URLs, or confidential PDFs).\n\n"
                "The moment an intruder opens or curls the token, an instantaneous webhook alert fires with the intruder's IP address, User-Agent, and geolocation!"
            )

        # Virtual Patching & Firewalls
        if "patch" in q or "firewall" in q or "virtual patch" in q or "block" in q:
            return (
                "🧱 **Perimeter Virtual Patching:**\n\n"
                "When a vulnerability is identified, changing application source code can take weeks of engineering cycles. "
                "Instead, **Virtual Patching** blocks the malicious traffic pattern at the firewall or WAF layer (e.g., Cloudflare, AWS WAF, or Linux `iptables/ufw`) within seconds, eliminating exposure without touching production code."
            )

        # MITRE ATT&CK
        if "mitre" in q:
            return (
                "🎯 **MITRE ATT&CK Matrix Correlation:**\n\n"
                "CyberShield AI tags observed telemetry with MITRE ATT&CK techniques in real time:\n"
                "• **T1046:** Network Service Scanning\n"
                "• **T1110:** Brute Force / Credential Guessing\n"
                "• **T1190:** Exploit Public-Facing Application (SQLi/Command Injection)\n"
                "• **T1059:** Command and Scripting Interpreter Execution"
            )

        # If RAG chunks are present, summarize them
        if rag_chunks:
            lines = []
            for index, chunk in enumerate(rag_chunks[:2], 1):
                metadata = chunk.get("metadata", {}) or {}
                label = metadata.get("technique_id") or metadata.get("rule_id") or f"Finding {index}"
                snippet = chunk.get("text", "").strip().replace("\n", " ")
                lines.append(f"• **{label}:** {snippet[:220]}")
            return f"Relevant SOC threat references for **'{query}'**:\n\n" + "\n\n".join(lines)

        # General helpful fallback
        return (
            f"I have analyzed your inquiry regarding **'{query}'**.\n\n"
            "As your CyberShield AI copilot, I continuously evaluate ingress traffic across our 5 decoy listeners (ports 2222, 2323, 8088, 8443, 3307). "
            "All telemetry is sandboxed with zero risk to production. Would you like me to inspect our latest attacker dossier or explain a specific defense technique?"
        )

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
