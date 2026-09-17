# Judge Briefing — Feature 1: Honeypot Decoy Telemetry Models

> **Commit Scope**: `honeypot/__init__.py`, `honeypot/models.py`  
> **Author**: Harkirat Singh  
> **Topic**: Forensic Data Contracts & Real-Time Telemetry Normalization

---

### 1. What Was Added in This Commit?
* **`DecoySession`**: Strongly typed data structure representing an attacker's complete lifecycle across any decoy port (SSH `2222`, HTTP `8080`, MySQL `3306`, etc.). Tracks:
  * Network tuple: `source_ip`, `source_port`, `destination_port`, `protocol`
  * Behavioral metrics: `bytes_in`, `bytes_out`, `interactions`, `risk_score`
  * Forensic state: `intent` (Reconnaissance, Exploitation), `client_fingerprint`, and containment flags.
* **`TelemetryEvent`**: Granular packet/keystroke event model capturing each raw interaction payload.
* **Cryptographic Hashing (`content_digest`)**: Automatically calculates the SHA-256 digest of every attacker command/payload upon receipt for immutable forensic audit trails.

---

### 2. Why Did We Code It This Way? (Engineering Rationale)
1. **Zero Data Loss & Type Safety**: Using `@dataclass` guarantees strict schemas across asynchronous socket workers and our SQLite persistence layer.
2. **Cryptographic Chain of Custody**: When showing incident evidence to a judge or SOC lead, raw attacker payloads must have an immutable SHA-256 hash so evidence cannot be tampered with.
3. **AI-Ready Schema**: The normalized fields (`intent`, `risk_score`, `metadata`) feed directly into our ChromaDB vector embeddings and Gemini RAG copilot.

---

### 3. Judge Q&A Cheat-Sheet (Exact Speaking Points)

#### 🎙️ If the Judge asks: *"What is the purpose of this initial honeypot module?"*
> **Answer**:  
> *"Sir, before opening raw decoy sockets to attackers, we established a strict forensic data contract. In `honeypot/models.py`, we created `DecoySession` and `TelemetryEvent`. Whenever an adversary connects to one of our decoys, every single keystroke or HTTP request is normalized and hashed with SHA-256 in real-time. This provides an untampered forensic audit trail that directly feeds our real-time SOC dashboard and AI investigation pipeline."*

#### 🎙️ If the Judge asks: *"Why not just use regular Python dictionaries?"*
> **Answer**:  
> *"Dataclasses give us type validation, structured serialization to SQLite/JSON, and prevent runtime KeyError crashes when multi-threaded socket workers concurrently write high-frequency telemetry."*
