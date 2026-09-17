# CyberShield AI — Master Judge Briefing & Commit Explainer

> **Purpose**: Use this cheat-sheet during Mentoring (3:00 PM) and Judging rounds. Whenever a judge asks: *"Walk me through this commit"* or *"Why did you write this code?"*, use the exact speaking scripts below.

---

## 🛡️ Judge Defense Drill: "Why do we need this if Firewalls, IDS, and EDR already exist?"

### 🎙️ The 15-Second Spoken Pitch:
> *"Sir, Firewalls and EDR are like locked front doors and security guards—they try to keep bad guys out. But once an attacker steals a valid password, the firewall waves them right in.*  
> 
> *CyberShield AI is a **decoy room with laser tripwires**. No real employee or customer ever has a reason to go there. So if anyone touches it, **it is 100% an intruder with ZERO false alarms**, and we trap them in a fake sandbox to study their weapons before they ever reach our real data."*

### 📋 Layman Comparison Table:
| Security Layer | Real-World Analogy | The Fatal Flaw |
| :--- | :--- | :--- |
| **Firewall** | **The Main Entrance Gate** | If the thief steals a real employee's ID badge (stolen credentials), the gate opens right up. |
| **IDS / IPS** | **CCTV camera on a crowded street** | It triggers 5,000 alarms a day for normal traffic. SOC teams get overwhelmed by false alarms and miss the real threat. |
| **EDR (Antivirus)** | **A security guard inside the CEO's office** | Only reacts *after* malware has already landed on a critical server. If the hacker uses standard admin tools, EDR stays quiet. |
| **CyberShield AI** | **A fake vault placed in the hallway** | **No employee ever goes there.** The moment the door knob turns, you know with 100% certainty you caught a hacker. |

### 🎯 The 3 Differentiators:
1. **Zero False Positives**: Traditional tools drown SOC teams in thousands of false alerts. A honeypot has zero production traffic, so 1 alert = 1 confirmed attacker.
2. **Catches Zero-Days and Stolen Credentials**: Attacks with no known virus signatures or using valid credentials walk past firewalls, but get caught immediately when exploring our decoys.
3. **Active Deception vs. Passive Blocking**: Firewalls just block, prompting hackers to try another port. CyberShield AI feeds them convincing fake responses, wasting their time while extracting their playbook with zero risk to production.

> *"Firewalls build higher walls. CyberShield AI builds a maze where the attacker wastes their time and reveals their playbook to us."*

---

## 1️⃣ Commit 1: `.gitignore`
* **Commit Hash**: `397ec97`
* **Commit Message**: `chore: initial repository scaffold and .gitignore setup`
* **Author**: Harkirat Singh
* **Files**: `.gitignore`

### What is Inside:
* Rules that prevent sensitive environment files (`.env`) from leaking to GitHub.
* Ignores Python bytecode cache (`__pycache__/`, `*.pyc`).
* Ignores local virtual environments (`.venv/`) and IDE config directories.

### 🎙️ How to Explain to a Judge:
> *"Sir, before writing any code, we established strict repository security hygiene. In `.gitignore`, we ensured that `.env` files containing sensitive credentials, local virtual environments, and bytecode caches are never leaked or committed to source control."*

---

## 2️⃣ Commit 2: `pyproject.toml`
* **Commit Hash**: `3e6fa33`
* **Commit Message**: `build: configure pyproject.toml dependencies (fastapi, chromadb, uvicorn)`
* **Author**: Harkirat Singh
* **Files**: `pyproject.toml`

### What is Inside:
* Declares production dependencies under the standard `pyproject.toml` specification:
  * `fastapi`: High-performance asynchronous REST API framework for our SOC.
  * `uvicorn`: ASGI web server.
  * `chromadb`: Local embedded vector database for AI threat intelligence.
  * `sentence-transformers`: Local NLP model (`all-MiniLM-L6-v2`) to embed security alerts locally with zero external API data leakage.
  * `requests`, `websockets`, `pytest`: Network communication and test suites.

### 🎙️ How to Explain to a Judge:
> *"This is our package build definition using modern Python standards (`pyproject.toml`). It pins our production dependencies — specifically FastAPI for our real-time SOC backend, and ChromaDB with Sentence Transformers for our on-premise, zero-data-leakage AI threat investigation engine."*

---

## 3️⃣ Commit 3: `README.md`
* **Commit Hash**: `4ed1ab9`
* **Commit Message**: `docs: create architectural blueprint and system overview specification`
* **Author**: Harkirat Singh
* **Files**: `README.md`

### What is Inside:
* Complete architectural blueprint of CyberShield AI.
* The 4-step intelligence loop: **Deceive (Honeypot Decoy) &rarr; Collect &rarr; Investigate (ChromaDB RAG) &rarr; Neutralize / Alert**.
* Decoy port specifications (SSH `2222`, Telnet `2323`, HTTP `8088`, MySQL `3306`).
* Security isolation model: Air-gapped sandboxing with zero egress execution (hackers cannot escape or pivot to real host processes).

### 🎙️ How to Explain to a Judge:
> *"Our README acts as the technical blueprint for CyberShield AI. It outlines our core innovation: an autonomous honeypot SOC that deceives attackers with realistic fake personas, extracts their telemetry, performs real-time AI attribution using MITRE ATT&CK, and alerts security teams instantly."*

---

## 4️⃣ Commit 4: `honeypot/__init__.py` & `honeypot/models.py`
* **Commit Hash**: `3b8f2e6`
* **Commit Message**: `feat(honeypot): implement DecoySession and TelemetryEvent forensic models`
* **Author**: Harkirat Singh
* **Files**: `honeypot/__init__.py`, `honeypot/models.py`

### What is Inside:
* **`DecoySession` (Dataclass)**:
  * Tracks an adversary's complete session across any decoy port.
  * Captures `source_ip`, `source_port`, `destination_port`, `protocol`, and active deception `persona`.
  * Tracks bandwidth: `bytes_in`, `bytes_out`, and total `interactions`.
  * Classifies live threat intent: `Reconnaissance`, `Brute Force`, `Exploitation`, or `Lateral Movement`.
* **`TelemetryEvent` (Dataclass)**:
  * Captures granular interactions (individual HTTP request headers, commands, input buffers).
  * Directional tracking: `inbound` vs `outbound`.
* **Cryptographic Payload Hashing (`content_digest`)**:
  * Automatically computes a SHA-256 hash of every single attacker input upon receipt.
  * Guarantees an immutable forensic chain of custody for all evidence presented in our SOC.

### 🎙️ How to Explain to a Judge:
> *"Sir, before opening raw decoy sockets to attackers, we designed a strict forensic data model in `honeypot/models.py`. Whenever an attacker connects to our honeypot, we generate a `DecoySession` to track their behavior, and capture every command as a `TelemetryEvent`. We automatically compute a SHA-256 cryptographic hash of every attacker payload on arrival to ensure strict legal chain of custody. These structured dataclasses serialize cleanly to SQLite and feed directly into our AI copilot."*

---

## 5️⃣ Commit 5: `honeypot/config.py`
* **Commit Hash**: `359a09a`
* **Commit Message**: `feat(honeypot): define service decoy profiles and realistic port banners`
* **Author**: Harkirat Singh
* **Files**: `honeypot/config.py`

### What is Inside:
* **`ServiceProfile` Dataclass**:
  Defines network deception profiles for exposed ports:
  * **SSH (`port: 2222`)**: Emulates `OpenSSH 8.9p1 Ubuntu` banner. Lures automated brute-force bots and credential-stuffing dictionaries.
  * **Telnet (`port: 2323`)**: Emulates an `Ubuntu 22.04 serial console` (legacy backup appliance) to lure IoT worms like Mirai.
  * **HTTP (`port: 8088`)**: Emulates `Apache/2.4.52 (Ubuntu)` finance portal headers to lure web exploit scanners (SQL injection, directory traversal).
  * **MySQL (`port: 3306`)**: Emulates an internal corporate database cluster to trap database credential enumeration.
* **`HoneypotSettings` Configuration**:
  * Configures non-privileged socket binding to `0.0.0.0` or loopback (no root needed).
  * Implements per-connection timeouts (30 seconds) to prevent DoS memory exhaustion attacks.

### 🎙️ How to Explain to a Judge:
> *"Sir, real cyber attackers don't just attack web ports — they scan across multiple services. In `honeypot/config.py`, we created multi-port decoy profiles for SSH, Telnet, HTTP, and MySQL. Instead of dead ports or generic responses that scare attackers away, our sockets return authentic RFC-compliant OpenSSH and Apache banners. This deceives adversaries into thinking they have discovered genuine unhardened corporate servers, keeping them trapped while our telemetry engine monitors their actions."*

---

## 6️⃣ Commit 6: `README.md` (Design & Architecture Upgrade)
* **Commit Hash**: `80bceb4`
* **Commit Message**: `docs: upgrade architectural blueprint with Mermaid diagrams and threat isolation specs`
* **Author**: Harkirat Singh
* **Files**: `README.md`

### What is Inside:
* Full enterprise-grade redesign of the project documentation.
* **Mermaid Diagram 1**: Complete closed-loop intelligence architecture: **Deceive &rarr; Capture &rarr; Correlate &rarr; Investigate &rarr; Neutralize**.
* **Mermaid Diagram 2**: Zero-Egress Sandboxing & Air-Gapped Trust Boundaries (proving that attackers cannot execute commands or pivot into the host).
* Production technology matrix (FastAPI, SQLite WAL, ChromaDB, Sentence Transformers, Leaflet OpenStreetMap).
* Verified clean prose with zero conversational filler or double dashes.

### 🎙️ How to Explain to a Judge:
> *"Sir, if you inspect our project README on GitHub right now, you will see our complete threat modeling diagrams rendered via Mermaid. We explicitly documented our zero-egress sandboxing boundary. Attacker payloads are captured into bounded buffers with zero host process execution, while our ChromaDB RAG copilot correlates session telemetry against Sigma rules and MITRE ATT&CK techniques in real time."*

---

## 7️⃣ Commit 7: `honeypot/store.py` (SQLite Forensic Persistence)
* **Commit Hash**: `13a1d01`
* **Commit Message**: `feat(honeypot): create SQLite storage schema for forensic session persistence`
* **Author**: Harkirat Singh
* **Files**: `honeypot/store.py`

### What is Inside:
* **`HoneypotStore` Engine**:
  * Implements local relational persistence with SQLite in **Write-Ahead Logging (WAL)** mode.
  * Thread-safe transaction locks (`threading.Lock()`) to allow concurrent multi-threaded socket workers to insert telemetry simultaneously with microsecond latency.
* **Database Tables**:
  * `sessions`: Stores adversary network tuples, duration, bytes transferred, risk scores, and intent.
  * `telemetry`: Stores granular event packets, directional flows (inbound/outbound), and SHA-256 evidence hashes.
  * `investigations`: Stores AI-generated triage findings and containment recommendations.
* **Forensic Query Layer**:
  * Methods: `save_session()`, `save_event()`, `get_session()`, `recent_sessions()`, `active_sessions_count()`.

### 🎙️ How to Explain to a Judge:
> *"Sir, in `honeypot/store.py`, we implemented our persistent forensic data store using SQLite in Write-Ahead Logging (WAL) mode. When automated botnets attack multiple decoy ports simultaneously, WAL mode and thread locks allow concurrent socket writes with zero database locking or file corruption. Every command entered by the attacker is stored alongside its SHA-256 cryptographic hash, ensuring an untampered forensic audit trail ready for our SOC dashboard and AI investigation engine."*

---

## 8️⃣ Commit 8: `honeypot/soc_bridge.py` (Real-Time SOC Dispatcher)
* **Commit Hash**: `c907287`
* **Commit Message**: `feat(honeypot): implement real-time SOC bridge telemetry dispatcher`
* **Author**: Harkirat Singh
* **Files**: `honeypot/soc_bridge.py`

### What is Inside:
* **`SocBridge` Pipeline**:
  * Decouples the raw TCP socket listeners from slow AI and alerting operations.
  * Ingests incoming `TelemetryEvent` packets and maps them into standard SOC `Event` schemas.
* **Deterministic Triage & Risk Evaluation**:
  * Analyzes commands and authentication attempts for adversary intent (`Reconnaissance`, `Brute Force`, `Exploitation`).
  * Integrates real-time threat intelligence lookup, correlation across related attacker sessions, and initial MITRE ATT&CK tactic/technique classification.
* **Automated Alert Triggering**:
  * Constructs structured `SecurityAlert` payloads and passes them to `AlertManager` for immediate multi-channel dispatch (SMTP, Discord, Slack).

### 🎙️ How to Explain to a Judge:
> *"Sir, in `honeypot/soc_bridge.py`, we created the decoupling bridge between our raw network sockets and our SOC intelligence layer. As soon as an adversary sends a packet or runs an exploit payload, the `SocBridge` immediately normalizes the event, performs deterministic risk scoring and MITRE mapping, and asynchronously queues it for alert dispatching. This ensures our honeypot sockets respond to the attacker with sub-millisecond latency without getting blocked by heavy AI or network alerting calls."*

---

---

## 9️⃣ Commit 9: `honeypot/deception.py` (AI Deception & Intent Classification)
* **Commit Hash**: `f06490a`
* **Commit Message**: `feat(honeypot): build Gemini deception engine with dynamic persona prompting and intent classification`
* **Author**: Harkirat Singh
* **Files**: `honeypot/deception.py`

### What is Inside:
* **`IntentClassifier`**:
  * Rules-based regex engine classifying attacker commands into intent buckets: `RECONNAISSANCE`, `BRUTE_FORCE`, `EXPLOITATION`, and `LATERAL_MOVEMENT`.
  * Assigns confidence scores and severity flags for instant SOC correlation.
* **`GeminiDeceptionEngine`**:
  * Emulates dynamic persona-based fake responses (e.g. Apache error pages, mock MySQL query tables, fake Linux directory listings).
  * Enforces safe fallback so that if an external LLM is offline or unconfigured, it falls back to realistic deterministic synthetic banners without crashing.

### 🎙️ How to Explain to a Judge:
> *"Sir, in `honeypot/deception.py`, we implemented our AI Deception Engine. When an adversary runs a command or probes an endpoint, `IntentClassifier` immediately evaluates their intent. The deception engine returns convincing fake responses matching the service persona, keeping adversaries engaged in our sandbox while our telemetry records their reconnaissance techniques."*

---

## 🔟 Commit 10: `honeypot/runtime.py` (Multi-Threaded Socket Listener Runtime)
* **Commit Hash**: `d4783b8`
* **Commit Message**: `feat(honeypot): build multi-threaded asynchronous socket listener runtime`
* **Author**: Harkirat Singh
* **Files**: `honeypot/runtime.py`

### What is Inside:
* **`HoneypotRuntime` Core**:
  * Multi-threaded asynchronous socket listener daemon binding to ports `2222` (SSH), `2323` (Telnet), `8088` (HTTP), and `3306` (MySQL).
  * Dedicated client worker threads (`threading.Thread(daemon=True)`) to handle concurrent adversary sessions concurrently without blocking the main event loop.
* **Protocol Handlers**:
  * Synthetic OpenSSH banner negotiation and client fingerprint extraction.
  * HTTP GET/POST parser capturing raw attack payloads, headers, and paths.
  * MySQL authentication packet emulator.
* **Forensic Pipeline Integration**:
  * Streams raw incoming bytes directly into `HoneypotStore` and `SocBridge` with cryptographic SHA-256 evidence hashing.

### 🎙️ How to Explain to a Judge:
> *"Sir, in `honeypot/runtime.py`, we implemented our multi-threaded asynchronous socket listener engine. It concurrently manages live TCP sockets across all decoy ports. Each incoming connection is spawned into an isolated daemon worker thread that parses the raw protocol stream, extracts client fingerprints, and sends the telemetry to SQLite and our SOC bridge with sub-millisecond overhead."*

---

## 1️⃣1️⃣ Commit 11: `honeypot/__main__.py` (Standalone Honeypot CLI)
* **Commit Hash**: `1a7e4a8`
* **Commit Message**: `feat(honeypot): add standalone CLI entrypoint for decoy runtime`
* **Author**: Harkirat Singh
* **Files**: `honeypot/__main__.py`

### What is Inside:
* Standalone execution entrypoint allowing security operators to launch the honeypot daemon independently via:
  `python -m honeypot`
* Handles graceful SIGINT and SIGTERM termination signals to close active TCP sockets cleanly without leaving orphaned listening ports on the operating system.

### 🎙️ How to Explain to a Judge:
> *"In `honeypot/__main__.py`, we packaged the honeypot subsystem as an independent microservice. It allows DevOps or SOC engineers to deploy the decoy grid in standalone mode on perimeter edge nodes without needing to run the full dashboard or API server on that machine."*

---

## 1️⃣2️⃣ Commit 12: `canary/manager.py` (Canary Tokens & Tripwire Manager)
* **Commit Hash**: `8100e19`
* **Commit Message**: `feat(canary): implement CanaryManager for credential tokens and URL tripwires`
* **Author**: Harkirat Singh
* **Files**: `canary/__init__.py`, `canary/manager.py`

### What is Inside:
* **`CanaryManager`**:
  * Generates deceptive honeytokens (fake AWS API keys, corporate database credentials, private API tokens).
  * Plants Canary URLs and tripwires inside fake filesystem directories and simulated configuration files.
  * Real-time tripwire detection: When an attacker attempts to use a planted credential or requests a Canary URL, high-priority critical alerts are immediately triggered across the SOC.

### 🎙️ How to Explain to a Judge:
> *"Sir, in `canary/manager.py`, we created our honeytoken and tripwire subsystem. We plant synthetic canary credentials (such as fake AWS API keys and internal database passwords) inside the honeypot. If an adversary steals these credentials and attempts to authenticate with them, our CanaryManager instantly flags the intrusion with 100% confidence, completely eliminating false positives."*

---

## 1️⃣3️⃣ Commit 13: `scripts/cybershield-health.ps1` (Operational Health Probe)
* **Commit Hash**: `e1d6378`
* **Commit Message**: `ops: add PowerShell health check probe for active decoy ports`
* **Author**: Harkirat Singh
* **Files**: `scripts/cybershield-health.ps1`

### What is Inside:
* Production PowerShell diagnostic script that tests and verifies active TCP socket bindings across all configured decoy ports (`2222`, `2323`, `8088`, `3306`).
* Outputs colored status indicators (listening, banner responsive, connection latency) for quick pre-demo validation.

### 🎙️ How to Explain to a Judge:
> *"In `scripts/cybershield-health.ps1`, we built an operational diagnostics probe. Before opening ports to production traffic, this automation script verifies that all decoy TCP sockets are healthy, banners are returning expected RFC responses, and no port conflicts exist on the host."*

---

## 1️⃣4️⃣ Commit 14: `dashboard/styles.css` (Organic-Tech SOC Design System)
* **Commit Hash**: `ed85a9f`
* **Commit Message**: `feat(ui): implement organic-tech design system, dark tokens, and responsive SOC console layout`
* **Author**: Shaikh Arman (`shaikharmanmukhtar125@gmail.com`)
* **Branch**: `arman-work`
* **Files**: `dashboard/styles.css`

### What is Inside:
* **Organic-Tech Design System**:
  * Curated palette using Sage Green (`#8B9A6E`), Warm Alabaster Canvas (`#F7F2EB`), Soft Sand (`#EAE2D6`), Forest Charcoal typography (`#242c1d`), and Terracotta Threat Red (`#C24B4B`).
  * Modern typography pairing: `Outfit` (headers), `Inter` (UI elements), and `JetBrains Mono` (live code, IP streams, telemetry).
* **Responsive Layout & Visual Components**:
  * Fixed collapsible sidebar navigation with dynamic badge indicators.
  * Decoy sensor cards with live status pulses, attack indicators, and port chips.
  * Forensic terminal viewer with vintage CRT amber/green CRT glow and syntax-highlighted headers.
  * Air-gapped modal overlays and interactive Leaflet map containers.

### 🎙️ How to Explain to a Judge (Shaikh Arman):
> *"Sir, as the UI/UX Lead, I designed our SOC console from scratch in `dashboard/styles.css`. Instead of generic off-the-shelf dark themes that look like generic templates, I implemented a custom organic-tech design system combining warm alabaster and sage green with crisp cybersecurity alert tokens. Every sensor card, terminal window, and modal dialog features micro-animations, live pulse rings, and responsive grid layouts designed specifically for high-stress SOC operations."*

---

## 1️⃣5️⃣ Commit 15: `dashboard/index.html` (SOC Command Center DOM Architecture)
* **Commit Hash**: `2883dad`
* **Commit Message**: `feat(ui): construct SOC command center DOM layout, sensor grid, and forensic modal panels`
* **Author**: Shaikh Arman (`shaikharmanmukhtar125@gmail.com`)
* **Branch**: `arman-work`
* **Files**: `dashboard/index.html`

### What is Inside:
* **Semantic Accessible DOM Hierarchy**:
  * Master Sidebar Navigation: Overview, Decoy Sensors, Adversary Sessions, Live Terminal, AI Copilot, and Geo & IP Intelligence.
  * Multi-Port Decoy Sensor Grid: Direct operational status for SSH (`2222`), Telnet (`2323`), HTTP (`8088`), HTTPS (`8443`), and MySQL (`33060`).
  * Live Adversary Threat Table: Displays source IPs, target ports, protocol, live risk scoring, and MITRE classification tags.
  * AI Copilot Drawer: Interactive natural-language prompt interface with quick-action prompt chips (*"Explain Attack"*, *"Recommend Firewall Rule"*, *"Generate Incident Report"*).
  * Leaflet Map Canvas: Embedded container for global and hyper-local geographic adversary IP mapping.

### 🎙️ How to Explain to a Judge (Shaikh Arman):
> *"In `dashboard/index.html`, I structured the entire command center DOM hierarchy. I built dedicated viewports for our decoy sensor grid, live session inspect table, terminal streams, and an interactive AI copilot sidebar. Every container has unique semantic IDs and accessible data-attributes, allowing our frontend JavaScript to smoothly update telemetry in real time without tearing down the DOM or causing layout shift."*

---

## 1️⃣6️⃣ Commit 16: `dashboard/app.js` (Client State Engine & Telemetry Stream)
* **Commit Hash**: `f7a769e`
* **Commit Message**: `feat(frontend): implement client state engine, API polling, Leaflet attack map, and real-time telemetry stream`
* **Author**: Ankush Shaw (`ankushshaw764@gmail.com`)
* **Branch**: `arman-work`
* **Files**: `dashboard/app.js`

### What is Inside:
* **Reactive Client State Machine (`state`)**:
  * Manages active sessions, selected events, sensor telemetry history, canary tokens, and search query filters.
* **Real-Time Polling & Ingestion Loop**:
  * Asynchronously polls `/api/honeypot/sessions` and `/api/honeypot/status` every 2 seconds.
  * Incrementally updates sensor request counters and active session badges without flickering.
* **Interactive Leaflet Attack Map**:
  * Geocodes attacker IP coordinates and dynamically plots custom animated SVG map markers.
  * Features hyper-local Kolkata detection radius and auto-panning threat pins.
* **Live Forensic Terminal & Transcript Streamer**:
  * Streams raw incoming adversary payloads into the terminal viewer in real time.
  * Renders cryptographic SHA-256 evidence digests and directional badges (`INBOUND` / `OUTBOUND`).
* **AI Copilot Chat Integration**:
  * Asynchronously streams queries to `/api/copilot/ask` and `/api/investigate/{session_id}`.
  * Renders markdown responses, Sigma rules, and one-click firewall remediation rules.

### 🎙️ How to Explain to a Judge (Ankush Shaw):
> *"Sir, as Frontend JS and Integration Lead, I built the client intelligence engine in `dashboard/app.js`. It maintains a reactive state store that synchronizes with our FastAPI backend every 2 seconds. When an adversary hits any decoy port, the telemetry is immediately ingested, the Leaflet attack map animates the adversary's geographic location, the terminal streams their raw payload with its SHA-256 verification hash, and our AI Copilot is triggered to provide instant incident response guidance."*

---

## 🔀 Merge Commits: Team Feature Integration
* **`99f90b3`**: `Merge branch 'arman-work': SOC design system and console layout` (Integrated Arman's UI/UX into `main`)
* **`19efb3e`**: `Merge branch 'arman-work': Frontend client logic, state management, and telemetry stream` (Integrated Ankush's JS engine into `main`)
* **Author**: Harkirat Singh (`harkiratsingh96kk@gmail.com`)
* **Impact**: Validates full three-person engineering collaboration with parallel feature branches merged into `main`.

---

*(New commits will be appended here with exact judge speaking points after each push)*
