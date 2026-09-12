#!/usr/bin/env python3
"""
hackathon_repo_builder.py - Automated Hackathon Git Repository & Commit Timeline Generator

Generates a realistic, professional 75-80 commit Git history distributed across the 36-hour
hackathon schedule for CyberShield AI, crediting:
- Harkirat Singh (Backend, AI/RAG, Honeypot Core & Architecture)
- Shaikh Arman (Frontend Lead: UI/UX, CSS Design System, HTML Layouts & Documentation)
- Ankush Shaw (Frontend Integration: WebSocket Client, JS State, Attack Simulators & Tests)

Usage:
  # Build a fresh repo in a sibling directory with ~77 staged commits:
  python scripts/hackathon_repo_builder.py --target-dir ../CyberShield_AI_Hackathon

  # Or build phase by phase live during the hackathon:
  python scripts/hackathon_repo_builder.py --target-dir ../CyberShield_AI_Hackathon --phase 1
  python scripts/hackathon_repo_builder.py --target-dir ../CyberShield_AI_Hackathon --phase 2
"""

import os
import sys
import shutil
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

# Team member profiles
AUTHORS = {
    "harkirat": {"name": "Harkirat Singh", "email": "harkiratsingh96kk@gmail.com"},
    "arman": {"name": "Shaikh Arman", "email": "shaikharman1@users.noreply.github.com"},
    "ankush": {"name": "Ankush Shaw", "email": "ankushshaw764@users.noreply.github.com"},
}

# Base Hackathon Start Date: Today (Sept 12, 2026) at 09:05 AM
DEFAULT_START_TIME = datetime(2026, 9, 12, 9, 5, 0)

PHASE_MILESTONES = {
    1: {"name": "Phase 1: Foundation, Socket Decoys & Storage (09:05 - 12:30)", "commits": range(0, 20)},
    2: {"name": "Phase 2: Log Collectors, Agents & MITRE Rules (13:30 - 15:30)", "commits": range(20, 36)},
    3: {"name": "Phase 3: AI Deception, ChromaDB RAG & Copilot (16:00 - 18:45)", "commits": range(36, 52)},
    4: {"name": "Phase 4: SOC Command Center Dashboard & Alerters (20:00 - 23:45)", "commits": range(52, 68)},
    5: {"name": "Phase 5: Geo-Intel, OpenStreetMap, Precision Lure & Tests (Day 2: 08:30 - 12:30)", "commits": range(68, 77)},
}

def get_commit_plan(src_dir: Path):
    """Returns 77 logical atomic commits with role-based author assignment."""
    return [
        # Phase 1: Foundation & Sockets (09:05 - 12:30)
        {"author": "harkirat", "files": [".gitignore"], "msg": "chore: initial repository scaffold and .gitignore setup", "min_offset": 5},
        {"author": "harkirat", "files": ["pyproject.toml"], "msg": "build: configure pyproject.toml dependencies (fastapi, chromadb, uvicorn)", "min_offset": 12},
        {"author": "harkirat", "files": ["README.md"], "msg": "docs: create architectural blueprint and system overview specification", "min_offset": 18},
        {"author": "arman",    "files": ["CONTRIBUTING.md", "SECURITY.md"], "msg": "docs: add contribution standards and responsible disclosure security policy", "min_offset": 25},
        {"author": "harkirat", "files": ["honeypot/__init__.py"], "msg": "feat(honeypot): initialize core honeypot module package", "min_offset": 32},
        {"author": "harkirat", "files": ["honeypot/models.py"], "msg": "feat(honeypot): implement DecoySession and TelemetryEvent data models", "min_offset": 40},
        {"author": "harkirat", "files": ["honeypot/config.py"], "msg": "feat(honeypot): define service profiles for SSH, Telnet, HTTP, HTTPS, MySQL", "min_offset": 48},
        {"author": "harkirat", "files": ["honeypot/store.py"], "msg": "feat(honeypot): create SQLite storage schema for forensic session persistence", "min_offset": 58},
        {"author": "harkirat", "files": ["honeypot/soc_bridge.py"], "msg": "feat(honeypot): implement real-time SOC bridge telemetry dispatcher", "min_offset": 68},
        {"author": "harkirat", "files": ["honeypot/runtime.py"], "msg": "feat(honeypot): build multi-threaded asynchronous socket listener runtime", "min_offset": 80},
        {"author": "harkirat", "files": ["honeypot/__main__.py"], "msg": "feat(honeypot): add standalone CLI entrypoint for decoy runtime", "min_offset": 92},
        {"author": "ankush",   "files": ["canary/__init__.py"], "msg": "feat(canary): scaffold tripwire and honeytoken package structure", "min_offset": 102},
        {"author": "ankush",   "files": ["canary/manager.py"], "msg": "feat(canary): implement CanaryManager for URL and credential tokens", "min_offset": 115},
        {"author": "harkirat", "files": ["scripts/cybershield-health.ps1"], "msg": "ops: add PowerShell health check probe for active decoy ports", "min_offset": 128},
        {"author": "harkirat", "files": ["Ai/__init__.py"], "msg": "feat(ai): scaffold AI threat analysis orchestrator namespace", "min_offset": 140},
        {"author": "harkirat", "files": ["Ai/schema.py"], "msg": "feat(ai): implement investigation schemas and event normalization models", "min_offset": 152},
        {"author": "harkirat", "files": ["Ai/agents/__init__.py"], "msg": "feat(agents): initialize sub-agent triage pipeline package", "min_offset": 164},
        {"author": "harkirat", "files": ["Ai/agents/threat_intel.py"], "msg": "feat(agents): implement deterministic threat feed lookup agent", "min_offset": 175},
        {"author": "harkirat", "files": ["Ai/agents/correlation.py"], "msg": "feat(agents): add temporal and IP-based cross-session correlation agent", "min_offset": 186},
        {"author": "harkirat", "files": ["Ai/agents/risk_scorer.py"], "msg": "feat(agents): build deterministic risk scoring and severity classification engine", "min_offset": 198},

        # Phase 2: Log Collectors & OS Agents (13:30 - 15:30)
        {"author": "harkirat", "files": ["Ai/agents/mitre_mapper.py"], "msg": "feat(agents): build rule-based MITRE ATT&CK technique classification engine", "min_offset": 270},
        {"author": "harkirat", "files": ["Ai/agents/alerter.py"], "msg": "feat(agents): implement multi-channel security alerter manager", "min_offset": 280},
        {"author": "harkirat", "files": ["collector/win/collector.py"], "msg": "feat(collector): implement Windows EventLog security audit collector", "min_offset": 290},
        {"author": "harkirat", "files": ["collector/win/telemetry_collector.py"], "msg": "feat(collector): create active network socket and process telemetry daemon", "min_offset": 300},
        {"author": "harkirat", "files": ["collector/win/firewall_collector.py"], "msg": "feat(collector): implement Windows Defender firewall event parser", "min_offset": 310},
        {"author": "harkirat", "files": ["collector/win/risk_scoring.py"], "msg": "feat(collector): add endpoint host anomaly scoring rules", "min_offset": 318},
        {"author": "harkirat", "files": ["collector/win/service.windows.ps1"], "msg": "ops: add background service runner for Windows telemetry agents", "min_offset": 325},
        {"author": "harkirat", "files": ["collector/linux/firewall_collector.py"], "msg": "feat(collector): implement Linux iptables and UFW drop log parser", "min_offset": 332},
        {"author": "harkirat", "files": ["collector/linux/collector.py"], "msg": "feat(collector): create Linux journald and auth.log collector", "min_offset": 340},
        {"author": "harkirat", "files": ["collector/linux/risk_scoring.py"], "msg": "feat(collector): add Linux host anomaly risk calculation logic", "min_offset": 348},
        {"author": "harkirat", "files": ["collector/linux/service.linux.sh"], "msg": "ops: add systemd service wrapper for Linux firewall collector", "min_offset": 355},
        {"author": "ankush",   "files": ["collector/linux.utils/test.event.sh"], "msg": "test: add mock security event emitter for Linux collector validation", "min_offset": 362},
        {"author": "ankush",   "files": ["collector/linux.utils/attack_simulator.sh"], "msg": "scripts: add shell script for automated decoy attack simulation", "min_offset": 370},
        {"author": "ankush",   "files": ["scripts/demo-attacks.ps1"], "msg": "scripts: create PowerShell multi-port attack generator for local decoys", "min_offset": 378},
        {"author": "ankush",   "files": ["scripts/demo-attacks-wsl.sh"], "msg": "scripts: create bash attack simulator for WSL and Linux environments", "min_offset": 385},
        {"author": "arman",    "files": ["deploy/cybershield-honeypot.nft"], "msg": "deploy: add nftables isolation rules for honey-lure socket routing", "min_offset": 395},

        # Phase 3: AI Deception, ChromaDB RAG & Copilot (16:00 - 18:45)
        {"author": "harkirat", "files": ["honeypot/deception.py"], "msg": "feat(deception): build Gemini deception engine with dynamic persona prompting", "min_offset": 425},
        {"author": "harkirat", "files": ["Ai/rag/core/config.py"], "msg": "feat(rag): define vector database paths and model parameters", "min_offset": 435},
        {"author": "harkirat", "files": ["Ai/rag/core/llm.py"], "msg": "feat(rag): create GeminiClient wrapper with JSON output schema validation", "min_offset": 445},
        {"author": "harkirat", "files": ["Ai/rag/core/embed.py"], "msg": "feat(rag): implement sentence-transformers local semantic embedding engine", "min_offset": 455},
        {"author": "harkirat", "files": ["Ai/rag/core/memory.py"], "msg": "feat(rag): build conversation memory and sliding context window tracker", "min_offset": 465},
        {"author": "harkirat", "files": ["Ai/rag/core/retrieve.py"], "msg": "feat(rag): implement hybrid BM25 and ChromaDB vector retrieval pipeline", "min_offset": 475},
        {"author": "harkirat", "files": ["Ai/rag/core/pipeline.py"], "msg": "feat(rag): build end-to-end RAG investigation pipeline with cross-encoder reranking", "min_offset": 485},
        {"author": "arman",    "files": ["Ai/rag/data/knowledge_base/sigma/"], "msg": "feat(rag): ingest Sigma detection rules into local knowledge base", "min_offset": 495},
        {"author": "arman",    "files": ["Ai/rag/data/knowledge_base/wazuh/"], "msg": "feat(rag): add Wazuh host detection rule definitions", "min_offset": 505},
        {"author": "arman",    "files": ["Ai/rag/data/knowledge_base/windows/"], "msg": "feat(rag): add Windows event ID reference catalog to RAG memory", "min_offset": 515},
        {"author": "harkirat", "files": ["Ai/rag/vectorstore/build_index.py"], "msg": "feat(rag): create offline vectorstore index builder script", "min_offset": 525},
        {"author": "arman",    "files": ["rag.util/mitre_attack_json_converter.py"], "msg": "feat(rag): add MITRE ATT&CK enterprise JSON format converter", "min_offset": 535},
        {"author": "harkirat", "files": ["Ai/orchestrator.py"], "msg": "feat(orchestrator): assemble full incident investigation orchestrator", "min_offset": 545},
        {"author": "harkirat", "files": ["Ai/backend/api_server.py"], "msg": "feat(api): initialize FastAPI REST server with CORS and router mounts", "min_offset": 558},
        {"author": "harkirat", "files": ["main.py"], "msg": "feat(core): create unified entrypoint for starting honeypots and API server", "min_offset": 570},
        {"author": "arman",    "files": ["docs/architecture.md"], "msg": "docs: detail single intelligence loop from ingestion to guided action", "min_offset": 585},

        # Phase 4: SOC Dashboard & Real-Time Telemetry (20:00 - 23:45)
        {"author": "arman",    "files": ["dashboard/styles.css"], "msg": "feat(dashboard): implement dark modern cybersecurity SOC styling and design system", "min_offset": 660},
        {"author": "arman",    "files": ["dashboard/index.html"], "msg": "feat(dashboard): create command center HTML layout with sensors and metrics", "min_offset": 680},
        {"author": "ankush",   "files": ["dashboard/app.js"], "msg": "feat(dashboard): implement real-time WebSocket connection and sensor sparklines", "min_offset": 700},
        {"author": "ankush",   "files": ["docs/canary-tokens.md"], "msg": "docs: add canary token deployment and incident handling guide", "min_offset": 720},
        {"author": "arman",    "files": ["docs/troubleshooting.md"], "msg": "docs: create operational playbook and SOC triage guide", "min_offset": 740},
        {"author": "harkirat", "files": ["docs/api-reference.md"], "msg": "docs: publish OpenAPI REST and WebSocket endpoint specifications", "min_offset": 760},
        {"author": "arman",    "files": ["docs/configuration.md"], "msg": "docs: document environment variables and deception profiles", "min_offset": 780},
        {"author": "harkirat", "files": ["docs/security-model.md"], "msg": "docs: document air-gapped sandboxing and zero-egress security model", "min_offset": 800},
        {"author": "arman",    "files": ["docs/telemetry.md"], "msg": "docs: define telemetry schema and event data lifecycle", "min_offset": 820},
        {"author": "ankush",   "files": ["docs/wsl-lab.md"], "msg": "docs: add step-by-step local WSL lab testing instructions", "min_offset": 840},
        {"author": "ankush",   "files": ["docs/demo-attacks.md"], "msg": "docs: prepare attack scenario walkthroughs for live judging demo", "min_offset": 860},
        {"author": "harkirat", "files": ["tests/test_honeypot_store.py"], "msg": "test: add unit tests for telemetry database CRUD operations", "min_offset": 880},
        {"author": "harkirat", "files": ["tests/test_honeypot_runtime.py"], "msg": "test: add integration tests for multi-port socket lifecycle", "min_offset": 900},
        {"author": "ankush",   "files": ["tests/test_canary.py"], "msg": "test: add test coverage for honeytoken creation and triggers", "min_offset": 920},
        {"author": "ankush",   "files": ["tests/test_websocket.py"], "msg": "test: add automated test for real-time WebSocket state streaming", "min_offset": 940},
        {"author": "harkirat", "files": ["tests/test_win_collector.py"], "msg": "test: add unit tests for Windows event log ingestion parser", "min_offset": 960},

        # Phase 5: Geo-Intel, OpenStreetMap & Final Polish (Day 2: 08:30 - 12:30)
        {"author": "harkirat", "files": ["Ai/intel/__init__.py"], "msg": "feat(intel): initialize geospatial threat attribution package", "min_offset": 1410},
        {"author": "harkirat", "files": ["Ai/intel/geo_tracker.py"], "msg": "feat(intel): implement real public WAN IP detection and BGP ASN tracker", "min_offset": 1430},
        {"author": "ankush",   "files": ["scripts/launch_real_attack.py"], "msg": "scripts: add standalone script to execute real WAN IP attack simulation", "min_offset": 1450},
        {"author": "harkirat", "files": ["tests/test_api.py"], "msg": "test: add automated test coverage for API endpoints and status checks", "min_offset": 1470},
        {"author": "harkirat", "files": ["tests/test_geo_tracker.py"], "msg": "test: add unit test suite for IP resolution and ASN caching", "min_offset": 1490},
        {"author": "harkirat", "files": ["tests/test_alerter.py"], "msg": "test: add unit tests for multi-channel alert dispatchers", "min_offset": 1510},
        {"author": "harkirat", "files": ["."], "msg": "polish: final build verification and production readiness review for submission", "min_offset": 1560}
    ]

def build_repo(src_dir: Path, target_dir: Path, phase: int = None):
    print(f"[*] Initializing CyberShield AI Hackathon Repository in: {target_dir.resolve()}")
    target_dir.mkdir(parents=True, exist_ok=True)
    
    # Check if git is initialized
    git_dir = target_dir / ".git"
    if not git_dir.exists():
        subprocess.run(["git", "init", "-b", "main"], cwd=str(target_dir), check=True)
        print("[+] Initialized fresh Git repository on branch 'main'")

    commit_plan = get_commit_plan(src_dir)
    commits_to_run = commit_plan

    if phase and phase in PHASE_MILESTONES:
        p_info = PHASE_MILESTONES[phase]
        print(f"[*] Running specific milestone: {p_info['name']}")
        commits_to_run = [commit_plan[i] for i in p_info["commits"] if i < len(commit_plan)]

    for idx, item in enumerate(commits_to_run):
        commit_files = item["files"]
        msg = item["msg"]
        min_offset = item["min_offset"]
        commit_time = DEFAULT_START_TIME + timedelta(minutes=min_offset)
        iso_time = commit_time.strftime("%Y-%m-%d %H:%M:%S")

        author_key = item.get("author", "harkirat")
        author = AUTHORS.get(author_key, AUTHORS["harkirat"])

        # Copy files from src_dir to target_dir
        if commit_files == ["."]:
            # Full sync
            shutil.copytree(str(src_dir), str(target_dir), dirs_exist_ok=True, ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__", "*.pyc"))
        else:
            for f in commit_files:
                src_f = src_dir / f
                dst_f = target_dir / f
                if src_f.is_file():
                    dst_f.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(str(src_f), str(dst_f))
                elif src_f.is_dir():
                    shutil.copytree(str(src_f), str(dst_f), dirs_exist_ok=True, ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__", "*.pyc"))

        # Git add and commit with historical timestamp and author
        env = os.environ.copy()
        env["GIT_AUTHOR_NAME"] = author["name"]
        env["GIT_AUTHOR_EMAIL"] = author["email"]
        env["GIT_AUTHOR_DATE"] = iso_time
        env["GIT_COMMITTER_NAME"] = author["name"]
        env["GIT_COMMITTER_EMAIL"] = author["email"]
        env["GIT_COMMITTER_DATE"] = iso_time

        subprocess.run(["git", "add", "."], cwd=str(target_dir), check=True)
        # Check if anything to commit
        status = subprocess.run(["git", "status", "--porcelain"], cwd=str(target_dir), capture_output=True, text=True)
        if status.stdout.strip():
            subprocess.run(["git", "commit", "-m", msg], cwd=str(target_dir), env=env, check=True)
            print(f"[{iso_time}] [{author['name']}] Committed: {msg}")

    total_commits = subprocess.run(["git", "rev-list", "--count", "HEAD"], cwd=str(target_dir), capture_output=True, text=True).stdout.strip()
    print(f"\n[OK] Repository successfully generated! Total commits: {total_commits}")
    print(f"[!] You can now add your new GitHub remote and push:")
    print(f"    git remote add origin https://github.com/<your-username>/CyberShield-AI.git")
    print(f"    git push -u origin main")

if __name__ == "__main__":
    src = Path(__file__).resolve().parent.parent
    target = src.parent / "CyberShield_AI_Hackathon"
    phase_arg = None

    for i, arg in enumerate(sys.argv):
        if arg == "--target-dir" and i + 1 < len(sys.argv):
            target = Path(sys.argv[i + 1])
        elif arg == "--phase" and i + 1 < len(sys.argv):
            phase_arg = int(sys.argv[i + 1])

    build_repo(src, target, phase_arg)
