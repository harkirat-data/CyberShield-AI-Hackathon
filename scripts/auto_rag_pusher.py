"""
auto_rag_pusher.py
Progressively pushes the RAG Knowledge Base and Vector Store to CyberShield-AI-Hackathon main.
5 commits spaced across 15 minutes (~3.5 min apart).
All commits authored by Harkirat Singh <harkiratsingh96kk@gmail.com>.
"""

import os
import sys
import time
import shutil
import tempfile
import subprocess
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HACKATHON_REMOTE_URL = "https://github.com/harkirat-data/CyberShield-AI-Hackathon.git"

AUTHOR = "Harkirat Singh"
EMAIL = "harkiratsingh96kk@gmail.com"

# 5 logical, progressive commits covering the full RAG knowledge base & vector store
COMMIT_BATCHES = [
    {
        "message": "feat(rag): add core RAG configuration, embedding generator, and ChromaDB vector store memory",
        "items": [
            "Ai/rag/core/config.py",
            "Ai/rag/core/embed.py",
            "Ai/rag/core/memory.py",
        ]
    },
    {
        "message": "feat(rag): implement hybrid document retriever and knowledge base chunking engine",
        "items": [
            "Ai/rag/core/retrieve.py",
            "Ai/rag/core/ingest.py",
            "Ai/rag/vectorstore/build_index.py",
        ]
    },
    {
        "message": "feat(rag): add curated Sigma detection rules, Wazuh mappings, and incident response playbooks",
        "items": [
            "Ai/rag/data/knowledge_base/sigma",
            "Ai/rag/data/knowledge_base/wazuh",
            "Ai/rag/data/knowledge_base/remediation",
            "Ai/rag/data/knowledge_base/windows",
            "Ai/rag/data/knowledge_base/linux",
        ]
    },
    {
        "message": "feat(rag): integrate MITRE ATT&CK enterprise dataset and ChromaDB embeddings index",
        "items": [
            "Ai/rag/data/knowledge_base/mitre",
            "Ai/rag/chromadb",
        ]
    },
    {
        "message": "feat(rag): add standalone Streamlit SOC threat analyst investigation portal and MITRE parser",
        "items": [
            "rag_streamlit.py",
            "rag.util/mitre_attack_json_converter.py",
        ]
    },
]


def now_ist_str():
    return datetime.now(IST).strftime("%H:%M:%S IST")


def run(cmd, cwd, env=None):
    result = subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True,
        env=env, encoding="utf-8", errors="replace"
    )
    out = (result.stdout or "").strip()
    err = (result.stderr or "").strip()
    return result.returncode == 0, out, err


def copy_item(src_root, dest_root, rel_path):
    src = os.path.join(src_root, rel_path)
    dest = os.path.join(dest_root, rel_path)
    if not os.path.exists(src):
        return False
    if os.path.isdir(src):
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        if os.path.exists(dest):
            shutil.rmtree(dest, ignore_errors=True)
        shutil.copytree(src, dest, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    else:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(src, dest)
    return True


def main():
    total_commits = len(COMMIT_BATCHES)
    interval_secs = 210  # ~3.5 minutes between commits (total ~14-15 minutes)

    print(f"[{now_ist_str()}] CyberShield AI -- RAG Progressive Pusher")
    print(f"Author  : {AUTHOR} <{EMAIL}>")
    print(f"Commits : {total_commits} batches")
    print(f"Interval: {interval_secs / 60:.1f} minutes")
    print("=" * 65)

    tmpdir = tempfile.mkdtemp(prefix="csa_rag_")
    print(f"[{now_ist_str()}] Cloning main branch...")
    ok, out, err = run(
        ["git", "clone", HACKATHON_REMOTE_URL, tmpdir, "--branch", "main", "--depth", "5"],
        cwd=tempfile.gettempdir()
    )
    if not ok:
        print(f"Clone failed: {err}")
        shutil.rmtree(tmpdir, ignore_errors=True)
        sys.exit(1)
    print(f"[{now_ist_str()}] Clone OK\n")

    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = AUTHOR
    env["GIT_AUTHOR_EMAIL"] = EMAIL
    env["GIT_COMMITTER_NAME"] = AUTHOR
    env["GIT_COMMITTER_EMAIL"] = EMAIL

    try:
        for idx, batch in enumerate(COMMIT_BATCHES, 1):
            msg = batch["message"]
            items = batch["items"]
            print(f"[{now_ist_str()}] ({idx}/{total_commits}) Preparing: {msg}")

            # Always pull rebase before modifying
            run(["git", "pull", "--rebase", "origin", "main"], cwd=tmpdir, env=env)

            # Copy items into the clone
            copied_any = False
            for rel in items:
                if copy_item(REPO_ROOT, tmpdir, rel):
                    copied_any = True
                    run(["git", "add", rel], cwd=tmpdir, env=env)

            if not copied_any:
                print(f"  [WARN] No items found for this batch, skipping.")
                continue

            # Check if there are changes to commit
            ok, out, err = run(["git", "diff", "--staged", "--quiet"], cwd=tmpdir, env=env)
            if ok:
                print(f"  [INFO] No staged changes (already up to date).")
            else:
                # Commit
                ok, out, err = run(["git", "commit", "-m", msg], cwd=tmpdir, env=env)
                if not ok:
                    print(f"  [FAIL] Commit failed: {err[:200]}")
                    continue

                # Push
                ok, out, err = run(["git", "push", "origin", "main"], cwd=tmpdir, env=env)
                if not ok:
                    print(f"  [FAIL] Push failed: {err[:200]}")
                else:
                    print(f"  [SUCCESS] Pushed to origin/main successfully!")

            # Sleep between commits unless it's the last one
            if idx < total_commits:
                next_time = (datetime.now(IST) + timedelta(seconds=interval_secs)).strftime("%H:%M:%S IST")
                print(f"  Sleeping {interval_secs / 60:.1f} min... Next commit at ~{next_time}\n")
                sys.stdout.flush()
                time.sleep(interval_secs)

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    print(f"\n[{now_ist_str()}] All RAG Knowledge Base and Vector Store commits completed under {AUTHOR}.")


if __name__ == "__main__":
    main()
