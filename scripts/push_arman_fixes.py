"""
push_arman_fixes.py
Pushes today's 3 high-priority honeypot and dashboard fixes to CyberShield-AI-Hackathon main.
All commits authored by Shaikh Arman <shaikharmanmukhtar125@gmail.com>.
"""

import subprocess
import os
import sys
import shutil
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HACKATHON_REMOTE_URL = "https://github.com/harkirat-data/CyberShield-AI-Hackathon.git"

AUTHOR = "Shaikh Arman"
EMAIL = "shaikharmanmukhtar125@gmail.com"

COMMITS = [
    (
        "honeypot/runtime.py",
        "fix(honeypot): add dynamic MySQL 33061 fallback and live socket-accurate session counting",
    ),
    (
        "honeypot/store.py",
        "fix(store): auto-close orphaned active sessions on telemetry store initialization",
    ),
    (
        "dashboard/app.js",
        "fix(dashboard): synchronize grid start/pause controls, active model status, and live sensor telemetry",
    ),
]


def run(cmd, cwd, env=None):
    result = subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True,
        env=env, encoding="utf-8", errors="replace"
    )
    out = (result.stdout or "").strip()
    err = (result.stderr or "").strip()
    return result.returncode == 0, out, err


def main():
    print(f"VALENS.AI -- Pushing High-Priority Fixes")
    print(f"Author: {AUTHOR} <{EMAIL}>")
    print("=" * 60)

    tmpdir = tempfile.mkdtemp(prefix="csa_arman_")
    print(f"Cloning {HACKATHON_REMOTE_URL} (main)...")
    ok, out, err = run(
        ["git", "clone", HACKATHON_REMOTE_URL, tmpdir, "--branch", "main", "--depth", "5"],
        cwd=tempfile.gettempdir()
    )
    if not ok:
        print(f"Clone failed: {err}")
        shutil.rmtree(tmpdir, ignore_errors=True)
        sys.exit(1)
    print("Clone OK\n")

    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = AUTHOR
    env["GIT_AUTHOR_EMAIL"] = EMAIL
    env["GIT_COMMITTER_NAME"] = AUTHOR
    env["GIT_COMMITTER_EMAIL"] = EMAIL

    try:
        for idx, (rel_path, message) in enumerate(COMMITS, 1):
            src_abs = os.path.join(REPO_ROOT, rel_path)
            dest_abs = os.path.join(tmpdir, rel_path)
            if not os.path.exists(src_abs):
                print(f"[{idx}/3] ERROR: Source file not found: {rel_path}")
                continue

            # Copy file
            os.makedirs(os.path.dirname(dest_abs), exist_ok=True)
            shutil.copy2(src_abs, dest_abs)

            # Git add
            ok, out, err = run(["git", "add", rel_path], cwd=tmpdir, env=env)
            if not ok:
                print(f"[{idx}/3] git add failed: {err}")
                continue

            # Check if changes exist
            ok, out, err = run(["git", "diff", "--staged", "--quiet"], cwd=tmpdir, env=env)
            if ok:
                print(f"[{idx}/3] {rel_path}: No changes to commit.")
                continue

            # Commit
            ok, out, err = run(["git", "commit", "-m", message], cwd=tmpdir, env=env)
            if not ok:
                print(f"[{idx}/3] Commit failed: {err}")
                continue
            print(f"[{idx}/3] Committed: {message}")

            # Push
            ok, out, err = run(["git", "push", "origin", "main"], cwd=tmpdir, env=env)
            if not ok:
                print(f"[{idx}/3] Push failed: {err}")
            else:
                print(f"      Pushed successfully to origin/main!")

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    print("\nAll fixes pushed under Shaikh Arman.")


if __name__ == "__main__":
    main()
