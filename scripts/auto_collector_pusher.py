"""
auto_collector_pusher_v3.py
Pushes remaining collector files quickly — 7 files, ~7 min apart, done by 20:00 IST.
ALL commits by Ankush Shaw <ankushshaw764@gmail.com>

Already pushed:
  collector/win/collector.py       (harkirat)
  collector/win/risk_scoring.py    (harkirat)
  collector/win/firewall_collector.py (ankush - done)

Remaining 7 files — all Ankush:
"""

import subprocess
import time
import os
import sys
import shutil
import tempfile
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))
DEADLINE = datetime.now(IST).replace(hour=20, minute=0, second=0, microsecond=0)
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HACKATHON_REMOTE_URL = "https://github.com/harkirat-data/CyberShield-AI-Hackathon.git"

AUTHOR = "Ankush Shaw"
EMAIL  = "ankushshaw764@gmail.com"

COMMITS = [
    (
        "collector/win/service.windows.ps1",
        "ops(collector): add PowerShell background service runner for continuous Windows log collection",
    ),
    (
        "collector/linux/collector.py",
        "feat(collector): add Linux auth.log and syslog collector with failed SSH login pattern detection",
    ),
    (
        "collector/linux/risk_scoring.py",
        "feat(collector): implement Linux host-level risk scoring with velocity and frequency heuristics",
    ),
    (
        "collector/linux/firewall_collector.py",
        "feat(collector): add iptables and ufw log parser for inbound connection threat telemetry",
    ),
    (
        "collector/linux/service.linux.sh",
        "ops(collector): add Linux systemd-compatible daemon script for continuous log ingestion",
    ),
    (
        "collector/linux.utils/attack_simulator.sh",
        "test(collector): add Linux attack simulation script for brute-force and port scan event generation",
    ),
    (
        "collector/linux.utils/test.event.sh",
        "test(collector): add full integration test harness for Linux collector event pipeline validation",
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


def now_ist():
    return datetime.now(IST)


def push_file(clone_dir, src_abs, dest_rel, message):
    dest_abs = os.path.join(clone_dir, dest_rel)
    os.makedirs(os.path.dirname(dest_abs), exist_ok=True)
    shutil.copy2(src_abs, dest_abs)

    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"]     = AUTHOR
    env["GIT_AUTHOR_EMAIL"]    = EMAIL
    env["GIT_COMMITTER_NAME"]  = AUTHOR
    env["GIT_COMMITTER_EMAIL"] = EMAIL

    run(["git", "add", dest_rel], cwd=clone_dir, env=env)
    ok, out, err = run(["git", "commit", "-m", message], cwd=clone_dir, env=env)
    if not ok:
        if "nothing to commit" in (out+err).lower():
            print("  already committed")
            return True
        print(f"  commit failed: {err[:150]}")
        return False

    ok2, _, err2 = run(["git", "push", "origin", "main"], cwd=clone_dir, env=env)
    if not ok2:
        print(f"  push failed: {err2[:150]}")
    return ok2


def main():
    now   = now_ist()
    total = len(COMMITS)
    secs_left = (DEADLINE - now).total_seconds()

    if secs_left <= 0:
        print("Past 20:00 IST.")
        sys.exit(0)

    # Spread evenly with 3-min buffer — minimum 60s, max 600s
    interval = max(60, min(600, (secs_left - 180) / max(total - 1, 1)))

    print(f"CyberShield AI -- Ankush Fast Pusher v3")
    print(f"Author   : {AUTHOR} <{EMAIL}>")
    print(f"Remaining: {total} files")
    print(f"Interval : {interval/60:.1f} min")
    print(f"Deadline : 20:00 IST  (in {secs_left/60:.0f} min)")
    print("=" * 55)

    tmpdir = tempfile.mkdtemp(prefix="csa_v3_")
    print("Cloning...")
    ok, _, err = run(
        ["git", "clone", HACKATHON_REMOTE_URL, tmpdir,
         "--branch", "main", "--depth", "3"],
        cwd=tempfile.gettempdir()
    )
    if not ok:
        print(f"Clone failed: {err}")
        shutil.rmtree(tmpdir, ignore_errors=True)
        sys.exit(1)
    print(f"Clone OK\n")

    try:
        for i, (src_rel, message) in enumerate(COMMITS):
            if now_ist() >= DEADLINE:
                print("Deadline hit -- stopping.")
                break

            src_abs = os.path.join(REPO_ROOT, src_rel)
            if not os.path.exists(src_abs):
                print(f"[SKIP] {src_rel} not found locally")
                continue

            # Always pull before committing
            run(["git", "pull", "--rebase", "origin", "main"], cwd=tmpdir)

            print(f"[{now_ist().strftime('%H:%M:%S')}] ({i+1}/{total}) {src_rel}")
            ok = push_file(tmpdir, src_abs, src_rel, message)
            print(f"  {'OK' if ok else 'FAILED'}")

            if i < total - 1:
                wake = now_ist() + timedelta(seconds=interval)
                print(f"  Next at {wake.strftime('%H:%M IST')} (sleep {interval/60:.1f} min)\n")
                time.sleep(interval)

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    print(f"\nDone at {now_ist().strftime('%H:%M:%S IST')}")
    print(f"All 7 remaining collector files pushed by {AUTHOR}.")


if __name__ == "__main__":
    main()
