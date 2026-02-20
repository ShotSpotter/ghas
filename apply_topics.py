#!/usr/bin/env python3
"""Bulk-apply GitHub topics to repos using the gh CLI."""

import argparse
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Result:
    repo: str
    topic: str
    success: bool
    message: str


def check_gh_cli():
    """Make sure gh is installed and authenticated."""
    try:
        subprocess.run(
            ["gh", "auth", "status"],
            capture_output=True,
            check=True,
        )
    except FileNotFoundError:
        print("❌ 'gh' CLI not found. Install it: https://cli.github.com")
        sys.exit(1)
    except subprocess.CalledProcessError:
        print("❌ 'gh' CLI not authenticated. Run: gh auth login")
        sys.exit(1)


def load_config(path: str) -> tuple[list[str], list[str]]:
    """Load topics and repos from JSON file."""
    data = json.loads(Path(path).read_text())

    topics = data["topics"]
    repos = data["repos"]

    if not topics:
        print("❌ No topics defined in config.")
        sys.exit(1)
    if not repos:
        print("❌ No repos defined in config.")
        sys.exit(1)

    return topics, repos


def apply_topic(repo: str, topic: str, dry_run: bool = False) -> Result:
    """Apply a single topic to a single repo via gh CLI."""
    cmd = ["gh", "repo", "edit", repo, "--add-topic", topic]

    if dry_run:
        return Result(repo, topic, True, f"DRY RUN: {' '.join(cmd)}")

    try:
        subprocess.run(cmd, capture_output=True, check=True, text=True)
        return Result(repo, topic, True, "✅ Applied")
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.strip() or e.stdout.strip() or str(e)
        return Result(repo, topic, False, f"❌ {error_msg}")


def print_progress(done: int, total: int, width: int = 40):
    """Inline progress bar."""
    pct = done / total
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    print(f"\r  [{bar}] {done}/{total} ({pct:.0%})", end="", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Bulk-apply topics to GitHub repos")
    parser.add_argument("-f", "--file", default="repos.json", help="Config file path")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Parallel workers")
    parser.add_argument("-n", "--dry-run", action="store_true", help="Preview without applying")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show every result")
    args = parser.parse_args()

    # --- Preflight ---
    if not args.dry_run:
        check_gh_cli()

    topics, repos = load_config(args.file)

    total_ops = len(topics) * len(repos)
    print(f"\n🏷️  Topics:  {', '.join(topics)}")
    print(f"📦 Repos:   {len(repos)}")
    print(f"🔧 Actions: {total_ops} topic applications")
    print(f"⚡ Workers: {args.workers}")
    if args.dry_run:
        print("🧪 MODE:    DRY RUN\n")
    else:
        print()
        confirm = input("Proceed? [y/N]: ").strip().lower()
        if confirm != "y":
            print("Aborted.")
            sys.exit(0)
        print()

    # --- Execute ---
    results: list[Result] = []
    done = 0

    print("  Applying topics...")
    print_progress(0, total_ops)

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(apply_topic, repo, topic, args.dry_run): (repo, topic)
            for repo in repos
            for topic in topics
        }

        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            done += 1
            print_progress(done, total_ops)

    print("\n")

    # --- Report ---
    failures = [r for r in results if not r.success]
    successes = [r for r in results if r.success]

    if args.verbose:
        for r in sorted(results, key=lambda r: (r.repo, r.topic)):
            print(f"  {r.repo:40s} {r.topic:25s} {r.message}")
        print()

    if failures:
        print(f"⚠️  Failures ({len(failures)}):\n")
        for r in sorted(failures, key=lambda r: r.repo):
            print(f"  {r.repo:40s} {r.topic:25s} {r.message}")
        print()

    print(f"✅ {len(successes)}/{total_ops} succeeded")
    if failures:
        print(f"❌ {len(failures)}/{total_ops} failed")
        sys.exit(1)


if __name__ == "__main__":
    main()