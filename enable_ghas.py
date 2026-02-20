#!/usr/bin/env python3
"""Enable GitHub Advanced Security features on repos using gh CLI."""

import argparse
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path


FEATURES = {
    "advanced_security": {
        "method": "PATCH",
        "endpoint": "/repos/{repo}",
        "body": {"security_and_analysis": {"advanced_security": {"status": "enabled"}}},
        "description": "GHAS license (required for CodeQL & secret scanning)",
    },
    "codeql": {
        "method": "PATCH",
        "endpoint": "/repos/{repo}/code-scanning/default-setup",
        "body": {"state": "configured", "query_suite": "default"},
        "description": "CodeQL code scanning (default setup)",
    },
    "dependabot_alerts": {
        "method": "PUT",
        "endpoint": "/repos/{repo}/vulnerability-alerts",
        "body": None,
        "description": "Dependabot vulnerability alerts",
    },
    "dependabot_updates": {
        "method": "PUT",
        "endpoint": "/repos/{repo}/automated-security-fixes",
        "body": None,
        "description": "Dependabot automated security fixes",
    },
    "secret_scanning": {
        "method": "PATCH",
        "endpoint": "/repos/{repo}",
        "body": {"security_and_analysis": {"secret_scanning": {"status": "enabled"}}},
        "description": "Secret scanning",
    },
    "secret_push_protection": {
        "method": "PATCH",
        "endpoint": "/repos/{repo}",
        "body": {"security_and_analysis": {"secret_scanning_push_protection": {"status": "enabled"}}},
        "description": "Secret scanning push protection",
    },
}

# Order matters — advanced_security must be first
ENABLE_ORDER = [
    "advanced_security",
    "codeql",
    "dependabot_alerts",
    "dependabot_updates",
    "secret_scanning",
    "secret_push_protection",
]

GHAS_DEPENDENT = {"codeql", "secret_scanning", "secret_push_protection"}


@dataclass
class Result:
    repo: str
    feature: str
    success: bool
    message: str


def check_gh_cli():
    try:
        subprocess.run(["gh", "auth", "status"], capture_output=True, check=True)
    except FileNotFoundError:
        print("❌ 'gh' CLI not found. Install it: https://cli.github.com")
        sys.exit(1)
    except subprocess.CalledProcessError:
        print("❌ 'gh' CLI not authenticated. Run: gh auth login")
        sys.exit(1)


def load_repos(path: str) -> list[str]:
    data = json.loads(Path(path).read_text())
    repos = data["repos"]
    if not repos:
        print("❌ No repos defined in config.")
        sys.exit(1)
    return repos


def check_current_status(repo: str) -> dict:
    """Check which features are already enabled on a repo."""
    cmd = ["gh", "api", f"/repos/{repo}", "--method", "GET"]
    proc = subprocess.run(cmd, capture_output=True, text=True)

    if proc.returncode != 0:
        return {}

    data = json.loads(proc.stdout)
    sa = data.get("security_and_analysis", {})

    # Check CodeQL status separately
    codeql_status = False
    cql_cmd = ["gh", "api", f"/repos/{repo}/code-scanning/default-setup", "--method", "GET"]
    cql_proc = subprocess.run(cql_cmd, capture_output=True, text=True)
    if cql_proc.returncode == 0:
        cql_data = json.loads(cql_proc.stdout)
        codeql_status = cql_data.get("state") == "configured"

    return {
        "advanced_security": sa.get("advanced_security", {}).get("status") == "enabled",
        "codeql": codeql_status,
        "secret_scanning": sa.get("secret_scanning", {}).get("status") == "enabled",
        "secret_push_protection": sa.get("secret_scanning_push_protection", {}).get("status") == "enabled",
        "dependabot_alerts": sa.get("dependabot_security_updates", {}).get("status") == "enabled",
    }


def enable_feature(repo: str, feature: str, dry_run: bool = False) -> Result:
    """Enable a single feature on a single repo."""
    config = FEATURES[feature]
    endpoint = config["endpoint"].format(repo=repo)

    cmd = ["gh", "api", endpoint, "--method", config["method"]]

    if config["body"]:
        cmd.extend(["--input", "-"])

    if dry_run:
        return Result(repo, feature, True, f"DRY RUN: {' '.join(cmd)}")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            input=json.dumps(config["body"]) if config["body"] else None,
        )

        if proc.returncode == 0:
            return Result(repo, feature, True, "✅ Enabled")

        error = proc.stderr.strip()

        # Already enabled is fine
        if "already enabled" in error.lower():
            return Result(repo, feature, True, "✅ Already enabled")

        # CodeQL: "configured" state already set
        if "already configured" in error.lower():
            return Result(repo, feature, True, "✅ Already configured")

        return Result(repo, feature, False, f"❌ {error}")

    except Exception as e:
        return Result(repo, feature, False, f"❌ {e}")


def enable_repo(repo: str, features: list[str], dry_run: bool = False) -> list[Result]:
    """Enable features on a repo in order. Stop if advanced_security fails."""
    results = []
    ghas_failed = False

    for feature in features:
        # Skip dependent features if GHAS failed
        if ghas_failed and feature in GHAS_DEPENDENT:
            results.append(Result(repo, feature, False, "⏭️  Skipped (GHAS not enabled)"))
            continue

        result = enable_feature(repo, feature, dry_run)
        results.append(result)

        if feature == "advanced_security" and not result.success:
            ghas_failed = True

    return results


def print_progress(done: int, total: int, width: int = 40):
    pct = done / total
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    print(f"\r  [{bar}] {done}/{total} ({pct:.0%})", end="", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Enable GHAS features on GitHub repos")
    parser.add_argument("-f", "--file", default="repos.json", help="Config file path")
    parser.add_argument("-w", "--workers", type=int, default=3, help="Parallel workers (careful with rate limits)")
    parser.add_argument("-n", "--dry-run", action="store_true", help="Preview without enabling")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show every result")
    parser.add_argument(
        "--features",
        nargs="+",
        choices=FEATURES.keys(),
        default=ENABLE_ORDER,
        help="Features to enable (default: all)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Just check current status, don't enable anything",
    )
    args = parser.parse_args()

    if not args.dry_run:
        check_gh_cli()

    repos = load_repos(args.file)

    # --- Check mode ---
    if args.check:
        print(f"\n🔍 Checking GHAS status for {len(repos)} repos...\n")
        print(f"  {'Repo':42s} {'GHAS':8s} {'CodeQL':8s} {'Secrets':10s} {'Push Prot':10s}")
        print(f"  {'─' * 42} {'─' * 8} {'─' * 8} {'─' * 10} {'─' * 10}")

        for repo in repos:
            status = check_current_status(repo)
            if status:
                ghas = "✅" if status.get("advanced_security") else "❌"
                codeql = "✅" if status.get("codeql") else "❌"
                secrets = "✅" if status.get("secret_scanning") else "❌"
                push = "✅" if status.get("secret_push_protection") else "❌"
                print(f"  {repo:42s} {ghas:8s} {codeql:8s} {secrets:10s} {push:10s}")
            else:
                print(f"  {repo:42s} ⚠️  Could not check")
        return

    # --- Enable mode ---
    # Preserve order based on ENABLE_ORDER
    features = [f for f in ENABLE_ORDER if f in args.features]

    total_ops = len(repos) * len(features)

    print(f"\n📦 Repos:       {len(repos)}")
    print(f"🔧 Features:    {', '.join(features)}")
    print(f"⚡ Workers:     {args.workers}")
    print(f"\n🔓 Features to enable:")
    for f in features:
        print(f"   • {f:30s} — {FEATURES[f]['description']}")

    if args.dry_run:
        print("\n🧪 MODE:        DRY RUN\n")
    else:
        print()
        print("⚠️  WARNING: Enabling GHAS consumes license seats!")
        print("   Each active committer on a repo = 1 seat.\n")
        confirm = input("Type 'enable' to proceed: ").strip().lower()
        if confirm != "enable":
            print("Aborted.")
            sys.exit(0)
        print()

    # --- Execute ---
    all_results: list[Result] = []
    done = 0

    print("  Enabling features...")
    print_progress(0, len(repos))

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(enable_repo, repo, features, args.dry_run): repo
            for repo in repos
        }

        for future in as_completed(futures):
            results = future.result()
            all_results.extend(results)
            done += 1
            print_progress(done, len(repos))

    print("\n")

    # --- Report ---
    successes = [r for r in all_results if r.success]
    failures = [r for r in all_results if not r.success]

    if args.verbose:
        for r in sorted(all_results, key=lambda r: (r.repo, r.feature)):
            print(f"  {r.repo:42s} {r.feature:28s} {r.message}")
        print()

    # Summary by feature
    for f in features:
        f_results = [r for r in all_results if r.feature == f]
        ok = sum(1 for r in f_results if r.success)
        fail = sum(1 for r in f_results if not r.success)
        print(f"  {f:28s}  ✅ {ok}  ❌ {fail}")

    print()

    if failures:
        print(f"⚠️  Failures ({len(failures)}):\n")
        for r in sorted(failures, key=lambda r: (r.feature, r.repo)):
            print(f"  {r.repo:42s} {r.feature:28s} {r.message}")
        print()

    print(f"✅ {len(successes)}/{len(all_results)} succeeded")
    if failures:
        print(f"❌ {len(failures)}/{len(all_results)} failed")


if __name__ == "__main__":
    main()