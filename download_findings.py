#!/usr/bin/env python3
"""Download SBOM, Dependabot alerts, and CodeQL findings for repos using gh CLI."""

import argparse
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")

CONTENT_TYPES = {
    "sbom": "/repos/{repo}/dependency-graph/sbom",
    "dependabot": "/repos/{repo}/dependabot/alerts?per_page=100&state=open",
    "codeql": "/repos/{repo}/code-scanning/alerts?per_page=100&state=open",
}


@dataclass
class Result:
    repo: str
    content_type: str
    success: bool
    message: str
    filepath: str = ""


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


def load_repos(path: str) -> list[str]:
    """Load repos from JSON file."""
    data = json.loads(Path(path).read_text())
    repos = data["repos"]
    if not repos:
        print("❌ No repos defined in config.")
        sys.exit(1)
    return repos


def paginate_api(endpoint: str) -> list:
    """Fetch all pages from a paginated GitHub API endpoint."""
    results = []
    page = 1

    while True:
        separator = "&" if "?" in endpoint else "?"
        paged = f"{endpoint}{separator}page={page}"

        cmd = ["gh", "api", paged, "--method", "GET"]
        proc = subprocess.run(cmd, capture_output=True, text=True)

        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip())

        data = json.loads(proc.stdout)

        # SBOM returns an object, not a list — no pagination needed
        if isinstance(data, dict):
            return data

        if not data:
            break

        results.extend(data)
        if len(data) < 100:
            break
        page += 1

    return results


def safe_filename(repo: str) -> str:
    """Convert 'org/repo' to 'org_repo'."""
    return repo.replace("/", "_")


def download(repo: str, content_type: str, output_dir: Path, dry_run: bool = False) -> Result:
    """Download one content type for one repo."""
    endpoint = CONTENT_TYPES[content_type].format(repo=repo)
    filename = f"{safe_filename(repo)}_{content_type}_{TIMESTAMP}.json"
    filepath = output_dir / filename

    if dry_run:
        return Result(repo, content_type, True, f"DRY RUN: gh api {endpoint}", str(filepath))

    try:
        data = paginate_api(endpoint)

        # Write the file
        filepath.write_text(json.dumps(data, indent=2))

        # Summary info
        if content_type == "sbom":
            count = len(data.get("sbom", {}).get("packages", []))
            msg = f"✅ {count} packages"
        else:
            count = len(data) if isinstance(data, list) else 0
            msg = f"✅ {count} alerts"

        return Result(repo, content_type, True, msg, str(filepath))

    except RuntimeError as e:
        error = str(e)
        # Common: CodeQL not enabled, Dependabot not enabled
        if "404" in error or "not enabled" in error.lower():
            return Result(repo, content_type, False, f"⚠️  Not enabled or no access")
        return Result(repo, content_type, False, f"❌ {error}")
    except Exception as e:
        return Result(repo, content_type, False, f"❌ {e}")


def print_progress(done: int, total: int, width: int = 40):
    """Inline progress bar."""
    pct = done / total
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    print(f"\r  [{bar}] {done}/{total} ({pct:.0%})", end="", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Download SBOM, Dependabot & CodeQL data from GitHub repos")
    parser.add_argument("-f", "--file", default="repos.json", help="Config file path")
    parser.add_argument("-o", "--output", default="findings", help="Output directory")
    parser.add_argument("-w", "--workers", type=int, default=5, help="Parallel workers (be gentle on the API)")
    parser.add_argument("-n", "--dry-run", action="store_true", help="Preview without downloading")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show every result")
    parser.add_argument(
        "-t", "--types",
        nargs="+",
        choices=CONTENT_TYPES.keys(),
        default=list(CONTENT_TYPES.keys()),
        help="Content types to download (default: all)",
    )
    args = parser.parse_args()

    # --- Preflight ---
    if not args.dry_run:
        check_gh_cli()

    repos = load_repos(args.file)
    output_dir = Path(args.output)

    total_ops = len(repos) * len(args.types)

    print(f"\n📦 Repos:       {len(repos)}")
    print(f"📄 Types:       {', '.join(args.types)}")
    print(f"🔧 Downloads:   {total_ops}")
    print(f"⚡ Workers:     {args.workers}")
    print(f"📁 Output:      {output_dir.resolve()}")
    print(f"🕐 Timestamp:   {TIMESTAMP}")

    if args.dry_run:
        print("🧪 MODE:        DRY RUN\n")
    else:
        print()
        confirm = input("Proceed? [y/N]: ").strip().lower()
        if confirm != "y":
            print("Aborted.")
            sys.exit(0)
        print()
        output_dir.mkdir(parents=True, exist_ok=True)

    # --- Execute ---
    results: list[Result] = []
    done = 0

    print("  Downloading...")
    print_progress(0, total_ops)

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(download, repo, ctype, output_dir, args.dry_run): (repo, ctype)
            for repo in repos
            for ctype in args.types
        }

        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            done += 1
            print_progress(done, total_ops)

    print("\n")

    # --- Report ---
    successes = [r for r in results if r.success]
    failures = [r for r in results if not r.success]

    if args.verbose:
        for r in sorted(results, key=lambda r: (r.repo, r.content_type)):
            print(f"  {r.repo:40s} {r.content_type:12s} {r.message}")
        print()

    # Summary by content type
    for ctype in args.types:
        type_results = [r for r in results if r.content_type == ctype]
        ok = sum(1 for r in type_results if r.success)
        fail = sum(1 for r in type_results if not r.success)
        print(f"  {ctype:12s}  ✅ {ok}  ❌ {fail}")

    print()

    if failures:
        print(f"⚠️  Failures ({len(failures)}):\n")
        for r in sorted(failures, key=lambda r: (r.content_type, r.repo)):
            print(f"  {r.repo:40s} {r.content_type:12s} {r.message}")
        print()

    print(f"✅ {len(successes)}/{total_ops} succeeded")
    if failures:
        print(f"❌ {len(failures)}/{total_ops} failed")

    if successes and not args.dry_run:
        print(f"\n📁 Files saved to: {output_dir.resolve()}")


if __name__ == "__main__":
    main()