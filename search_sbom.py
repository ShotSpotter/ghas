#!/usr/bin/env python3
"""Search SBOM files for a package."""

import argparse
import json
import re
import sys
from pathlib import Path


def search(findings_dir: str, pattern: str, exact: bool = False):
    sbom_files = sorted(Path(findings_dir).glob("*_sbom_*.json"))

    if not sbom_files:
        print(f"❌ No SBOM files found in {findings_dir}")
        sys.exit(1)

    regex = re.compile(
        rf"^{re.escape(pattern)}$" if exact else re.escape(pattern),
        re.IGNORECASE,
    )

    results = []

    for filepath in sbom_files:
        repo = filepath.stem.split("_sbom_")[0].replace("_", "/", 1)
        data = json.loads(filepath.read_text())
        packages = data.get("sbom", {}).get("packages", [])

        for pkg in packages:
            name = pkg.get("name", "")
            version = pkg.get("versionInfo", "unknown")

            if regex.search(name):
                results.append({
                    "repo": repo,
                    "package": name,
                    "version": version,
                })

    if not results:
        print(f"No matches for '{pattern}'")
        return

    # Print results
    print(f"\n🔍 Found {len(results)} matches for '{pattern}':\n")
    print(f"  {'Repo':42s} {'Package':50s} {'Version'}")
    print(f"  {'─' * 42} {'─' * 50} {'─' * 15}")

    for r in sorted(results, key=lambda r: (r["package"], r["version"], r["repo"])):
        print(f"  {r['repo']:42s} {r['package']:50s} {r['version']}")

    # Unique version summary
    versions = {}
    for r in results:
        key = r["package"]
        versions.setdefault(key, set()).add(r["version"])

    print(f"\n📦 Version Summary:\n")
    for pkg, vers in sorted(versions.items()):
        print(f"  {pkg}")
        for v in sorted(vers):
            count = sum(1 for r in results if r["package"] == pkg and r["version"] == v)
            print(f"    {v:30s} ({count} repos)")


def main():
    parser = argparse.ArgumentParser(description="Search SBOM files for a package")
    parser.add_argument("package", help="Package name to search for (substring match)")
    parser.add_argument("-d", "--dir", default="findings", help="Findings directory")
    parser.add_argument("-e", "--exact", action="store_true", help="Exact name match")
    args = parser.parse_args()

    search(args.dir, args.package, args.exact)


if __name__ == "__main__":
    main()