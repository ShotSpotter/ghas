#!/usr/bin/env python3
"""
Integration script for the GHAS workflow to automatically check for compromised Axios versions.
This can be called after downloading findings to ensure no compromised versions are present.
"""

import argparse
import json
import sys
from pathlib import Path
from check_axios_versions import AxiosChecker


def integrate_axios_check(findings_dir: str = "findings", output_file: str = None):
    """
    Integrate axios checking with the GHAS workflow.
    
    Args:
        findings_dir: Directory containing SBOM and other findings
        output_file: Optional file to save the report
    """
    
    print("🔍 Running integrated Axios security check...")
    print(f"📁 Scanning findings directory: {findings_dir}")
    print(f"🎯 Looking for compromised versions: 1.14.1, 0.30.4")
    print("-" * 50)
    
    # Create checker instance
    checker = AxiosChecker(verbose=True)
    
    # Scan findings directory
    findings_path = Path(findings_dir)
    if not findings_path.exists():
        print(f"❌ Findings directory not found: {findings_dir}")
        print("💡 Run download_findings.py first to generate SBOM data")
        return 1
    
    # Scan for axios in findings
    results = checker.scan_directory(findings_path)
    
    # Also scan current directory for local package files
    current_dir = Path(".")
    local_results = []
    
    # Look for local JavaScript package files
    for pattern in ["package.json", "package-lock.json", "yarn.lock"]:
        for file_path in current_dir.rglob(pattern):
            if "node_modules" not in str(file_path) and "findings" not in str(file_path):
                if pattern == "package.json":
                    local_results.extend(checker.check_package_json(file_path))
                elif pattern == "package-lock.json":
                    local_results.extend(checker.check_package_lock(file_path))
                elif pattern == "yarn.lock":
                    local_results.extend(checker.check_yarn_lock(file_path))
    
    # Combine results
    all_results = results + local_results
    
    # Generate report
    report = checker.generate_report(all_results)
    print("\n" + report)
    
    # Save report if requested
    if output_file:
        with open(output_file, 'w') as f:
            f.write(report)
        print(f"\n📄 Report saved to: {output_file}")
    
    # Create summary for integration with other tools
    summary = {
        "scan_type": "axios_security_check",
        "findings_scanned": len([r for r in all_results if r.file_type == "SBOM"]),
        "local_files_scanned": len(local_results),
        "total_axios_instances": len(all_results),
        "compromised_instances": len([r for r in all_results if r.is_compromised]),
        "status": "COMPROMISED" if any(r.is_compromised for r in all_results) else "CLEAN"
    }
    
    # Save summary as JSON for CI/CD integration
    summary_file = f"axios_check_summary_{__import__('datetime').datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"📄 Summary saved to: {summary_file}")
    
    # Return appropriate exit code
    return 1 if any(r.is_compromised for r in all_results) else 0


def main():
    parser = argparse.ArgumentParser(
        description="Integrate Axios security check with GHAS workflow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check after downloading findings
  python integrate_axios_check.py
  
  # Specify custom findings directory
  python integrate_axios_check.py -d my_findings/
  
  # Save detailed report
  python integrate_axios_check.py -o axios_security_report.txt
        """
    )
    
    parser.add_argument(
        '-d', '--findings-dir',
        default='findings',
        help='Findings directory to scan (default: findings)'
    )
    parser.add_argument(
        '-o', '--output',
        help='Save detailed report to file'
    )
    
    args = parser.parse_args()
    
    # Run the integrated check
    exit_code = integrate_axios_check(
        findings_dir=args.findings_dir,
        output_file=args.output
    )
    
    sys.exit(exit_code)


if __name__ == '__main__':
    main()