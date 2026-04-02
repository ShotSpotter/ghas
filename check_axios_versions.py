#!/usr/bin/env python3
"""
Checker script to detect compromised Axios versions (1.14.1 and 0.30.4).
Scans SBOM files, package.json, package-lock.json, and yarn.lock files.
"""

import argparse
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Any, Tuple


# Compromised versions to check for
COMPROMISED_VERSIONS = ["1.14.1", "0.30.4"]


@dataclass
class AxiosCheck:
    """Result of an Axios version check."""
    file_path: str
    file_type: str
    version_found: str
    is_compromised: bool
    source: str  # Where in the file it was found


class AxiosChecker:
    """Main checker class for Axios versions."""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.results: List[AxiosCheck] = []
        
    def log(self, message: str, force: bool = False):
        """Log a message if verbose mode is on."""
        if self.verbose or force:
            print(f"🔍 {message}")
            
    def check_sbom_file(self, file_path: Path) -> List[AxiosCheck]:
        """Check an SBOM JSON file for Axios dependencies."""
        results = []
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            # Extract packages from SBOM structure
            packages = data.get('sbom', {}).get('packages', [])
            
            for package in packages:
                name = package.get('name', '')
                version = package.get('versionInfo', '')
                
                # Look for axios in package name or external refs
                is_axios = False
                source_info = ""
                
                if name.lower() == 'axios':
                    is_axios = True
                    source_info = f"package name: {name}"
                else:
                    # Check external refs for npm packages
                    external_refs = package.get('externalRefs', [])
                    for ref in external_refs:
                        locator = ref.get('referenceLocator', '')
                        if 'pkg:npm/axios@' in locator:
                            is_axios = True
                            source_info = f"purl: {locator}"
                            # Extract version from purl if not in versionInfo
                            if not version:
                                match = re.search(r'pkg:npm/axios@([^/]+)', locator)
                                if match:
                                    version = match.group(1)
                            break
                
                if is_axios and version:
                    is_compromised = version in COMPROMISED_VERSIONS
                    results.append(AxiosCheck(
                        file_path=str(file_path),
                        file_type="SBOM",
                        version_found=version,
                        is_compromised=is_compromised,
                        source=source_info
                    ))
                    
                    if is_compromised:
                        self.log(f"🚨 COMPROMISED AXIOS FOUND in {file_path}: v{version}", force=True)
                    else:
                        self.log(f"✅ Safe Axios version in {file_path}: v{version}")
                        
        except (json.JSONDecodeError, FileNotFoundError, KeyError) as e:
            self.log(f"⚠️  Error reading SBOM {file_path}: {e}")
            
        return results
    
    def check_package_json(self, file_path: Path) -> List[AxiosCheck]:
        """Check a package.json file for Axios dependencies."""
        results = []
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Check both dependencies and devDependencies
            for dep_type in ['dependencies', 'devDependencies', 'peerDependencies']:
                deps = data.get(dep_type, {})
                if 'axios' in deps:
                    version_spec = deps['axios']
                    # Clean version spec (remove ^, ~, etc.)
                    clean_version = re.sub(r'[^\d.]', '', version_spec)
                    
                    is_compromised = clean_version in COMPROMISED_VERSIONS
                    results.append(AxiosCheck(
                        file_path=str(file_path),
                        file_type="package.json",
                        version_found=version_spec,
                        is_compromised=is_compromised,
                        source=f"{dep_type}"
                    ))
                    
                    if is_compromised:
                        self.log(f"🚨 COMPROMISED AXIOS FOUND in {file_path}: {version_spec} ({dep_type})", force=True)
                    else:
                        self.log(f"✅ Axios dependency in {file_path}: {version_spec} ({dep_type})")
                        
        except (json.JSONDecodeError, FileNotFoundError) as e:
            self.log(f"⚠️  Error reading package.json {file_path}: {e}")
            
        return results
    
    def check_package_lock(self, file_path: Path) -> List[AxiosCheck]:
        """Check a package-lock.json file for Axios dependencies."""
        results = []
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Check both lockfileVersion 1 and 2+ formats
            if 'dependencies' in data:
                # Lockfile v1 format
                deps = data.get('dependencies', {})
                if 'axios' in deps:
                    version = deps['axios'].get('version', '')
                    is_compromised = version in COMPROMISED_VERSIONS
                    results.append(AxiosCheck(
                        file_path=str(file_path),
                        file_type="package-lock.json",
                        version_found=version,
                        is_compromised=is_compromised,
                        source="dependencies"
                    ))
            
            if 'packages' in data:
                # Lockfile v2+ format
                packages = data.get('packages', {})
                for package_path, package_info in packages.items():
                    if package_path.endswith('/axios') or package_path == 'node_modules/axios':
                        version = package_info.get('version', '')
                        is_compromised = version in COMPROMISED_VERSIONS
                        results.append(AxiosCheck(
                            file_path=str(file_path),
                            file_type="package-lock.json",
                            version_found=version,
                            is_compromised=is_compromised,
                            source=f"packages[{package_path}]"
                        ))
                        
            for result in results:
                if result.is_compromised:
                    self.log(f"🚨 COMPROMISED AXIOS FOUND in {file_path}: v{result.version_found}", force=True)
                else:
                    self.log(f"✅ Axios lockfile entry in {file_path}: v{result.version_found}")
                    
        except (json.JSONDecodeError, FileNotFoundError) as e:
            self.log(f"⚠️  Error reading package-lock.json {file_path}: {e}")
            
        return results
    
    def check_yarn_lock(self, file_path: Path) -> List[AxiosCheck]:
        """Check a yarn.lock file for Axios dependencies."""
        results = []
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Parse yarn.lock format (simplified)
            axios_pattern = r'axios@[^:]*:\s*version\s+"([^"]+)"'
            matches = re.finditer(axios_pattern, content, re.MULTILINE)
            
            for match in matches:
                version = match.group(1)
                is_compromised = version in COMPROMISED_VERSIONS
                results.append(AxiosCheck(
                    file_path=str(file_path),
                    file_type="yarn.lock",
                    version_found=version,
                    is_compromised=is_compromised,
                    source="lock entry"
                ))
                
                if is_compromised:
                    self.log(f"🚨 COMPROMISED AXIOS FOUND in {file_path}: v{version}", force=True)
                else:
                    self.log(f"✅ Axios yarn.lock entry in {file_path}: v{version}")
                    
        except FileNotFoundError as e:
            self.log(f"⚠️  Error reading yarn.lock {file_path}: {e}")
            
        return results
    
    def scan_directory(self, directory: Path) -> List[AxiosCheck]:
        """Recursively scan a directory for relevant files."""
        results = []
        
        # File patterns to look for
        file_patterns = [
            ('**/*sbom*.json', self.check_sbom_file),
            ('**/package.json', self.check_package_json),
            ('**/package-lock.json', self.check_package_lock),
            ('**/yarn.lock', self.check_yarn_lock),
        ]
        
        for pattern, checker_func in file_patterns:
            for file_path in directory.glob(pattern):
                if file_path.is_file():
                    self.log(f"Checking {file_path}")
                    file_results = checker_func(file_path)
                    results.extend(file_results)
                    
        return results
    
    def scan_files(self, file_paths: List[str]) -> List[AxiosCheck]:
        """Scan specific files."""
        results = []
        
        for file_path_str in file_paths:
            file_path = Path(file_path_str)
            if not file_path.exists():
                self.log(f"⚠️  File not found: {file_path}")
                continue
                
            self.log(f"Checking {file_path}")
            
            # Determine file type and use appropriate checker
            if 'sbom' in file_path.name.lower() and file_path.suffix == '.json':
                file_results = self.check_sbom_file(file_path)
            elif file_path.name == 'package.json':
                file_results = self.check_package_json(file_path)
            elif file_path.name == 'package-lock.json':
                file_results = self.check_package_lock(file_path)
            elif file_path.name == 'yarn.lock':
                file_results = self.check_yarn_lock(file_path)
            else:
                self.log(f"⚠️  Unknown file type: {file_path}")
                continue
                
            results.extend(file_results)
            
        return results
    
    def generate_report(self, results: List[AxiosCheck]) -> str:
        """Generate a summary report of findings."""
        compromised_count = sum(1 for r in results if r.is_compromised)
        safe_count = len(results) - compromised_count
        
        report = []
        report.append("=" * 60)
        report.append("🔍 AXIOS VERSION SECURITY CHECK REPORT")
        report.append("=" * 60)
        report.append(f"📊 Total Axios instances found: {len(results)}")
        report.append(f"🚨 Compromised versions: {compromised_count}")
        report.append(f"✅ Safe versions: {safe_count}")
        report.append("")
        
        if compromised_count > 0:
            report.append("🚨 COMPROMISED AXIOS VERSIONS FOUND:")
            report.append("-" * 40)
            for result in results:
                if result.is_compromised:
                    report.append(f"  File: {result.file_path}")
                    report.append(f"  Type: {result.file_type}")
                    report.append(f"  Version: {result.version_found}")
                    report.append(f"  Source: {result.source}")
                    report.append("")
        else:
            report.append("✅ No compromised Axios versions detected!")
            
        if safe_count > 0:
            report.append("✅ SAFE AXIOS VERSIONS:")
            report.append("-" * 25)
            for result in results:
                if not result.is_compromised:
                    report.append(f"  {result.file_path}: v{result.version_found} ({result.file_type})")
            report.append("")
            
        report.append("ℹ️  Compromised versions checked: " + ", ".join(COMPROMISED_VERSIONS))
        report.append("ℹ️  Reference: https://security.snyk.io/vuln/SNYK-JS-AXIOS-7361793")
        
        return "\n".join(report)


def main():
    parser = argparse.ArgumentParser(
        description="Check for compromised Axios versions (1.14.1 and 0.30.4)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check current directory recursively
  python check_axios_versions.py

  # Check findings directory
  python check_axios_versions.py -d findings/

  # Check specific files
  python check_axios_versions.py -f package.json package-lock.json

  # Verbose output
  python check_axios_versions.py -v

  # Save report to file
  python check_axios_versions.py --output axios_check_report.txt
        """
    )
    
    parser.add_argument(
        '-d', '--directory', 
        type=str, 
        default='.',
        help='Directory to scan recursively (default: current directory)'
    )
    parser.add_argument(
        '-f', '--files',
        nargs='+',
        help='Specific files to check'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    parser.add_argument(
        '--output', '-o',
        type=str,
        help='Save report to file'
    )
    parser.add_argument(
        '--json-output',
        type=str,
        help='Save detailed results as JSON'
    )
    
    args = parser.parse_args()
    
    checker = AxiosChecker(verbose=args.verbose)
    
    # Perform the scan
    if args.files:
        results = checker.scan_files(args.files)
    else:
        directory = Path(args.directory)
        if not directory.exists():
            print(f"❌ Directory not found: {directory}")
            sys.exit(1)
        results = checker.scan_directory(directory)
    
    # Generate and display report
    report = checker.generate_report(results)
    print(report)
    
    # Save outputs if requested
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"📄 Report saved to: {args.output}")
        
    if args.json_output:
        json_data = {
            'scan_timestamp': __import__('datetime').datetime.now().isoformat(),
            'compromised_versions_checked': COMPROMISED_VERSIONS,
            'summary': {
                'total_found': len(results),
                'compromised': sum(1 for r in results if r.is_compromised),
                'safe': sum(1 for r in results if not r.is_compromised)
            },
            'results': [
                {
                    'file_path': r.file_path,
                    'file_type': r.file_type,
                    'version_found': r.version_found,
                    'is_compromised': r.is_compromised,
                    'source': r.source
                }
                for r in results
            ]
        }
        
        with open(args.json_output, 'w') as f:
            json.dump(json_data, f, indent=2)
        print(f"📄 JSON results saved to: {args.json_output}")
    
    # Exit with error code if compromised versions found
    compromised_found = any(r.is_compromised for r in results)
    if compromised_found:
        print("\n❌ SECURITY ALERT: Compromised Axios versions detected!")
        sys.exit(1)
    else:
        print("\n✅ No compromised Axios versions found.")
        sys.exit(0)


if __name__ == '__main__':
    main()