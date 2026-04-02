#!/usr/bin/env python3
"""Search for LangFlow usage across all repositories and check for CVE-2025-3248 vulnerability."""

import argparse
import json
import re
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Set

try:
    import packaging.version as version_utils
    VERSION_PARSING_AVAILABLE = True
except ImportError:
    VERSION_PARSING_AVAILABLE = False
    print("⚠️  Note: 'packaging' library not found. Install with: pip install packaging")
    print("   Version comparison will use simplified string comparison.")
    print()


@dataclass
class LangFlowFinding:
    repo: str
    source: str  # 'sbom', 'dependabot', 'codeql'
    package: str
    version: str
    vulnerable: bool = False
    cve_details: str = ""


# LangFlow Code Injection Vulnerability Information
LANGFLOW_VULNERABILITY = {
    "id": "Code Injection in /api/v1/validate/code",
    "affected_packages": [
        "langflow",
        "langflow-base",
        "langflow-ui",
        "langflow-backend", 
        "python-langflow"
    ],
    "vulnerable_versions": [
        "< 1.3.0",  # All versions before 1.3.0 are vulnerable
    ],
    "description": "Code injection in /api/v1/validate/code endpoint allows remote unauthenticated arbitrary code execution",
    "severity": "CRITICAL",
    "endpoint": "/api/v1/validate/code",
    "authentication_required": False
}


def is_langflow_package(package_name: str) -> bool:
    """Check if a package name is related to LangFlow."""
    langflow_patterns = [
        "langflow",
        "langflow-base",
        "langflow-ui", 
        "langflow-backend",
        "python-langflow",
        "langflow-core",
        "langflow-api"
    ]
    
    package_lower = package_name.lower()
    return any(pattern in package_lower for pattern in langflow_patterns)


def simple_version_compare(version_str: str, comparison: str, target_version: str) -> bool:
    """Simple version comparison when packaging library is not available."""
    try:
        # Convert version strings to comparable tuples
        def version_tuple(v):
            return tuple(map(int, (v.split("."))))
        
        v1 = version_tuple(version_str)
        v2 = version_tuple(target_version)
        
        if comparison == "<":
            return v1 < v2
        elif comparison == "<=":
            return v1 <= v2
        elif comparison == ">=":
            return v1 >= v2
        elif comparison == ">":
            return v1 > v2
        
    except (ValueError, AttributeError):
        # If parsing fails, assume potentially vulnerable
        return True
    
    return False


def is_vulnerable_version(package_name: str, version_str: str) -> tuple[bool, str]:
    """Check if a package version is vulnerable to the code injection vulnerability."""
    if not any(pkg in package_name.lower() for pkg in LANGFLOW_VULNERABILITY["affected_packages"]):
        return False, ""
    
    if version_str in ["unknown", "", "latest", "main", "dev"]:
        return True, "Unknown version - potentially vulnerable"
    
    try:
        if VERSION_PARSING_AVAILABLE:
            pkg_version = version_utils.parse(version_str)
            
            # Check against the vulnerable version ranges
            for vuln_range in LANGFLOW_VULNERABILITY["vulnerable_versions"]:
                if "< " in vuln_range and not ">=" in vuln_range:
                    # Simple less than check, e.g., "< 1.0.19"
                    max_version = version_utils.parse(vuln_range.replace("< ", ""))
                    if pkg_version < max_version:
                        return True, f"Vulnerable: {version_str} < {max_version}"
                
                elif ">=" in vuln_range and "< " in vuln_range:
                    # Range check, e.g., ">= 1.1.0, < 1.1.8"
                    parts = vuln_range.split(", ")
                    min_version = version_utils.parse(parts[0].replace(">= ", ""))
                    max_version = version_utils.parse(parts[1].replace("< ", ""))
                    
                    if min_version <= pkg_version < max_version:
                        return True, f"Vulnerable: {min_version} <= {version_str} < {max_version}"
        else:
            # Use simple version comparison when packaging is not available
            for vuln_range in LANGFLOW_VULNERABILITY["vulnerable_versions"]:
                if "< " in vuln_range and not ">=" in vuln_range:
                    # Simple less than check, e.g., "< 1.0.19"
                    max_version = vuln_range.replace("< ", "").strip()
                    if simple_version_compare(version_str, "<", max_version):
                        return True, f"Vulnerable: {version_str} < {max_version}"
                
                elif ">=" in vuln_range and "< " in vuln_range:
                    # Range check, e.g., ">= 1.1.0, < 1.1.8"
                    parts = vuln_range.split(", ")
                    min_version = parts[0].replace(">= ", "").strip()
                    max_version = parts[1].replace("< ", "").strip()
                    
                    if (simple_version_compare(version_str, ">=", min_version) and 
                        simple_version_compare(version_str, "<", max_version)):
                        return True, f"Vulnerable: {min_version} <= {version_str} < {max_version}"
        
        return False, f"Safe: {version_str} not in vulnerable ranges"
        
    except Exception:
        # If version parsing fails, assume potentially vulnerable
        return True, f"Warning: Cannot parse version '{version_str}' - potentially vulnerable"


def search_sbom_files(findings_dir: Path) -> List[LangFlowFinding]:
    """Search SBOM files for LangFlow packages."""
    findings = []
    sbom_files = sorted(findings_dir.glob("*_sbom_*.json"))
    
    for filepath in sbom_files:
        try:
            repo = filepath.stem.split("_sbom_")[0].replace("_", "/", 1)
            data = json.loads(filepath.read_text())
            packages = data.get("sbom", {}).get("packages", [])
            
            for pkg in packages:
                name = pkg.get("name", "")
                version_str = pkg.get("versionInfo", "unknown")
                
                if is_langflow_package(name):
                    vulnerable, cve_details = is_vulnerable_version(name, version_str)
                    
                    findings.append(LangFlowFinding(
                        repo=repo,
                        source="sbom",
                        package=name,
                        version=version_str,
                        vulnerable=vulnerable,
                        cve_details=cve_details
                    ))
                    
        except Exception as e:
            print(f"⚠️  Error processing {filepath.name}: {e}")
    
    return findings


def search_dependabot_files(findings_dir: Path) -> List[LangFlowFinding]:
    """Search Dependabot files for LangFlow vulnerabilities."""
    findings = []
    dependabot_files = sorted(findings_dir.glob("*_dependabot_*.json"))
    
    for filepath in dependabot_files:
        try:
            repo = filepath.stem.split("_dependabot_")[0].replace("_", "/", 1)
            data = json.loads(filepath.read_text())
            alerts = data if isinstance(data, list) else []
            
            for alert in alerts:
                package_info = alert.get("dependency", {}).get("package", {})
                package_name = package_info.get("name", "")
                version_str = package_info.get("version", "unknown")
                
                if is_langflow_package(package_name):
                    # Check if this is the specific LangFlow vulnerability
                    advisory = alert.get("security_advisory", {})
                    cve_id = advisory.get("cve_id", "")
                    summary = advisory.get("summary", "")
                    
                    vulnerable = True  # Dependabot alerts are by definition vulnerabilities
                    cve_details = f"Dependabot alert: {advisory.get('summary', 'Security advisory')}"
                    
                    # Check if this matches the known LangFlow code injection vulnerability
                    if "validate/code" in summary or "code injection" in summary.lower():
                        cve_details = f"🚨 {LANGFLOW_VULNERABILITY['id']} - {LANGFLOW_VULNERABILITY['description']}"
                    
                    findings.append(LangFlowFinding(
                        repo=repo,
                        source="dependabot",
                        package=package_name,
                        version=version_str,
                        vulnerable=vulnerable,
                        cve_details=cve_details
                    ))
                    
        except Exception as e:
            print(f"⚠️  Error processing {filepath.name}: {e}")
    
    return findings


def search_codeql_files(findings_dir: Path) -> List[LangFlowFinding]:
    """Search CodeQL files for potential LangFlow-related security issues and code patterns."""
    findings = []
    codeql_files = sorted(findings_dir.glob("*_codeql_*.json"))
    
    # Enhanced patterns for detecting LangFlow usage - more specific to reduce false positives
    langflow_code_patterns = [
        "langflow", "LangFlow", "LANGFLOW",
        "from langflow import", "import langflow",
        "/api/v1/validate/code",  # The vulnerable endpoint
        "validate/code", "langflow_api", "langflowai",
        "FlowController", "BaseFlow", "LangFlowNode",
        "langflow.interface", "langflow.graph", "langflow.components",
        "langflow_component", "FlowRunner"
    ]
    
    # File path patterns that might indicate LangFlow - made more specific
    langflow_file_patterns = [
        "langflow/", "/langflow/", "langflow.py",
        "/flows/", "flow_config", "langflow.json",
        "validate_code.py", "/api/v1/validate/code"
    ]
    
    for filepath in codeql_files:
        try:
            repo = filepath.stem.split("_codeql_")[0].replace("_", "/", 1)
            data = json.loads(filepath.read_text())
            alerts = data if isinstance(data, list) else []
            
            for alert in alerts:
                # Look for LangFlow-related patterns in CodeQL findings
                rule = alert.get("rule", {})
                rule_name = rule.get("name", "").lower()
                rule_id = rule.get("id", "").lower() 
                description = rule.get("description", "").lower()
                
                location = alert.get("most_recent_instance", {}).get("location", {})
                file_path = location.get("path", "").lower()
                
                # Check message content for LangFlow patterns
                message_text = alert.get("most_recent_instance", {}).get("message", {}).get("text", "").lower()
                
                # Enhanced detection logic
                langflow_indicators = []
                
                # Check for LangFlow code patterns
                for pattern in langflow_code_patterns:
                    pattern_lower = pattern.lower()
                    if (pattern_lower in rule_name or 
                        pattern_lower in description or 
                        pattern_lower in message_text or
                        pattern_lower in rule_id):
                        langflow_indicators.append(f"Code pattern: {pattern}")
                
                # Check for LangFlow file patterns  
                for pattern in langflow_file_patterns:
                    if pattern in file_path:
                        langflow_indicators.append(f"File path: {pattern}")
                
                # Check for the specific vulnerable endpoint
                if "validate/code" in file_path or "validate/code" in message_text:
                    langflow_indicators.append("🚨 Vulnerable endpoint detected")
                
                if langflow_indicators:
                    severity = rule.get("severity", "unknown")
                    is_critical = severity.lower() in ["critical", "error"] or "validate/code" in str(langflow_indicators)
                    
                    findings.append(LangFlowFinding(
                        repo=repo,
                        source="codeql",
                        package=f"Code analysis: {rule_name[:50]}...",
                        version="N/A", 
                        vulnerable=is_critical,
                        cve_details=f"CodeQL finding: {'; '.join(langflow_indicators[:3])} | {description[:100]}..."
                    ))
                    
        except Exception as e:
            print(f"⚠️  Error processing {filepath.name}: {e}")
    
    return findings


def search_for_manual_langflow(findings_dir: Path) -> List[LangFlowFinding]:
    """Search for indicators of manual LangFlow installations and usage."""
    findings = []
    
    # Get all JSON files to search through for manual indicators
    all_json_files = list(findings_dir.glob("*.json"))
    
    # Manual installation indicators
    manual_indicators = {
        "git_submodules": [
            "langflow", "LangFlow", "langflow.git",
            "github.com/logspace-ai/langflow"
        ],
        "docker_containers": [
            "langflow", "langflowai", "langflow:latest",
            "custom/langflow", "local/langflow"
        ],
        "file_paths": [
            "langflow/", "/langflow/", "langflow-main/",
            "LangFlow/", "langflow-master/", "langflow-dev/",
            "vendor/langflow", "third_party/langflow",
            "external/langflow", "deps/langflow"
        ],
        "config_files": [
            "langflow.json", "langflow.yaml", "langflow.yml",
            "langflow_config", "flow_config.json",
            ".langflow", "langflow.toml"
        ],
        "environment_vars": [
            "LANGFLOW_", "langflow_", "LANGFLOW_API",
            "LANGFLOW_HOST", "LANGFLOW_PORT", "LANGFLOW_SECRET"
        ],
        "api_endpoints": [
            "/api/v1/validate/code", "/langflow/api",
            ":7860", ":8000/langflow", "langflow.local"
        ],
        "python_imports": [
            "from langflow import", "import langflow",
            "langflow.interface", "langflow.graph", 
            "langflow.components", "langflow.custom"
        ]
    }
    
    repo_findings = {}  # Track findings per repo to avoid duplicates
    
    # Search through all finding files for manual indicators
    for json_file in all_json_files:
        try:
            # Extract repo name from filename
            filename = json_file.stem
            if "_sbom_" in filename:
                repo = filename.split("_sbom_")[0].replace("_", "/", 1)
            elif "_dependabot_" in filename:
                repo = filename.split("_dependabot_")[0].replace("_", "/", 1) 
            elif "_codeql_" in filename:
                repo = filename.split("_codeql_")[0].replace("_", "/", 1)
            else:
                continue
                
            # Read file content as text to search for patterns
            content = json_file.read_text().lower()
            
            repo_indicators = []
            
            # Check for various manual installation indicators
            for category, patterns in manual_indicators.items():
                for pattern in patterns:
                    if pattern.lower() in content:
                        indicator_detail = f"{category}: {pattern}"
                        if indicator_detail not in repo_indicators:
                            repo_indicators.append(indicator_detail)
                            
                            # Determine if this is a high-risk indicator
                            is_vulnerable = (
                                "validate/code" in pattern or
                                "LANGFLOW_" in pattern or  
                                "langflow.git" in pattern or
                                category in ["api_endpoints", "environment_vars"]
                            )
                            
                            # Store finding
                            finding_key = f"{repo}_{category}_{pattern}"
                            if finding_key not in repo_findings:
                                repo_findings[finding_key] = LangFlowFinding(
                                    repo=repo,
                                    source="manual_detection", 
                                    package=f"Manual indicator ({category})",
                                    version="Unknown",
                                    vulnerable=is_vulnerable,
                                    cve_details=f"Manual installation indicator: {indicator_detail}"
                                )
                                
        except Exception as e:
            if "/tmp/" not in str(json_file):  # Avoid spamming for tmp files
                print(f"⚠️  Error searching {json_file.name}: {e}")
    
    return list(repo_findings.values())


def analyze_findings(findings: List[LangFlowFinding]) -> None:
    """Analyze and display the LangFlow findings with vulnerability assessment."""
    if not findings:
        print("✅ No LangFlow usage detected across all repositories.")
        return
    
    print(f"\n🔍 LangFlow Detection Report")
    print(f"{'='*60}")
    print(f"Found {len(findings)} LangFlow-related items across repositories\n")
    
    # Separate vulnerable and non-vulnerable findings
    vulnerable_findings = [f for f in findings if f.vulnerable]
    safe_findings = [f for f in findings if not f.vulnerable]
    
    # LangFlow code injection vulnerability specific analysis
    code_injection_findings = [f for f in vulnerable_findings if LANGFLOW_VULNERABILITY["id"] in f.cve_details]
    
    if code_injection_findings:
        print(f"🚨 CRITICAL: LANGFLOW CODE INJECTION DETECTED")
        print(f"{'='*60}")
        print(f"Found {len(code_injection_findings)} instances of LangFlow code injection vulnerability")
        print(f"Severity: {LANGFLOW_VULNERABILITY['severity']}")
        print(f"Vulnerability: {LANGFLOW_VULNERABILITY['description']}")
        print(f"Affected Endpoint: {LANGFLOW_VULNERABILITY['endpoint']}")
        print(f"Authentication Required: {LANGFLOW_VULNERABILITY['authentication_required']}\n")
        
        for finding in code_injection_findings:
            print(f"  🔥 {finding.repo}")
            print(f"     Package: {finding.package} v{finding.version}")
            print(f"     Source: {finding.source}")
            print(f"     Details: {finding.cve_details}\n")
    
    # Vulnerable instances (excluding already shown code injection specific)
    other_vulnerable = [f for f in vulnerable_findings if LANGFLOW_VULNERABILITY["id"] not in f.cve_details]
    
    if other_vulnerable:
        print(f"⚠️  VULNERABLE LANGFLOW INSTANCES")
        print(f"{'='*60}")
        print(f"Found {len(other_vulnerable)} potentially vulnerable LangFlow instances\n")
        
        # Group by repo for cleaner display
        by_repo: Dict[str, List[LangFlowFinding]] = {}
        for finding in other_vulnerable:
            by_repo.setdefault(finding.repo, []).append(finding)
        
        for repo, repo_findings in sorted(by_repo.items()):
            print(f"  🔴 {repo}")
            for finding in repo_findings:
                print(f"     📦 {finding.package} v{finding.version} ({finding.source})")
                print(f"        {finding.cve_details}")
            print()
    
    # Safe instances
    if safe_findings:
        print(f"✅ SAFE LANGFLOW INSTANCES")
        print(f"{'='*60}")
        print(f"Found {len(safe_findings)} LangFlow instances that appear safe\n")
        
        by_repo: Dict[str, List[LangFlowFinding]] = {}
        for finding in safe_findings:
            by_repo.setdefault(finding.repo, []).append(finding)
        
        for repo, repo_findings in sorted(by_repo.items()):
            print(f"  🟢 {repo}")
            for finding in repo_findings:
                print(f"     📦 {finding.package} v{finding.version} ({finding.source})")
                print(f"        {finding.cve_details}")
            print()
    
    # Summary statistics
    print(f"📊 SUMMARY")
    print(f"{'='*60}")
    print(f"Total repositories analyzed: {len(set(f.repo for f in findings))}")
    print(f"LangFlow instances found: {len(findings)}")
    print(f"🚨 Critical (Code Injection): {len(code_injection_findings)}")
    print(f"⚠️  Other vulnerabilities: {len(other_vulnerable)}")
    print(f"✅ Safe instances: {len(safe_findings)}")
    
    # Detection method breakdown
    print(f"\n🔍 DETECTION BREAKDOWN")
    print(f"{'='*60}")
    detection_counts = {}
    for finding in findings:
        detection_counts[finding.source] = detection_counts.get(finding.source, 0) + 1
    
    for detection_type, count in sorted(detection_counts.items()):
        if detection_type == "sbom":
            print(f"📦 Package Manager (SBOM): {count}")
        elif detection_type == "dependabot":
            print(f"🚨 Security Alerts (Dependabot): {count}")
        elif detection_type == "codeql":
            print(f"🔍 Code Analysis (CodeQL): {count}")
        elif detection_type == "manual_detection":
            print(f"🕵️  Manual Installations: {count}")
            # Show breakdown of manual indicators
            manual_categories = {}
            for finding in findings:
                if finding.source == "manual_detection":
                    if "(" in finding.package and ")" in finding.package:
                        category = finding.package.split("(")[1].split(")")[0]
                        manual_categories[category] = manual_categories.get(category, 0) + 1
            
            for category, cat_count in sorted(manual_categories.items()):
                print(f"     • {category}: {cat_count}")
    
    # Package version summary
    print(f"\n📦 PACKAGE VERSIONS DETECTED")
    print(f"{'='*60}")
    version_summary: Dict[str, Set[str]] = {}
    for finding in findings:
        if finding.source == "sbom":  # Focus on actual package versions
            version_summary.setdefault(finding.package, set()).add(finding.version)
    
    if version_summary:
        for package, versions in sorted(version_summary.items()):
            print(f"  {package}:")
            for ver in sorted(versions):
                vuln_status = "🚨" if any(f.version == ver and f.vulnerable for f in findings if f.package == package) else "✅"
                count = sum(1 for f in findings if f.package == package and f.version == ver)
                print(f"    {vuln_status} {ver:20s} ({count} repos)")
    else:
        print("  (No package manager installations detected - check manual findings above)")
    
    # Recommendations
    print(f"\n💡 RECOMMENDATIONS")
    print(f"{'='*60}")
    if code_injection_findings:
        print(f"🚨 IMMEDIATE ACTION REQUIRED:")
        print(f"   • LangFlow code injection vulnerability detected - update to v1.3.0+ immediately")
        print(f"   • Block access to /api/v1/validate/code endpoint if possible")
        print(f"   • Review server logs for exploitation attempts")
        print(f"   • Affected packages should be updated to version 1.3.0 or later")
    
    if vulnerable_findings:
        print(f"⚠️  SECURITY REVIEW NEEDED:")
        print(f"   • Update vulnerable LangFlow packages to latest versions")
        print(f"   • Review LangFlow usage in production environments")
        print(f"   • Implement additional security controls around flow execution")
    
    if findings:
        print(f"📋 GENERAL RECOMMENDATIONS:")
        print(f"   • Maintain inventory of all LangFlow usage (including manual installations)")
        print(f"   • Subscribe to LangFlow security advisories")
        print(f"   • Implement network-level access controls for LangFlow API endpoints")
        print(f"   • Monitor /api/v1/validate/code endpoint for suspicious activity")
        print(f"   • Regular security scanning of flow configurations")
        
        # Add specific recommendations for manual installations
        manual_findings = [f for f in findings if f.source == "manual_detection"]
        if manual_findings:
            print(f"")
            print(f"🕵️  MANUAL INSTALLATION SPECIFIC:")
            print(f"   • Audit git submodules and vendor dependencies")
            print(f"   • Review Docker containers and custom builds")
            print(f"   • Check environment variables and configuration files")
            print(f"   • Validate all custom LangFlow integrations")
            print(f"   • Consider centralizing LangFlow deployments for better control")


def main():
    parser = argparse.ArgumentParser(
        description="Search for LangFlow usage and CVE-2025-3248 vulnerability across all repositories"
    )
    parser.add_argument("-d", "--dir", default="findings", help="Findings directory (default: findings)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    findings_dir = Path(args.dir)
    if not findings_dir.exists():
        print(f"❌ Findings directory not found: {findings_dir}")
        sys.exit(1)
    
    print(f"🔍 Searching for LangFlow usage in {findings_dir}")
    
    # Search all file types
    all_findings = []
    
    if args.verbose:
        print("   📦 Searching SBOM files...")
    all_findings.extend(search_sbom_files(findings_dir))
    
    if args.verbose:
        print("   🚨 Searching Dependabot alerts...")
    all_findings.extend(search_dependabot_files(findings_dir))
    
    if args.verbose:
        print("   🔍 Searching CodeQL findings...")
    all_findings.extend(search_codeql_files(findings_dir))
    
    if args.verbose:
        print("   🕵️  Searching for manual installations...")
    all_findings.extend(search_for_manual_langflow(findings_dir))
    
    # Analyze and display results
    analyze_findings(all_findings)


if __name__ == "__main__":
    main()