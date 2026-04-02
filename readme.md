# AppSec GitHub Script and Tooling

## Venv
```
pip install -r requirements.txt
```

## ApplyLabels

```
# Preview what will happen
python apply_labels.py --dry-run

# Run it (10 parallel workers by default)
python apply_labels.py

# Custom file, more workers, verbose output
python apply_labels.py -f my_repos.json -w 20 -v
```

## Enable GHAS

```
# Check what's currently enabled
python enable_ghas.py --check

# Preview what will be enabled
python enable_ghas.py --dry-run -v

# Enable everything
python enable_ghas.py

# Enable only specific features
python enable_ghas.py --features advanced_security secret_scanning

# Enable only dependabot (no GHAS seat needed)
python enable_ghas.py --features dependabot_alerts dependabot_updates

```

## Download Findings

### Auth
 `gh auth refresh -h github.com -s admin:repo_hook -s security_events`


```
# Preview everything
python download_findings.py --dry-run -v

# Download all types
python download_findings.py

# Only SBOMs
python download_findings.py -t sbom

# Only Dependabot + CodeQL
python download_findings.py -t dependabot codeql

# Custom output dir, more verbose
python download_findings.py -o /tmp/appsec-findings -v

```

## Generate HTML Reports

Converts the JSON findings from `download_findings.py` into formatted HTML reports with appropriate disclaimers and styling.

```
# Generate reports from findings directory
python generate_reports.py

# Custom input/output directories
python generate_reports.py -i /path/to/findings -o /path/to/reports

# Verbose output to see each file processed
python generate_reports.py -v

# Using custom template directory
python generate_reports.py -t /path/to/custom/templates
```

### Report Features

- **SBOM Reports**: Comprehensive package inventory with license information prominently displayed
- **Dependabot Reports**: Security alerts with disclaimers about defense in depth and infrastructure mitigations  
- **CodeQL Reports**: Static analysis findings with warnings about false positives and need for expert interpretation
- **Interactive Features**: Search functionality, responsive design, severity grouping
- **Professional Styling**: Clean, readable HTML with proper color coding and navigation

Reports include important disclaimers emphasizing that these are raw findings requiring:
- Expert interpretation and context analysis
- Consideration of existing infrastructure mitigations
- Validation through penetration testing and external vulnerability scans
- Defense-in-depth security approach

## Search SBOM

# Substring search
python search_sbom.py log4j

# Exact match
python search_sbom.py "org.apache.logging.log4j:log4j-core" --exact

# Different findings dir
python search_sbom.py spring -d /tmp/appsec-findings

## LangFlow Vulnerability Detection

Search all repositories for LangFlow usage and check for critical code injection vulnerability:

```bash
# Basic scan for LangFlow usage and vulnerabilities  
python search_langflow.py

# Verbose output with detailed scanning progress
python search_langflow.py -v

# Custom findings directory
python search_langflow.py -d /path/to/findings
```

This script performs comprehensive detection across:
- **SBOM files**: Identifies LangFlow packages and versions
- **Dependabot alerts**: Finds LangFlow-related security advisories
- **CodeQL findings**: Detects LangFlow code patterns and potential security issues
- **Manual installations**: Searches for evidence of manual LangFlow deployments including:
  - Git submodules and direct repository clones
  - Docker containers and custom images
  - Configuration files and environment variables
  - API endpoint usage patterns
  - File path indicators and directory structures

**Critical Vulnerability Coverage:**
- **Code Injection in /api/v1/validate/code**: All LangFlow versions prior to 1.3.0
- **Remote Unauthenticated Exploitation**: No authentication required for attack
- **Arbitrary Code Execution**: Attackers can execute arbitrary code via crafted HTTP requests
- Automatically identifies vulnerable versions requiring immediate patching

**Report Features:**
- Cross-repository vulnerability summary
- Package version inventory with risk assessment  
- Specific code injection vulnerability detection and severity analysis
- **Manual installation detection** for non-package-manager deployments:
  - Git submodules (`git submodule add https://github.com/logspace-ai/langflow`)
  - Direct clones and vendor directories
  - Docker containers and custom builds
  - Configuration files and environment variables
  - API endpoint references and usage patterns
- Actionable security recommendations including endpoint blocking guidance

## Axios Security Check

Check for compromised Axios versions (1.14.1 and 0.30.4) that contain malicious code:

### Python Script (Comprehensive)

```bash
# Check current directory recursively
python check_axios_versions.py

# Check findings directory for SBOM data
python check_axios_versions.py -d findings/

# Check specific files
python check_axios_versions.py -f package.json package-lock.json

# Verbose output
python check_axios_versions.py -v

# Save report to file
python check_axios_versions.py --output axios_check_report.txt

# Save detailed results as JSON
python check_axios_versions.py --json-output axios_results.json
```

### Shell Script (Quick Check)

```bash
# Quick check of current directory
./check_axios_versions.sh

# Check specific directory
./check_axios_versions.sh /path/to/project

# Use in CI/CD pipelines (exits with code 1 if compromised versions found)
./check_axios_versions.sh || exit 1
```

### Integrated Workflow

```bash
# Download findings first, then check for Axios
python download_findings.py
python integrate_axios_check.py

# Custom findings directory
python integrate_axios_check.py -d my_findings/

# Save detailed report
python integrate_axios_check.py -o axios_security_report.txt
```

### File Types Checked

- **SBOM files**: `*sbom*.json` - Scans Software Bill of Materials for npm/axios packages
- **package.json**: Checks dependencies, devDependencies, and peerDependencies  
- **package-lock.json**: Scans lockfile entries in both v1 and v2+ formats
- **yarn.lock**: Parses Yarn lockfile format for axios entries

### Security Alert Details

**Compromised versions checked**: 1.14.1, 0.30.4  
**Risk**: These versions contain malicious code that can compromise applications  
**Action required**: Immediately update to safe versions (latest stable recommended)  
**Reference**: https://security.snyk.io/vuln/SNYK-JS-AXIOS-7361793

The checker will:
- 🚨 **Alert** on any compromised versions found
- ✅ **Report** safe versions detected  
- 📄 **Generate** summary reports for compliance
- 💾 **Save** JSON output for CI/CD integration
- ⚡ **Exit** with error code 1 if compromised versions detected (for automation)