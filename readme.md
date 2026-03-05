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