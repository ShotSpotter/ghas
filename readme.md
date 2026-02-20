# AppSec GitHub Script and Tooling

## Venv
```
p ins#

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