#!/usr/bin/env python3
"""Generate HTML reports from SBOM, Dependabot alerts, and CodeQL findings JSON files."""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from collections import defaultdict

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
except ImportError:
    print("❌ Jinja2 not found. Install it: pip install -r requirements.txt")
    sys.exit(1)


def load_json_file(filepath: Path) -> dict:
    """Load and parse JSON file."""
    try:
        return json.loads(filepath.read_text())
    except Exception as e:
        print(f"❌ Error loading {filepath}: {e}")
        return {}


def get_repo_name_from_filename(filename: str) -> str:
    """Extract repo name from filename pattern: org_repo_contenttype_timestamp.json"""
    parts = filename.replace('.json', '').split('_')
    if len(parts) >= 4:
        # Reconstruct org/repo from org_repo
        return f"{parts[0]}/{parts[1]}"
    return filename.replace('.json', '')


def get_content_type_from_filename(filename: str) -> str:
    """Extract content type from filename."""
    if '_sbom_' in filename:
        return 'sbom'
    elif '_dependabot_' in filename:
        return 'dependabot'
    elif '_codeql_' in filename:
        return 'codeql'
    return 'unknown'


def setup_jinja_environment(templates_dir: Path) -> Environment:
    """Setup Jinja2 environment with templates."""
    return Environment(
        loader=FileSystemLoader(templates_dir),
        autoescape=select_autoescape(['html', 'xml'])
    )


def process_sbom_data(data: dict, repo_name: str) -> dict:
    """Process SBOM data for template rendering."""
    sbom_info = data.get('sbom', {})
    packages = sbom_info.get('packages', [])
    
    # Extract license information and organize packages
    processed_packages = []
    for package in packages:
        processed_package = {
            'name': package.get('name', 'Unknown'),
            'version': package.get('versionInfo', 'Unknown'),
            'supplier': package.get('supplier', {}).get('name', 'Unknown'),
            'licenses': []
        }
        
        # Extract license information
        license_info = package.get('licenseConcluded', '')
        if license_info and license_info != 'NOASSERTION':
            processed_package['licenses'].append(license_info)
        
        # Also check for license information in other fields
        license_declared = package.get('licenseDeclared', '')
        if license_declared and license_declared != 'NOASSERTION' and license_declared not in processed_package['licenses']:
            processed_package['licenses'].append(license_declared)
        
        if not processed_package['licenses']:
            processed_package['licenses'] = ['Not specified']
        
        processed_packages.append(processed_package)
    
    return {
        'repo_name': repo_name,
        'sbom_name': sbom_info.get('name', 'Unknown'),
        'creation_time': sbom_info.get('creationInfo', {}).get('created', 'Unknown'),
        'packages': processed_packages,
        'total_packages': len(processed_packages),
        'generated_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


def process_dependabot_data(data: list, repo_name: str) -> dict:
    """Process Dependabot data for template rendering."""
    alerts = data if isinstance(data, list) else []
    
    # Group by severity
    severity_groups = {'critical': [], 'high': [], 'medium': [], 'low': [], 'unknown': []}
    
    for alert in alerts:
        severity = alert.get('security_advisory', {}).get('severity', 'unknown').lower()
        if severity not in severity_groups:
            severity = 'unknown'
        
        processed_alert = {
            'number': alert.get('number', 'N/A'),
            'package': alert.get('dependency', {}).get('package', {}).get('name', 'Unknown'),
            'version': alert.get('dependency', {}).get('package', {}).get('version', 'Unknown'),
            'summary': alert.get('security_advisory', {}).get('summary', 'No summary available'),
            'cve_id': alert.get('security_advisory', {}).get('cve_id', ''),
            'published_at': alert.get('security_advisory', {}).get('published_at', ''),
            'state': alert.get('state', 'unknown'),
            'html_url': alert.get('html_url', '')
        }
        
        severity_groups[severity].append(processed_alert)
    
    return {
        'repo_name': repo_name,
        'total_alerts': len(alerts),
        'severity_groups': severity_groups,
        'generated_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


def process_codeql_data(data: list, repo_name: str) -> dict:
    """Process CodeQL data for template rendering."""
    alerts = data if isinstance(data, list) else []
    
    # Group by severity
    severity_groups = {'critical': [], 'high': [], 'medium': [], 'low': [], 'unknown': []}
    
    for alert in alerts:
        severity = alert.get('rule', {}).get('severity', 'unknown').lower()
        if severity not in severity_groups:
            severity = 'unknown'
        
        processed_alert = {
            'number': alert.get('number', 'N/A'),
            'rule_id': alert.get('rule', {}).get('id', 'Unknown'),
            'rule_name': alert.get('rule', {}).get('name', 'Unknown'),
            'description': alert.get('rule', {}).get('description', 'No description available'),
            'category': alert.get('rule', {}).get('security_severity_level', 'Unknown'),
            'state': alert.get('state', 'unknown'),
            'created_at': alert.get('created_at', ''),
            'html_url': alert.get('html_url', ''),
            'location': {
                'path': alert.get('most_recent_instance', {}).get('location', {}).get('path', 'Unknown'),
                'start_line': alert.get('most_recent_instance', {}).get('location', {}).get('start_line', 'N/A'),
                'end_line': alert.get('most_recent_instance', {}).get('location', {}).get('end_line', 'N/A')
            }
        }
        
        severity_groups[severity].append(processed_alert)
    
    return {
        'repo_name': repo_name,
        'total_alerts': len(alerts),
        'severity_groups': severity_groups,
        'generated_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


def generate_html_report(json_file: Path, output_dir: Path, templates_dir: Path, verbose: bool = False) -> bool:
    """Generate HTML report from a JSON file."""
    try:
        # Load JSON data
        data = load_json_file(json_file)
        if not data:
            return False
        
        # Extract info from filename
        repo_name = get_repo_name_from_filename(json_file.name)
        content_type = get_content_type_from_filename(json_file.name)
        
        if content_type == 'unknown':
            print(f"⚠️  Unknown content type for {json_file.name}")
            return False
        
        # Setup Jinja2
        env = setup_jinja_environment(templates_dir)
        template = env.get_template(f"{content_type}.html")
        
        # Process data based on content type
        if content_type == 'sbom':
            template_data = process_sbom_data(data, repo_name)
        elif content_type == 'dependabot':
            template_data = process_dependabot_data(data, repo_name)
        elif content_type == 'codeql':
            template_data = process_codeql_data(data, repo_name)
        else:
            return False
        
        # Generate HTML
        html_content = template.render(template_data)
        
        # Create output filename
        output_filename = json_file.stem + '.html'
        output_path = output_dir / output_filename
        
        # Write HTML file
        output_path.write_text(html_content, encoding='utf-8')
        
        if verbose:
            print(f"✅ Generated: {output_path}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error processing {json_file.name}: {e}")
        return False


def collect_rollup_data_by_type(json_files: list) -> dict:
    """Collect and organize data by content type for rollup reports."""
    rollup_data = {
        'sbom': [],
        'dependabot': [], 
        'codeql': []
    }
    
    for json_file in json_files:
        content_type = get_content_type_from_filename(json_file.name)
        if content_type == 'unknown':
            continue
            
        data = load_json_file(json_file)
        if not data:
            continue
            
        repo_name = get_repo_name_from_filename(json_file.name)
        
        # Process and store data for rollup
        if content_type == 'sbom':
            processed_data = process_sbom_data(data, repo_name)
            rollup_data['sbom'].append(processed_data)
        elif content_type == 'dependabot':
            processed_data = process_dependabot_data(data, repo_name)
            rollup_data['dependabot'].append(processed_data)
        elif content_type == 'codeql':
            processed_data = process_codeql_data(data, repo_name)
            rollup_data['codeql'].append(processed_data)
    
    return rollup_data


def generate_rollup_reports(rollup_data: dict, output_dir: Path, templates_dir: Path, verbose: bool = False) -> int:
    """Generate rollup HTML reports for each content type."""
    success_count = 0
    
    for content_type, repos_data in rollup_data.items():
        if not repos_data:
            if verbose:
                print(f"⏭️  Skipping {content_type} rollup - no data")
            continue
            
        try:
            # Setup Jinja2 environment
            env = setup_jinja_environment(templates_dir)
            template = env.get_template(f"{content_type}_rollup.html")
            
            # Create rollup template data
            template_data = create_rollup_template_data(content_type, repos_data)
            
            # Generate HTML
            html_content = template.render(template_data)
            
            # Create output filename
            output_filename = f"{content_type}_rollup.html"
            output_path = output_dir / output_filename
            
            # Write HTML file
            output_path.write_text(html_content, encoding='utf-8')
            
            if verbose:
                print(f"✅ Generated rollup: {output_path}")
            
            success_count += 1
            
        except Exception as e:
            print(f"❌ Error generating {content_type} rollup: {e}")
            
    return success_count


def create_rollup_template_data(content_type: str, repos_data: list) -> dict:
    """Create template data for rollup reports."""
    if content_type == 'sbom':
        return create_sbom_rollup_data(repos_data)
    elif content_type == 'dependabot':
        return create_dependabot_rollup_data(repos_data)
    elif content_type == 'codeql':
        return create_codeql_rollup_data(repos_data)
    else:
        return {}


def create_sbom_rollup_data(repos_data: list) -> dict:
    """Create rollup data for SBOM reports."""
    all_packages = defaultdict(lambda: {'versions': set(), 'repos': set(), 'licenses': set()})
    total_packages = 0
    total_repos = len(repos_data)
    
    for repo_data in repos_data:
        for package in repo_data['packages']:
            pkg_name = package['name']
            all_packages[pkg_name]['versions'].add(package['version'])
            all_packages[pkg_name]['repos'].add(repo_data['repo_name'])
            for license in package['licenses']:
                all_packages[pkg_name]['licenses'].add(license)
            total_packages += 1
    
    # Convert sets to sorted lists for template
    processed_packages = []
    for pkg_name, pkg_info in all_packages.items():
        processed_packages.append({
            'name': pkg_name,
            'versions': sorted(list(pkg_info['versions'])),
            'repos': sorted(list(pkg_info['repos'])),
            'licenses': sorted(list(pkg_info['licenses'])),
            'repo_count': len(pkg_info['repos'])
        })
    
    # Sort by repo count (most used packages first)
    processed_packages.sort(key=lambda x: x['repo_count'], reverse=True)
    
    return {
        'content_type': 'SBOM',
        'total_repos': total_repos,
        'total_packages': total_packages,
        'unique_packages': len(processed_packages),
        'packages': processed_packages,
        'repos': [repo['repo_name'] for repo in repos_data],
        'generated_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


def create_dependabot_rollup_data(repos_data: list) -> dict:
    """Create rollup data for Dependabot reports."""
    total_alerts = 0
    severity_totals = defaultdict(int)
    all_repos = []
    
    for repo_data in repos_data:
        total_alerts += repo_data['total_alerts']
        repo_summary = {
            'name': repo_data['repo_name'],
            'total_alerts': repo_data['total_alerts'],
            'severity_counts': {}
        }
        
        for severity, alerts in repo_data['severity_groups'].items():
            count = len(alerts)
            severity_totals[severity] += count
            repo_summary['severity_counts'][severity] = count
            
        all_repos.append(repo_summary)
    
    # Sort repos by total alerts (highest first)
    all_repos.sort(key=lambda x: x['total_alerts'], reverse=True)
    
    return {
        'content_type': 'Dependabot',
        'total_repos': len(repos_data),
        'total_alerts': total_alerts,
        'severity_totals': dict(severity_totals),
        'repos': all_repos,
        'generated_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


def create_codeql_rollup_data(repos_data: list) -> dict:
    """Create rollup data for CodeQL reports."""
    total_alerts = 0
    severity_totals = defaultdict(int)
    rule_counts = defaultdict(int)
    all_repos = []
    
    for repo_data in repos_data:
        total_alerts += repo_data['total_alerts']
        repo_summary = {
            'name': repo_data['repo_name'],
            'total_alerts': repo_data['total_alerts'],
            'severity_counts': {}
        }
        
        for severity, alerts in repo_data['severity_groups'].items():
            count = len(alerts)
            severity_totals[severity] += count
            repo_summary['severity_counts'][severity] = count
            
            # Count rule occurrences
            for alert in alerts:
                rule_id = alert.get('rule_id', 'Unknown')
                rule_counts[rule_id] += 1
                
        all_repos.append(repo_summary)
    
    # Sort repos by total alerts (highest first)
    all_repos.sort(key=lambda x: x['total_alerts'], reverse=True)
    
    # Get top 20 most common rules
    top_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:20]
    
    return {
        'content_type': 'CodeQL',
        'total_repos': len(repos_data),
        'total_alerts': total_alerts,
        'severity_totals': dict(severity_totals),
        'top_rules': [{'rule_id': rule, 'count': count} for rule, count in top_rules],
        'repos': all_repos,
        'generated_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


def main():
    parser = argparse.ArgumentParser(description="Generate HTML reports from GHAS findings JSON files")
    parser.add_argument("-i", "--input", default="findings", help="Input directory with JSON files")
    parser.add_argument("-o", "--output", default="reports", help="Output directory for HTML reports")
    parser.add_argument("-t", "--templates", default="templates", help="Templates directory")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--no-rollup", action="store_true", help="Disable generation of rollup reports (enabled by default)")
    
    args = parser.parse_args()
    
    # Setup paths
    input_dir = Path(args.input)
    output_dir = Path(args.output)
    templates_dir = Path(args.templates)
    
    # Validate directories
    if not input_dir.exists():
        print(f"❌ Input directory not found: {input_dir}")
        sys.exit(1)
    
    if not templates_dir.exists():
        print(f"❌ Templates directory not found: {templates_dir}")
        sys.exit(1)
    
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Find JSON files
    json_files = list(input_dir.glob("*.json"))
    if not json_files:
        print(f"❌ No JSON files found in {input_dir}")
        sys.exit(1)
    
    print(f"\n📊 Processing {len(json_files)} JSON files...")
    print(f"📁 Input:     {input_dir.absolute()}")
    print(f"📁 Output:    {output_dir.absolute()}")
    print(f"📁 Templates: {templates_dir.absolute()}\n")
    
    # Process individual files
    success_count = 0
    for json_file in json_files:
        if generate_html_report(json_file, output_dir, templates_dir, args.verbose):
            success_count += 1
    
    print(f"\n✅ Successfully generated {success_count}/{len(json_files)} individual HTML reports")
    
    # Generate rollup reports unless disabled
    rollup_count = 0
    if not args.no_rollup:
        print("\n📊 Generating rollup reports...")
        rollup_data = collect_rollup_data_by_type(json_files)
        rollup_count = generate_rollup_reports(rollup_data, output_dir, templates_dir, args.verbose)
        print(f"✅ Successfully generated {rollup_count} rollup reports")
    
    total_reports = success_count + rollup_count
    if total_reports > 0:
        print(f"\n📁 All reports saved to: {output_dir.absolute()}")
        if rollup_count > 0:
            print(f"📋 Rollup reports: *_rollup.html files provide cross-repository summaries")


if __name__ == "__main__":
    main()