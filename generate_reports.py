#!/usr/bin/env python3
"""Generate HTML reports from SBOM, Dependabot alerts, and CodeQL findings JSON files."""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

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


def main():
    parser = argparse.ArgumentParser(description="Generate HTML reports from GHAS findings JSON files")
    parser.add_argument("-i", "--input", default="findings", help="Input directory with JSON files")
    parser.add_argument("-o", "--output", default="reports", help="Output directory for HTML reports")
    parser.add_argument("-t", "--templates", default="templates", help="Templates directory")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
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
    
    # Process files
    success_count = 0
    for json_file in json_files:
        if generate_html_report(json_file, output_dir, templates_dir, args.verbose):
            success_count += 1
    
    print(f"\n✅ Successfully generated {success_count}/{len(json_files)} HTML reports")
    
    if success_count > 0:
        print(f"📁 Reports saved to: {output_dir.absolute()}")


if __name__ == "__main__":
    main()