#!/bin/bash
# Quick shell script to check for compromised Axios versions
# Can be used in CI/CD pipelines or as a pre-commit hook

set -e

# Compromised versions
COMPROMISED_VERSIONS=("1.14.1" "0.30.4")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to log messages
log() {
    echo -e "${BLUE}🔍 $1${NC}"
}

warn() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

error() {
    echo -e "${RED}🚨 $1${NC}"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

# Function to check if version is compromised
is_compromised_version() {
    local version="$1"
    for compromised in "${COMPROMISED_VERSIONS[@]}"; do
        if [[ "$version" == "$compromised" ]]; then
            return 0  # true
        fi
    done
    return 1  # false
}

# Function to check package.json files
check_package_json() {
    local file="$1"
    local found_issues=0
    
    log "Checking $file"
    
    if [[ ! -f "$file" ]]; then
        warn "File not found: $file"
        return 0
    fi
    
    # Use jq if available, otherwise use grep
    if command -v jq >/dev/null 2>&1; then
        # Check dependencies
        local axios_version
        axios_version=$(jq -r '.dependencies.axios // empty' "$file" 2>/dev/null)
        if [[ -n "$axios_version" ]]; then
            # Clean version (remove ^, ~, etc.)
            local clean_version
            clean_version=$(echo "$axios_version" | sed 's/[^0-9.]//g')
            if is_compromised_version "$clean_version"; then
                error "COMPROMISED AXIOS FOUND in $file: $axios_version (dependencies)"
                found_issues=1
            else
                success "Safe Axios version in $file: $axios_version (dependencies)"
            fi
        fi
        
        # Check devDependencies
        axios_version=$(jq -r '.devDependencies.axios // empty' "$file" 2>/dev/null)
        if [[ -n "$axios_version" ]]; then
            clean_version=$(echo "$axios_version" | sed 's/[^0-9.]//g')
            if is_compromised_version "$clean_version"; then
                error "COMPROMISED AXIOS FOUND in $file: $axios_version (devDependencies)"
                found_issues=1
            else
                success "Safe Axios version in $file: $axios_version (devDependencies)"
            fi
        fi
    else
        # Fallback to grep
        if grep -q '"axios"' "$file"; then
            local axios_lines
            axios_lines=$(grep -n '"axios"' "$file")
            while IFS= read -r line; do
                if echo "$line" | grep -q '"axios".*"1\.14\.1"'; then
                    error "COMPROMISED AXIOS 1.14.1 FOUND in $file: $line"
                    found_issues=1
                elif echo "$line" | grep -q '"axios".*"0\.30\.4"'; then
                    error "COMPROMISED AXIOS 0.30.4 FOUND in $file: $line"
                    found_issues=1
                else
                    success "Axios dependency found in $file (version check requires jq for precise parsing)"
                fi
            done <<< "$axios_lines"
        fi
    fi
    
    return $found_issues
}

# Function to check package-lock.json files
check_package_lock() {
    local file="$1"
    local found_issues=0
    
    log "Checking $file"
    
    if [[ ! -f "$file" ]]; then
        warn "File not found: $file"
        return 0
    fi
    
    # Check for compromised versions
    for version in "${COMPROMISED_VERSIONS[@]}"; do
        if grep -q "\"axios\".*\"$version\"" "$file" || grep -q "\"version\": \"$version\"" "$file"; then
            error "COMPROMISED AXIOS $version FOUND in $file"
            found_issues=1
        fi
    done
    
    # Show any axios entries found
    if grep -q "axios" "$file"; then
        local axios_count
        axios_count=$(grep -c "axios" "$file")
        if [[ $found_issues -eq 0 ]]; then
            success "Found $axios_count axios references in $file (no compromised versions detected)"
        fi
    fi
    
    return $found_issues
}

# Function to check yarn.lock files
check_yarn_lock() {
    local file="$1"
    local found_issues=0
    
    log "Checking $file"
    
    if [[ ! -f "$file" ]]; then
        warn "File not found: $file"
        return 0
    fi
    
    # Check for compromised versions
    for version in "${COMPROMISED_VERSIONS[@]}"; do
        if grep -q "version \"$version\"" "$file"; then
            # Check if it's axios by looking at the context
            local line_num
            line_num=$(grep -n "version \"$version\"" "$file" | cut -d: -f1)
            # Look backwards for axios reference
            if sed -n "$(($line_num-10)),${line_num}p" "$file" | grep -q "axios"; then
                error "COMPROMISED AXIOS $version FOUND in $file"
                found_issues=1
            fi
        fi
    done
    
    if grep -q "axios@" "$file"; then
        local axios_count
        axios_count=$(grep -c "axios@" "$file")
        if [[ $found_issues -eq 0 ]]; then
            success "Found $axios_count axios entries in $file (no compromised versions detected)"
        fi
    fi
    
    return $found_issues
}

# Function to check SBOM files
check_sbom() {
    local file="$1"
    local found_issues=0
    
    log "Checking SBOM $file"
    
    if [[ ! -f "$file" ]]; then
        warn "File not found: $file"
        return 0
    fi
    
    # Check for npm axios packages
    if grep -q "pkg:npm/axios" "$file"; then
        for version in "${COMPROMISED_VERSIONS[@]}"; do
            if grep -q "pkg:npm/axios@$version" "$file"; then
                error "COMPROMISED AXIOS $version FOUND in SBOM $file"
                found_issues=1
            fi
        done
        
        if [[ $found_issues -eq 0 ]]; then
            success "Found axios in SBOM $file (no compromised versions detected)"
        fi
    fi
    
    return $found_issues
}

# Main function
main() {
    echo "======================================"
    echo "🔍 Axios Security Checker (Shell)"
    echo "======================================"
    echo "Checking for compromised versions: ${COMPROMISED_VERSIONS[*]}"
    echo ""
    
    local total_issues=0
    local search_dir="${1:-.}"  # Default to current directory
    
    # Find and check package.json files
    while IFS= read -r -d '' file; do
        if ! check_package_json "$file"; then
            total_issues=$((total_issues + 1))
        fi
    done < <(find "$search_dir" -name "package.json" -type f -print0 2>/dev/null)
    
    # Find and check package-lock.json files
    while IFS= read -r -d '' file; do
        if ! check_package_lock "$file"; then
            total_issues=$((total_issues + 1))
        fi
    done < <(find "$search_dir" -name "package-lock.json" -type f -print0 2>/dev/null)
    
    # Find and check yarn.lock files
    while IFS= read -r -d '' file; do
        if ! check_yarn_lock "$file"; then
            total_issues=$((total_issues + 1))
        fi
    done < <(find "$search_dir" -name "yarn.lock" -type f -print0 2>/dev/null)
    
    # Find and check SBOM files
    while IFS= read -r -d '' file; do
        if ! check_sbom "$file"; then
            total_issues=$((total_issues + 1))
        fi
    done < <(find "$search_dir" -name "*sbom*.json" -type f -print0 2>/dev/null)
    
    echo ""
    echo "======================================"
    if [[ $total_issues -eq 0 ]]; then
        success "✅ No compromised Axios versions found!"
        echo "======================================"
        exit 0
    else
        error "❌ SECURITY ALERT: $total_issues compromised Axios version(s) detected!"
        echo "======================================"
        echo ""
        echo "🚨 IMMEDIATE ACTION REQUIRED:"
        echo "  1. Update axios to a safe version (latest stable recommended)"
        echo "  2. Review your package.json and lock files"
        echo "  3. Run 'npm audit' or 'yarn audit' for additional security checks"
        echo "  4. Consider using 'npm audit fix' to automatically fix issues"
        echo ""
        echo "📚 Reference: https://security.snyk.io/vuln/SNYK-JS-AXIOS-7361793"
        exit 1
    fi
}

# Check if script is being run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi