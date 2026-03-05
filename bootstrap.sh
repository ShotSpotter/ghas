#!/bin/bash

# Bootstrap script for GitHub AppSec Scripts and Tooling
# Creates virtual environment, installs dependencies, and activates environment

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
VENV_DIR="$SCRIPT_DIR/venv"

echo -e "${BLUE}🚀 GitHub AppSec Tooling Bootstrap${NC}"
echo "=================================================="

# Check if virtual environment already exists
if [ -d "$VENV_DIR" ]; then
    echo -e "${GREEN}✅ Virtual environment already exists at: $VENV_DIR${NC}"
else
    echo -e "${YELLOW}📦 Creating virtual environment...${NC}"
    python3 -m venv "$VENV_DIR"
    echo -e "${GREEN}✅ Virtual environment created at: $VENV_DIR${NC}"
fi

# Activate virtual environment
echo -e "${YELLOW}🔧 Activating virtual environment...${NC}"
source "$VENV_DIR/bin/activate"

# Check if requirements.txt exists and install dependencies
if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
    echo -e "${YELLOW}📋 Installing dependencies from requirements.txt...${NC}"
    pip install --upgrade pip
    pip install -r "$SCRIPT_DIR/requirements.txt"
    echo -e "${GREEN}✅ Dependencies installed successfully${NC}"
else
    echo -e "${RED}⚠️  No requirements.txt found, skipping dependency installation${NC}"
fi

echo ""
echo "=================================================="
echo -e "${GREEN}🎉 Environment ready!${NC}"
echo ""
echo -e "${BLUE}📚 Available Commands:${NC}"
echo ""
echo -e "${YELLOW}🏷️  Apply Labels:${NC}"
echo "   python apply_labels.py --dry-run    # Preview changes"
echo "   python apply_labels.py              # Apply labels"
echo ""
echo -e "${YELLOW}🔒 Enable GHAS:${NC}"
echo "   python enable_ghas.py --check       # Check current status"
echo "   python enable_ghas.py --dry-run     # Preview changes"
echo "   python enable_ghas.py               # Enable GHAS features"
echo ""
echo -e "${YELLOW}⬇️  Download Findings:${NC}"
echo "   python download_findings.py --dry-run    # Preview downloads"
echo "   python download_findings.py              # Download all findings"
echo "   python download_findings.py -t sbom      # Download only SBOMs"
echo ""
echo -e "${YELLOW}📊 Generate Reports:${NC}"
echo "   python generate_reports.py          # Generate HTML reports"
echo "   python generate_reports.py -v       # Verbose output"
echo ""
echo -e "${YELLOW}🔍 Search SBOM:${NC}"
echo "   python search_sbom.py log4j         # Search for packages"
echo "   python search_sbom.py spring        # Search in SBOM files"
echo ""
echo -e "${BLUE}📖 For detailed help, see: ${NC}readme.md"
echo ""
echo -e "${GREEN}💡 Tip: Your virtual environment is now active!${NC}"
echo -e "${GREEN}   To deactivate later, run: ${NC}deactivate"
echo ""

# Start a new shell with the virtual environment active
echo -e "${YELLOW}🐚 Starting new shell with virtual environment active...${NC}"
echo -e "${BLUE}   (Type 'exit' to return to your original shell)${NC}"
echo ""

# Export the virtual environment path so it's available in the new shell
export VIRTUAL_ENV="$VENV_DIR"
export PATH="$VENV_DIR/bin:$PATH"

# Check if we're in an interactive shell
if [ -t 1 ]; then
    # Start an interactive shell
    exec ${SHELL:-/bin/bash} -l
else
    # Non-interactive, just show the activation command
    echo "To activate this environment in your current shell, run:"
    echo "source $VENV_DIR/bin/activate"
fi