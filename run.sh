#!/bin/bash
# CyberDrill Startup Script for Linux/Mac

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}CyberDrill Security Tool${NC}"
echo -e "${GREEN}================================${NC}"

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is not installed${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo -e "${GREEN}Python version: ${PYTHON_VERSION}${NC}"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv venv
fi

# Activate virtual environment
echo -e "${YELLOW}Activating virtual environment...${NC}"
source venv/bin/activate

# Install/upgrade pip
echo -e "${YELLOW}Upgrading pip...${NC}"
pip install --upgrade pip

# Install requirements
echo -e "${YELLOW}Installing requirements...${NC}"
pip install -r requirements.txt

# Check for X11 (for GUI)
if [ -z "$DISPLAY" ]; then
    echo -e "${YELLOW}Warning: DISPLAY not set. GUI may not work properly.${NC}"
fi

# Create necessary directories
mkdir -p data icons

# Run the application
echo -e "${GREEN}Starting CyberDrill...${NC}"
python3 cyberdrill.py "$@"

# Deactivate virtual environment on exit
deactivate