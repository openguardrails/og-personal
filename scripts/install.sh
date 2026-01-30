#!/bin/bash
# OG Personal - One-command installer
# Usage: curl -fsSL https://openguardrails.com/install.sh | bash

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo ""
echo -e "${GREEN}   OG Personal${NC} - Security Agent Installer"
echo ""

# Check for Node.js
if ! command -v node &> /dev/null; then
    echo -e "${RED}Error: Node.js is not installed.${NC}"
    echo "Please install Node.js 22+ from https://nodejs.org"
    exit 1
fi

# Check Node.js version
NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 22 ]; then
    echo -e "${YELLOW}Warning: Node.js 22+ is recommended. You have v${NODE_VERSION}.${NC}"
fi

# Check for npm
if ! command -v npm &> /dev/null; then
    echo -e "${RED}Error: npm is not installed.${NC}"
    exit 1
fi

echo -e "${BLUE}Installing OG Personal...${NC}"

# Install globally
npm install -g og-personal

echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo "Next steps:"
echo -e "  ${BLUE}og onboard${NC}  - Set up OG Personal with your API key"
echo -e "  ${BLUE}og start${NC}    - Start 24/7 security monitoring"
echo -e "  ${BLUE}og scan${NC}     - Run a one-time security scan"
echo ""
echo -e "Dashboard: ${BLUE}http://localhost:18790${NC}"
echo ""
