#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/ismeup/Agent"
DEFAULT_INSTALL_DIR="$(pwd)/ismeup-agent"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${BLUE}==>${NC} $1"; }
success() { echo -e "${GREEN}✓${NC} $1"; }
warn()    { echo -e "${YELLOW}!${NC} $1"; }
die()     { echo -e "${RED}Error:${NC} $1" >&2; exit 1; }

# ---------------------------------------------------------
# Interactive check — registration requires a real TTY
# ---------------------------------------------------------
if [ ! -t 0 ]; then
    echo ""
    echo -e "${BOLD}This installer requires an interactive terminal.${NC}"
    echo "Run it like this instead:"
    echo ""
    echo "  curl -sSL https://raw.githubusercontent.com/ismeup/Agent/main/install.sh -o install.sh"
    echo "  bash install.sh"
    echo ""
    exit 1
fi

echo ""
echo -e "${BOLD}IsMeUp Agent Installer${NC}"
echo "────────────────────────────────────────"
echo ""

# ---------------------------------------------------------
# Check dependencies
# ---------------------------------------------------------
info "Checking dependencies..."

command -v git  &>/dev/null || die "git is required but not installed."
command -v docker &>/dev/null || die "Docker is required but not installed. See https://docs.docker.com/engine/install/"

if docker compose version &>/dev/null 2>&1; then
    DC="docker compose"
elif command -v docker-compose &>/dev/null; then
    DC="docker-compose"
else
    die "Docker Compose is required but not installed. See https://docs.docker.com/compose/install/"
fi

success "git, Docker, and Docker Compose are available"

# ---------------------------------------------------------
# Install directory
# ---------------------------------------------------------
echo ""
echo -e "Install directory ${BLUE}[${DEFAULT_INSTALL_DIR}]${NC}:"
read -r -p "> " INSTALL_DIR
INSTALL_DIR="${INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"
INSTALL_DIR="${INSTALL_DIR%/}"   # strip trailing slash

PARENT_DIR="$(dirname "$INSTALL_DIR")"

if [ ! -d "$PARENT_DIR" ]; then
    die "Parent directory '$PARENT_DIR' does not exist."
fi

if [ -w "$PARENT_DIR" ]; then
    SUDO=""
else
    warn "No write permission to '$PARENT_DIR' — sudo will be used for file operations."
    SUDO="sudo"
fi

# ---------------------------------------------------------
# Clone or update repository
# ---------------------------------------------------------
echo ""
if [ -d "$INSTALL_DIR/.git" ]; then
    warn "Directory '$INSTALL_DIR' already contains a git repository."
    read -r -p "Update existing installation? [y/N] " REPLY
    if [[ "${REPLY}" =~ ^[Yy]$ ]]; then
        info "Pulling latest changes..."
        $SUDO git -C "$INSTALL_DIR" pull
        success "Repository updated"
    else
        info "Using existing directory as-is"
    fi
elif [ -d "$INSTALL_DIR" ] && [ -n "$(ls -A "$INSTALL_DIR" 2>/dev/null)" ]; then
    die "Directory '$INSTALL_DIR' already exists and is not empty."
else
    info "Cloning repository into '$INSTALL_DIR'..."
    $SUDO git clone "$REPO_URL" "$INSTALL_DIR"
    success "Repository cloned"
fi

cd "$INSTALL_DIR"

# ---------------------------------------------------------
# Build Docker image
# ---------------------------------------------------------
echo ""
info "Building Docker image (this may take a minute)..."
$DC build
success "Docker image built"

# ---------------------------------------------------------
# Register agent
# ---------------------------------------------------------
echo ""
echo -e "${BOLD}Agent registration${NC}"
echo "────────────────────────────────────────"
info "Starting registration. Follow the on-screen prompts."
echo ""
$DC run --rm agent --register

echo ""
success "Agent registered"

# ---------------------------------------------------------
# Start service
# ---------------------------------------------------------
echo ""
info "Starting the agent service..."
$DC up -d
success "Agent is running"

# ---------------------------------------------------------
# Summary
# ---------------------------------------------------------
echo ""
echo "────────────────────────────────────────"
echo -e "${GREEN}${BOLD}Installation complete!${NC}"
echo ""
echo "Useful commands (run from '$INSTALL_DIR'):"
echo "  View logs:   $DC logs -f"
echo "  Stop:        $DC down"
echo "  Restart:     $DC restart"
echo ""
