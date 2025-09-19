#!/bin/bash

# install_tools.sh - Install required tools for Secure Data Wiping on Puppy Linux Bookworm
# This script installs all necessary dependencies for the data wiping solution

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
LOG_FILE="/tmp/install_tools.log"
TEMP_DIR="/tmp/install_deps"

# Logging function
log_message() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

print_banner() {
    echo -e "${BLUE}"
    echo "=============================================="
    echo "  Secure Data Wiping Tool - Installation"
    echo "  Compatible with Puppy Linux Bookworm"
    echo "=============================================="
    echo -e "${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run as root${NC}"
        echo "Please run: sudo $0"
        exit 1
    fi
}

# Update package lists
update_packages() {
    log_message "${YELLOW}Updating package lists...${NC}"

    # For Puppy Linux, we might need to use different package managers
    if command -v apt &> /dev/null; then
        apt update
    elif command -v pkg &> /dev/null; then
        pkg update
    else
        log_message "${YELLOW}Package manager not found, proceeding with manual installation${NC}"
    fi
}

# Install core system tools
install_core_tools() {
    log_message "${YELLOW}Installing core system tools...${NC}"

    local tools_apt=("curl" "wget" "jq" "python3" "python3-pip" "build-essential" "git")
    local tools_manual=()

    # Try to install via package manager first
    for tool in "${tools_apt[@]}"; do
        if command -v apt &> /dev/null; then
            if ! dpkg -l | grep -q "^ii  $tool "; then
                apt install -y "$tool" 2>/dev/null || tools_manual+=("$tool")
            fi
        elif command -v pkg &> /dev/null; then
            pkg install -y "$tool" 2>/dev/null || tools_manual+=("$tool")
        else
            tools_manual+=("$tool")
        fi
    done

    # Manual installation for tools that failed
    if [[ ${#tools_manual[@]} -gt 0 ]]; then
        log_message "${YELLOW}Some tools need manual installation: ${tools_manual[*]}${NC}"
        install_manual_tools "${tools_manual[@]}"
    fi
}

# Install storage management tools
install_storage_tools() {
    log_message "${YELLOW}Installing storage management tools...${NC}"

    local storage_tools=("hdparm" "nvme-cli" "gdisk" "parted" "smartmontools" "sg3-utils")

    for tool in "${storage_tools[@]}"; do
        if command -v apt &> /dev/null; then
            apt install -y "$tool" 2>/dev/null || {
                log_message "${RED}Failed to install $tool via apt${NC}"
                install_storage_tool_manual "$tool"
            }
        else
            install_storage_tool_manual "$tool"
        fi
    done
}

# Install specific storage tool manually
install_storage_tool_manual() {
    local tool="$1"
    log_message "${YELLOW}Installing $tool manually...${NC}"

    case "$tool" in
        "hdparm")
            install_hdparm
            ;;
        "nvme-cli")
            install_nvme_cli
            ;;
        "gdisk")
            install_gdisk
            ;;
        "smartmontools")
            install_smartmontools
            ;;
        "sg3-utils")
            install_sg3_utils
            ;;
        *)
            log_message "${RED}Don't know how to manually install $tool${NC}"
            ;;
    esac
}

# Install hdparm from source
install_hdparm() {
    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR"

    wget -q https://sourceforge.net/projects/hdparm/files/hdparm/hdparm-9.65.tar.gz/download -O hdparm-9.65.tar.gz
    tar -xzf hdparm-9.65.tar.gz
    cd hdparm-9.65
    make && make install

    log_message "${GREEN}hdparm installed successfully${NC}"
}

# Install nvme-cli from source
install_nvme_cli() {
    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR"

    git clone https://github.com/linux-nvme/nvme-cli.git
    cd nvme-cli
    make && make install

    log_message "${GREEN}nvme-cli installed successfully${NC}"
}

# Install gdisk from source
install_gdisk() {
    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR"

    wget -q https://sourceforge.net/projects/gptfdisk/files/gptfdisk/1.0.9/gdisk-1.0.9.tar.gz/download -O gdisk-1.0.9.tar.gz
    tar -xzf gdisk-1.0.9.tar.gz
    cd gdisk-1.0.9
    make && make install

    log_message "${GREEN}gdisk installed successfully${NC}"
}

# Install smartmontools from source
install_smartmontools() {
    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR"

    wget -q https://sourceforge.net/projects/smartmontools/files/smartmontools/7.4/smartmontools-7.4.tar.gz/download -O smartmontools-7.4.tar.gz
    tar -xzf smartmontools-7.4.tar.gz
    cd smartmontools-7.4
    ./configure && make && make install

    log_message "${GREEN}smartmontools installed successfully${NC}"
}

# Install sg3-utils from source
install_sg3_utils() {
    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR"

    wget -q https://sg.danny.cz/sg/p/sg3_utils-1.47.tar.xz
    tar -xJf sg3_utils-1.47.tar.xz
    cd sg3_utils-1.47
    ./configure && make && make install

    log_message "${GREEN}sg3-utils installed successfully${NC}"
}

# Install Python dependencies
install_python_deps() {
    log_message "${YELLOW}Installing Python dependencies...${NC}"

    # Install pip if not available
    if ! command -v pip3 &> /dev/null; then
        curl -s https://bootstrap.pypa.io/get-pip.py | python3
    fi

    # Install required Python packages
    pip3 install --upgrade pip
    pip3 install requests supabase cryptography hashlib hmac json-logging psutil
}

# Install GUI framework (Tkinter)
install_gui_deps() {
    log_message "${YELLOW}Installing GUI dependencies...${NC}"

    if command -v apt &> /dev/null; then
        apt install -y python3-tk python3-pil python3-pil.imagetk
    else
        log_message "${YELLOW}GUI dependencies may need manual installation${NC}"
    fi
}

# Create necessary directories
create_directories() {
    log_message "${YELLOW}Creating application directories...${NC}"

    local dirs=(
        "/opt/secure-wipe"
        "/opt/secure-wipe/bin"
        "/opt/secure-wipe/config"
        "/opt/secure-wipe/logs"
        "/opt/secure-wipe/certs"
        "/var/log/secure-wipe"
    )

    for dir in "${dirs[@]}"; do
        mkdir -p "$dir"
        chmod 755 "$dir"
    done

    # Set proper permissions
    chown -R root:root /opt/secure-wipe
    chmod 700 /opt/secure-wipe/config
    chmod 750 /var/log/secure-wipe
}

# Install manual tools (fallback)
install_manual_tools() {
    local tools=("$@")
    log_message "${YELLOW}Manual installation needed for: ${tools[*]}${NC}"

    mkdir -p "$TEMP_DIR"

    for tool in "${tools[@]}"; do
        case "$tool" in
            "jq")
                install_jq_manual
                ;;
            "curl")
                log_message "${RED}curl is essential - please install manually${NC}"
                ;;
            *)
                log_message "${YELLOW}Skipping manual installation of $tool${NC}"
                ;;
        esac
    done
}

# Install jq manually
install_jq_manual() {
    cd "$TEMP_DIR"

    # Determine architecture
    local arch=$(uname -m)
    local jq_arch=""

    case "$arch" in
        "x86_64") jq_arch="linux64" ;;
        "i686"|"i386") jq_arch="linux32" ;;
        "armv7l") jq_arch="linux32" ;;
        "aarch64") jq_arch="linux64" ;;
        *) jq_arch="linux64" ;;
    esac

    wget -q "https://github.com/stedolan/jq/releases/download/jq-1.6/jq-$jq_arch" -O jq
    chmod +x jq
    mv jq /usr/local/bin/

    log_message "${GREEN}jq installed manually${NC}"
}

# Verify installations
verify_installations() {
    log_message "${YELLOW}Verifying installations...${NC}"

    local required_tools=("hdparm" "nvme" "sgdisk" "jq" "python3" "smartctl")
    local missing_tools=()

    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        else
            local version=$($tool --version 2>&1 | head -1 || echo "Version unknown")
            log_message "${GREEN}✓ $tool: $version${NC}"
        fi
    done

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_message "${RED}Missing tools: ${missing_tools[*]}${NC}"
        log_message "${RED}Some features may not work properly${NC}"
        return 1
    else
        log_message "${GREEN}All required tools installed successfully!${NC}"
        return 0
    fi
}

# Show helpful CLI commands
show_cli_commands() {
    echo -e "${BLUE}"
    echo "=============================================="
    echo "  Useful CLI Commands for Puppy Linux"
    echo "=============================================="
    echo -e "${NC}"

    echo -e "${YELLOW}Storage Management:${NC}"
    echo "  lsblk -f                    # List block devices with filesystems"
    echo "  fdisk -l                    # List all disk partitions"
    echo "  hdparm -I /dev/sdX          # Get ATA drive information"
    echo "  smartctl -a /dev/sdX        # SMART drive information"
    echo "  nvme list                   # List NVMe devices"
    echo ""

    echo -e "${YELLOW}System Information:${NC}"
    echo "  uname -a                    # System information"
    echo "  lscpu                       # CPU information"
    echo "  free -h                     # Memory usage"
    echo "  df -h                       # Disk usage"
    echo ""

    echo -e "${YELLOW}Network (for Supabase):${NC}"
    echo "  ping -c 4 supabase.co       # Test connectivity to Supabase"
    echo "  curl -I https://supabase.co # Check HTTPS connectivity"
    echo ""

    echo -e "${YELLOW}Security:${NC}"
    echo "  hdparm --user-master u --security-set-pass p /dev/sdX  # Set ATA password"
    echo "  hdparm --user-master u --security-erase p /dev/sdX     # ATA secure erase"
    echo "  nvme format /dev/nvmeXnY --ses=1                       # NVMe secure erase"
    echo ""
}

# Cleanup temporary files
cleanup() {
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
        log_message "${GREEN}Cleanup completed${NC}"
    fi
}

# Main installation process
main() {
    print_banner

    # Trap to ensure cleanup
    trap cleanup EXIT

    check_root

    log_message "${GREEN}Starting installation process...${NC}"

    # Create temporary directory
    mkdir -p "$TEMP_DIR"

    # Installation steps
    update_packages
    install_core_tools
    install_storage_tools
    install_python_deps
    install_gui_deps
    create_directories

    # Verify everything is installed
    if verify_installations; then
        echo -e "${GREEN}"
        echo "=============================================="
        echo "  Installation completed successfully!"
        echo "=============================================="
        echo -e "${NC}"

        show_cli_commands

        echo -e "${GREEN}"
        echo "Next steps:"
        echo "1. Copy the drive detection and wiping scripts to /opt/secure-wipe/bin/"
        echo "2. Configure your Supabase credentials"
        echo "3. Test the drive detection: ./drive_detection.sh"
        echo -e "${NC}"
    else
        echo -e "${RED}"
        echo "Installation completed with some missing components."
        echo "Please check the log file: $LOG_FILE"
        echo -e "${NC}"
        exit 1
    fi
}

# Execute main function
main "$@"

