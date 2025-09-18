#!/bin/bash

# Install Required Tools for Secure Data Wiping
# Compatible with Bookworm Puppy Linux

set -e

echo "=================================================="
echo "Installing Required Tools for Data Wiping Solution"
echo "=================================================="

# Update package lists
echo "[INFO] Updating package lists..."
apt-get update

# Essential tools for device detection and wiping
REQUIRED_PACKAGES=(
    "hdparm"           # HDD/SSD management
    "nvme-cli"         # NVMe SSD management
    "gdisk"            # GPT disk partitioning
    "util-linux"       # Contains lsblk, wipefs
    "smartmontools"    # SMART monitoring
    "parted"           # Partition management
    "cryptsetup"       # LUKS encryption detection
    "pciutils"         # lspci for hardware detection
    "usbutils"         # lsusb for USB detection
    "dmidecode"        # Hardware information
    "lshw"             # Hardware lister
    "openssl"          # Certificate generation
    "jq"               # JSON processing
    "curl"             # HTTP requests (if needed)
    "sg3-utils"        # SCSI generic utilities
    "sdparm"           # SCSI disk parameters
    "dc3dd"            # Enhanced dd with hashing
    "shred"            # File shredding utility
)

# Install packages
echo "[INFO] Installing required packages..."
for package in "${REQUIRED_PACKAGES[@]}"; do
    echo "[INFO] Installing $package..."
    if apt-get install -y "$package"; then
        echo "[SUCCESS] $package installed successfully"
    else
        echo "[WARNING] Failed to install $package, continuing..."
    fi
done

# Install additional Python tools if available
echo "[INFO] Installing Python utilities..."
apt-get install -y python3 python3-pip python3-cryptography 2>/dev/null || {
    echo "[WARNING] Python tools not available, skipping..."
}

# Create necessary directories
echo "[INFO] Creating working directories..."
mkdir -p /tmp/secure_wipe
mkdir -p /mnt/usb_cert
mkdir -p /var/log/secure_wipe

# Set permissions
chmod 755 /tmp/secure_wipe
chmod 755 /var/log/secure_wipe

# Download additional utilities if needed
echo "[INFO] Checking for additional utilities..."

# Check if nwipe is available (alternative secure erase tool)
if ! command -v nwipe &> /dev/null; then
    echo "[INFO] nwipe not found, attempting to install..."
    apt-get install -y nwipe 2>/dev/null || {
        echo "[WARNING] nwipe not available in repositories"
    }
fi

# Verify installations
echo ""
echo "=================================================="
echo "Verifying Tool Installations"
echo "=================================================="

TOOLS_TO_CHECK=(
    "hdparm"
    "nvme"
    "gdisk"
    "lsblk"
    "smartctl"
    "parted"
    "cryptsetup"
    "lspci"
    "lsusb"
    "dmidecode"
    "lshw"
    "openssl"
    "jq"
    "sg_sanitize"
    "sdparm"
    "shred"
)

MISSING_TOOLS=()

for tool in "${TOOLS_TO_CHECK[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo "[✓] $tool - Available"
    else
        echo "[✗] $tool - Missing"
        MISSING_TOOLS+=("$tool")
    fi
done

# Summary
echo ""
echo "=================================================="
echo "Installation Summary"
echo "=================================================="

if [ ${#MISSING_TOOLS[@]} -eq 0 ]; then
    echo "[SUCCESS] All required tools are installed!"
    echo ""
    echo "System is ready for secure data wiping operations."
    echo ""
    echo "Next steps:"
    echo "1. Run detection.sh to identify devices"
    echo "2. Run secure_wipe.sh to wipe selected devices"
    echo "3. Run certificate_gen.sh to generate wipe certificates"
else
    echo "[WARNING] Some tools are missing:"
    for tool in "${MISSING_TOOLS[@]}"; do
        echo "  - $tool"
    done
    echo ""
    echo "The system may still function, but some features might be limited."
fi

# Create a system info file
echo "[INFO] Creating system information file..."
cat > /tmp/secure_wipe/system_info.txt << EOF
Secure Data Wiping System Information
=====================================
Installation Date: $(date)
Operating System: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)
Kernel Version: $(uname -r)
Architecture: $(uname -m)

Available Tools:
EOF

for tool in "${TOOLS_TO_CHECK[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo "$tool: $(command -v "$tool")" >> /tmp/secure_wipe/system_info.txt
    fi
done

echo ""
echo "[INFO] System information saved to /tmp/secure_wipe/system_info.txt"
echo "[INFO] Installation completed!"
echo ""
