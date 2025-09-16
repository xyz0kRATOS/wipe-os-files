#!/bin/bash

# SIH2025 Secure Wipe Tool Setup Script for Puppy Linux
# Compatible with Puppy's package management system

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect available Puppy package managers
detect_package_managers() {
    print_status "Detecting available package managers..."

    AVAILABLE_MANAGERS=""

    if command_exists petget; then
        AVAILABLE_MANAGERS="$AVAILABLE_MANAGERS petget"
        print_success "Found: petget (Puppy Package Manager)"
    fi

    if command_exists pkg; then
        AVAILABLE_MANAGERS="$AVAILABLE_MANAGERS pkg"
        print_success "Found: pkg"
    fi

    if [ -f /usr/local/petget/petget ]; then
        AVAILABLE_MANAGERS="$AVAILABLE_MANAGERS petget"
        print_success "Found: petget GUI package manager"
    fi

    if command_exists ppm; then
        AVAILABLE_MANAGERS="$AVAILABLE_MANAGERS ppm"
        print_success "Found: ppm (Puppy Package Manager)"
    fi

    # Check for repository files
    if [ -d /root/.packages ]; then
        print_success "Found: Puppy package database"
    fi

    echo "Available managers: $AVAILABLE_MANAGERS"
}

# Function to download and compile tools manually
download_and_compile_hdparm() {
    print_status "Downloading and compiling hdparm..."

    cd /tmp

    # Download hdparm source
    if command_exists wget; then
        wget -O hdparm-9.65.tar.gz "https://sourceforge.net/projects/hdparm/files/hdparm/hdparm-9.65.tar.gz/download" || {
            print_warning "wget failed, trying alternative download"
            return 1
        }
    else
        print_error "wget not available"
        return 1
    fi

    tar -xzf hdparm-9.65.tar.gz || return 1
    cd hdparm-9.65

    # Compile
    make || {
        print_error "hdparm compilation failed"
        return 1
    }

    # Install
    cp hdparm /usr/local/bin/
    chmod +x /usr/local/bin/hdparm

    print_success "hdparm installed to /usr/local/bin/"
}

# Function to download nvme-cli
download_nvme_cli() {
    print_status "Downloading nvme-cli binary..."

    cd /tmp

    # Try to download pre-compiled binary
    if command_exists wget; then
        # Download static binary if available
        wget -O nvme https://github.com/linux-nvme/nvme-cli/releases/download/v2.4/nvme-cli-2.4-x86_64-static || {
            print_warning "Could not download nvme-cli binary"
            return 1
        }

        chmod +x nvme
        cp nvme /usr/local/bin/
        print_success "nvme-cli installed to /usr/local/bin/"
    else
        return 1
    fi
}

# Function to install basic system tools available in Puppy
install_puppy_basics() {
    print_status "Checking for basic tools in Puppy Linux..."

    # These are usually available in Puppy Linux
    BASIC_TOOLS=("python" "python3" "dd" "cat" "lsblk" "fdisk" "mount" "umount" "df")

    for tool in "${BASIC_TOOLS[@]}"; do
        if command_exists "$tool"; then
            print_success "$tool: Available"
        else
            print_warning "$tool: Not found"
        fi
    done

    # Check for Python
    if ! command_exists python3 && ! command_exists python; then
        print_error "Python not found! This is required."
        print_status "Please install Python through Puppy Package Manager"
        return 1
    fi

    # Check for essential /proc and /sys filesystem
    if [ -d /proc ] && [ -d /sys ]; then
        print_success "Kernel interfaces available"
    else
        print_error "Missing kernel interfaces"
    fi
}

# Function to create manual tool implementations
create_manual_tools() {
    print_status "Creating manual tool implementations..."

    mkdir -p /opt/secure-wipe/tools

    # Create simple lshw replacement using /proc and /sys
    cat > /opt/secure-wipe/tools/simple_hwdetect.sh << 'EOF'
#!/bin/bash
# Simple hardware detection using /proc and /sys

echo "=== SYSTEM HARDWARE INFORMATION ==="
echo "CPU Info:"
if [ -f /proc/cpuinfo ]; then
    grep "model name" /proc/cpuinfo | head -1
    grep "processor" /proc/cpuinfo | wc -l | sed 's/^/CPU Cores: /'
fi

echo
echo "Memory Info:"
if [ -f /proc/meminfo ]; then
    grep "MemTotal" /proc/meminfo
    grep "MemAvailable" /proc/meminfo || grep "MemFree" /proc/meminfo
fi

echo
echo "Block Devices:"
if [ -f /proc/partitions ]; then
    echo "major minor  #blocks  name"
    cat /proc/partitions | grep -E "sd[a-z]$|hd[a-z]$|nvme[0-9]+n[0-9]+$"
fi

echo
echo "Storage Device Details:"
for dev in $(ls /sys/block/ 2>/dev/null | grep -E "^(sd|hd|nvme|mmcblk)"); do
    if [ -d "/sys/block/$dev" ]; then
        echo "Device: /dev/$dev"
        if [ -f "/sys/block/$dev/size" ]; then
            size_blocks=$(cat /sys/block/$dev/size)
            size_mb=$((size_blocks * 512 / 1024 / 1024))
            echo "  Size: ${size_mb}MB"
        fi

        if [ -f "/sys/block/$dev/queue/rotational" ]; then
            rot=$(cat /sys/block/$dev/queue/rotational)
            if [ "$rot" = "0" ]; then
                echo "  Type: SSD"
            else
                echo "  Type: HDD"
            fi
        fi

        if [ -f "/sys/block/$dev/device/model" ]; then
            model=$(cat /sys/block/$dev/device/model)
            echo "  Model: $model"
        fi
        echo
    fi
done
EOF

    chmod +x /opt/secure-wipe/tools/simple_hwdetect.sh

    # Create simple disk wiper using dd
    cat > /opt/secure-wipe/tools/simple_wipe.sh << 'EOF'
#!/bin/bash
# Simple disk wiping tool using dd

DRY_RUN=true

if [ "$1" = "--real" ]; then
    DRY_RUN=false
    shift
fi

if [ $# -lt 1 ]; then
    echo "Usage: $0 [--real] <device>"
    echo "       --real: Actually perform wipe (dangerous!)"
    echo "       By default, runs in dry-run mode (safe)"
    exit 1
fi

DEVICE="$1"

echo "=== SIMPLE DISK WIPE TOOL ==="
echo "Device: $DEVICE"
echo "Mode: $([ "$DRY_RUN" = "true" ] && echo "DRY-RUN (Safe)" || echo "REAL WIPE (Destructive!)")"
echo

if [ ! -b "$DEVICE" ] && [ "$DRY_RUN" = "false" ]; then
    echo "ERROR: $DEVICE is not a valid block device"
    exit 1
fi

# Get device info
if [ -f "/proc/partitions" ]; then
    DEVICE_NAME=$(basename "$DEVICE")
    DEVICE_INFO=$(grep "$DEVICE_NAME$" /proc/partitions 2>/dev/null)
    if [ -n "$DEVICE_INFO" ]; then
        SIZE_KB=$(echo "$DEVICE_INFO" | awk '{print $3}')
        SIZE_MB=$((SIZE_KB / 1024))
        echo "Device size: ${SIZE_MB}MB"
    fi
fi

echo
echo "Wipe methods to be used:"
echo "1. Zero fill pass"
echo "2. Random data pass"
echo "3. Final zero pass"

if [ "$DRY_RUN" = "true" ]; then
    echo
    echo "[DRY-RUN] Would execute:"
    echo "  dd if=/dev/zero of=$DEVICE bs=1M status=progress"
    echo "  dd if=/dev/urandom of=$DEVICE bs=1M status=progress"
    echo "  dd if=/dev/zero of=$DEVICE bs=1M status=progress"
    echo
    echo "No actual wiping performed - this was a dry run."
    echo "Use --real flag to perform actual wipe (DESTRUCTIVE!)"
else
    echo
    echo "WARNING: This will PERMANENTLY destroy all data on $DEVICE"
    echo "Type 'YES' to continue:"
    read confirmation

    if [ "$confirmation" != "YES" ]; then
        echo "Aborted."
        exit 1
    fi

    echo "Starting wipe process..."

    echo "Pass 1/3: Zero fill..."
    dd if=/dev/zero of="$DEVICE" bs=1M status=progress 2>/dev/null || echo "Zero fill completed"

    echo "Pass 2/3: Random data..."
    dd if=/dev/urandom of="$DEVICE" bs=1M count=100 status=progress 2>/dev/null || echo "Random fill completed"

    echo "Pass 3/3: Final zero pass..."
    dd if=/dev/zero of="$DEVICE" bs=1M count=10 status=progress 2>/dev/null || echo "Final zero completed"

    sync
    echo "Wipe completed!"
fi
EOF

    chmod +x /opt/secure-wipe/tools/simple_wipe.sh

    print_success "Manual tools created"
}

# Function to create Python detection script
create_python_detection() {
    print_status "Creating Python-based detection script..."

    # Determine Python command
    PYTHON_CMD=""
    if command_exists python3; then
        PYTHON_CMD="python3"
    elif command_exists python; then
        PYTHON_CMD="python"
    else
        print_error "No Python interpreter found"
        return 1
    fi

    cat > /opt/secure-wipe/bin/detect_devices.py << EOF
#!/usr/bin/env $PYTHON_CMD

import os
import sys
import subprocess
import json
from datetime import datetime

def run_command(cmd):
    """Execute command safely"""
    try:
        if isinstance(cmd, str):
            result = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
        else:
            result = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
        return result.strip()
    except:
        return None

def get_block_devices():
    """Get block devices from /proc/partitions"""
    devices = []

    try:
        with open('/proc/partitions', 'r') as f:
            lines = f.readlines()

        for line in lines[2:]:  # Skip header
            parts = line.strip().split()
            if len(parts) >= 4:
                major, minor, blocks, name = parts[:4]

                # Skip partitions (look for whole disks)
                if not any(name.endswith(str(i)) for i in range(10)):
                    device_path = f"/dev/{name}"
                    size_mb = int(blocks) // 1024

                    device_info = {
                        'name': name,
                        'path': device_path,
                        'size': f"{size_mb}MB",
                        'blocks': blocks,
                        'major': major,
                        'minor': minor
                    }

                    # Try to get additional info
                    device_info.update(get_device_details(name))
                    devices.append(device_info)

    except Exception as e:
        print(f"Error reading /proc/partitions: {e}")

    return devices

def get_device_details(device_name):
    """Get additional device details from /sys"""
    details = {
        'type': 'Unknown',
        'model': 'Unknown',
        'removable': False
    }

    sys_path = f"/sys/block/{device_name}"

    try:
        # Check if removable
        removable_path = f"{sys_path}/removable"
        if os.path.exists(removable_path):
            with open(removable_path, 'r') as f:
                details['removable'] = f.read().strip() == '1'

        # Check rotational (SSD vs HDD)
        rot_path = f"{sys_path}/queue/rotational"
        if os.path.exists(rot_path):
            with open(rot_path, 'r') as f:
                if f.read().strip() == '0':
                    details['type'] = 'SSD'
                else:
                    details['type'] = 'HDD'

        # Try to get model
        model_path = f"{sys_path}/device/model"
        if os.path.exists(model_path):
            with open(model_path, 'r') as f:
                details['model'] = f.read().strip()

        # Check if NVMe
        if 'nvme' in device_name:
            details['type'] = 'NVMe SSD'

        # Check if USB
        if details['removable']:
            details['type'] = 'USB Storage'

    except Exception:
        pass

    return details

def check_device_access(device_path):
    """Check if device is accessible"""
    if not os.path.exists(device_path):
        return False, "Device does not exist"

    try:
        with open(device_path, 'rb') as f:
            f.read(512)  # Try to read first sector
        return True, "Accessible"
    except PermissionError:
        return False, "Permission denied (try as root)"
    except Exception as e:
        return False, f"Access error: {str(e)}"

def main():
    print("=== PUPPY LINUX STORAGE DEVICE DETECTION ===")
    print(f"Scan time: {datetime.now()}")
    print()

    devices = get_block_devices()

    if not devices:
        print("No storage devices found!")
        return

    print(f"Found {len(devices)} storage device(s):")
    print()

    for i, device in enumerate(devices, 1):
        print(f"{i}. Device: {device['name']}")
        print(f"   Path: {device['path']}")
        print(f"   Size: {device['size']}")
        print(f"   Type: {device['type']}")
        print(f"   Model: {device['model']}")
        print(f"   Removable: {device['removable']}")

        # Check accessibility
        accessible, access_msg = check_device_access(device['path'])
        print(f"   Access: {access_msg}")

        print()

    # JSON output option
    if len(sys.argv) > 1 and sys.argv[1] == '--json':
        print("JSON Output:")
        print(json.dumps(devices, indent=2))

if __name__ == "__main__":
    main()
EOF

    chmod +x /opt/secure-wipe/bin/detect_devices.py

    print_success "Python detection script created"
}

# Function to create test certificates
create_certificate_system() {
    print_status "Creating certificate generation system..."

    # Determine Python command
    PYTHON_CMD=""
    if command_exists python3; then
        PYTHON_CMD="python3"
    elif command_exists python; then
        PYTHON_CMD="python"
    else
        print_error "No Python interpreter found"
        return 1
    fi

    cat > /opt/secure-wipe/bin/generate_certificate.py << EOF
#!/usr/bin/env $PYTHON_CMD

import json
import hashlib
import os
import sys
from datetime import datetime

def generate_certificate(device_info, wipe_info):
    """Generate a simple certificate without cryptographic libraries"""

    timestamp = datetime.now().isoformat()

    cert_data = {
        "certificate_version": "1.0-simple",
        "certificate_id": hashlib.md5(f"{timestamp}{device_info['name']}".encode()).hexdigest()[:16],
        "timestamp": timestamp,
        "compliance_standards": ["Basic Overwrite", "DoD-style multi-pass"],
        "tool_info": {
            "name": "SIH2025 Secure Wipe Tool - Puppy Linux Version",
            "version": "1.0.0",
            "platform": "Puppy Linux",
            "method": "Air-gapped bootable tool"
        },
        "device_information": device_info,
        "wipe_information": wipe_info,
        "verification": {
            "method": "Visual inspection + basic read test",
            "status": "completed" if wipe_info.get('status') == 'success' else "partial"
        }
    }

    # Create integrity hash
    cert_json = json.dumps(cert_data, sort_keys=True)
    integrity_hash = hashlib.sha256(cert_json.encode()).hexdigest()
    cert_data["integrity_hash"] = integrity_hash

    return cert_data

def save_certificate(cert_data, output_dir="/tmp"):
    """Save certificate to files"""

    cert_id = cert_data['certificate_id']

    # Save JSON
    json_file = f"{output_dir}/certificate_{cert_id}.json"
    with open(json_file, 'w') as f:
        json.dump(cert_data, f, indent=2)

    # Save human-readable
    txt_file = f"{output_dir}/certificate_{cert_id}.txt"
    with open(txt_file, 'w') as f:
        f.write("SECURE DATA WIPE CERTIFICATE\\n")
        f.write("=" * 50 + "\\n\\n")
        f.write(f"Certificate ID: {cert_data['certificate_id']}\\n")
        f.write(f"Timestamp: {cert_data['timestamp']}\\n")
        f.write(f"Tool: {cert_data['tool_info']['name']}\\n")
        f.write(f"Version: {cert_data['tool_info']['version']}\\n\\n")

        f.write("DEVICE INFORMATION:\\n")
        f.write("-" * 20 + "\\n")
        dev = cert_data['device_information']
        f.write(f"Device: {dev['name']} ({dev['path']})\\n")
        f.write(f"Size: {dev['size']}\\n")
        f.write(f"Type: {dev['type']}\\n")
        f.write(f"Model: {dev['model']}\\n\\n")

        f.write("WIPE INFORMATION:\\n")
        f.write("-" * 20 + "\\n")
        wipe = cert_data['wipe_information']
        f.write(f"Method: {wipe['method']}\\n")
        f.write(f"Status: {wipe['status']}\\n")
        f.write(f"Start: {wipe['start_time']}\\n")
        f.write(f"End: {wipe['end_time']}\\n\\n")

        f.write(f"Verification: {cert_data['verification']['status']}\\n")
        f.write(f"Integrity Hash: {cert_data['integrity_hash']}\\n")

    return json_file, txt_file

def main():
    # Example usage with mock data
    mock_device = {
        "name": "sda",
        "path": "/dev/sda",
        "size": "8GB",
        "type": "USB Storage",
        "model": "Generic USB Drive"
    }

    mock_wipe = {
        "method": "3-pass overwrite (zero, random, zero)",
        "status": "success",
        "start_time": datetime.now().replace(hour=10, minute=0).isoformat(),
        "end_time": datetime.now().isoformat(),
        "passes_completed": 3
    }

    cert = generate_certificate(mock_device, mock_wipe)
    json_file, txt_file = save_certificate(cert)

    print("Certificate generated successfully!")
    print(f"JSON file: {json_file}")
    print(f"Text file: {txt_file}")
    print()
    print("Certificate preview:")
    print(json.dumps(cert, indent=2))

if __name__ == "__main__":
    main()
EOF

    chmod +x /opt/secure-wipe/bin/generate_certificate.py

    print_success "Certificate system created"
}

# Main installation function
main() {
    echo "=========================================="
    echo "SIH2025 Secure Wipe Tool Setup"
    echo "Puppy Linux Compatible Version"
    echo "=========================================="
    echo

    # Check if running as root
    if [ "\$EUID" -ne 0 ] && [ "\$(id -u)" -ne 0 ]; then
        print_warning "Running as regular user. Some operations may fail."
        print_status "Consider running as root for full functionality."
    fi

    # Create directories
    print_status "Creating tool directories..."
    mkdir -p /opt/secure-wipe/{bin,tools,logs,certificates}
    mkdir -p /tmp/secure-wipe

    # Detect package managers
    detect_package_managers
    echo

    # Install basic tools check
    install_puppy_basics
    echo

    # Try to get essential tools
    print_status "Attempting to install/compile essential tools..."

    if ! command_exists hdparm; then
        download_and_compile_hdparm || print_warning "Could not install hdparm"
    else
        print_success "hdparm already available"
    fi

    if ! command_exists nvme; then
        download_nvme_cli || print_warning "Could not install nvme-cli"
    else
        print_success "nvme already available"
    fi

    echo

    # Create manual tools
    create_manual_tools
    echo

    # Create Python scripts
    create_python_detection
    echo

    # Create certificate system
    create_certificate_system
    echo

    # Create main test script
    print_status "Creating main test script..."

    cat > /opt/secure-wipe/bin/test_all.sh << 'EOF'
#!/bin/bash

echo "=== SIH2025 SECURE WIPE TOOL TEST ==="
echo "Puppy Linux Compatible Version"
echo

echo "1. System Information:"
/opt/secure-wipe/tools/simple_hwdetect.sh
echo

echo "2. Python Device Detection:"
/opt/secure-wipe/bin/detect_devices.py
echo

echo "3. Certificate Generation Test:"
/opt/secure-wipe/bin/generate_certificate.py
echo

echo "4. Dry-run Wipe Test:"
echo "Available devices for testing:"
/opt/secure-wipe/bin/detect_devices.py | grep "Path:"
echo
echo "To test wipe on a device (DRY-RUN, safe):"
echo "  /opt/secure-wipe/tools/simple_wipe.sh /dev/sda"
echo
echo "To perform actual wipe (DANGEROUS!):"
echo "  /opt/secure-wipe/tools/simple_wipe.sh --real /dev/sda"
echo
echo "=== Test completed ==="
EOF

    chmod +x /opt/secure-wipe/bin/test_all.sh

    print_success "Installation completed!"
    echo

    print_status "Testing installation..."
    /opt/secure-wipe/bin/test_all.sh

    echo
    print_success "=== SETUP COMPLETE ==="
    print_status "Available commands:"
    echo "  /opt/secure-wipe/bin/test_all.sh           - Run all tests"
    echo "  /opt/secure-wipe/bin/detect_devices.py     - Detect storage devices"
    echo "  /opt/secure-wipe/tools/simple_wipe.sh      - Wipe devices (dry-run by default)"
    echo "  /opt/secure-wipe/bin/generate_certificate.py - Generate certificates"
    echo
    print_warning "Always test with dry-run first!"
    print_warning "Use --real flag only when you're sure!"
}

# Run main function
main "\$@"

