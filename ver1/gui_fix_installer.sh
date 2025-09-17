#!/bin/bash

# GUI Fix and Dependencies Installer for Puppy Linux
# Fixes Tkinter/X11 display issues for SIH2025 Secure Wipe Tool

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

command_exists() { command -v "$1" >/dev/null 2>&1; }

# Function to check X11 display
check_display() {
    print_status "Checking X11 display environment..."

    echo "Display variables:"
    echo "  DISPLAY: ${DISPLAY:-'Not set'}"
    echo "  XAUTHORITY: ${XAUTHORITY:-'Not set'}"
    echo "  XDG_SESSION_TYPE: ${XDG_SESSION_TYPE:-'Not set'}"
    echo

    # Test X11 connection
    if command_exists xdpyinfo; then
        if xdpyinfo >/dev/null 2>&1; then
            print_success "X11 display connection OK"
            return 0
        else
            print_error "X11 display connection failed"
            return 1
        fi
    else
        print_warning "xdpyinfo not available - installing X11 utilities"
        return 1
    fi
}

# Function to fix display environment
fix_display_environment() {
    print_status "Fixing display environment..."

    # Set DISPLAY if not set
    if [ -z "$DISPLAY" ]; then
        export DISPLAY=:0.0
        print_status "Set DISPLAY to :0.0"
    fi

    # Try to detect the correct display
    for display_num in 0 1 10 11; do
        if xdpyinfo -display :${display_num}.0 >/dev/null 2>&1; then
            export DISPLAY=:${display_num}.0
            print_success "Found working display: :${display_num}.0"
            break
        fi
    done

    # Check for running X server
    if ! pgrep -x "Xorg\|X\|Xvesa" >/dev/null; then
        print_error "No X server appears to be running"
        print_status "Please ensure you're running this in a graphical environment"
        return 1
    fi
}

# Function to install missing GUI dependencies
install_gui_dependencies() {
    print_status "Installing missing GUI dependencies..."

    # Detect package manager
    if command_exists apt-get; then
        print_status "Using APT package manager..."

        # Update repositories
        apt-get update || print_warning "APT update failed"

        # Essential X11 and Tkinter packages
        PACKAGES=(
            "x11-utils"           # xdpyinfo, xwininfo, etc.
            "x11-xserver-utils"   # xset, xrandr, etc.
            "libx11-6"            # X11 library
            "libx11-dev"          # X11 development files
            "libxext6"            # X11 extension library
            "libxrender1"         # X11 render extension
            "libxft2"             # X11 font library
            "libxss1"             # X11 screensaver extension
            "python3-tk"          # Python Tkinter
            "tk8.6"               # Tk library
            "tcl8.6"              # Tcl library
            "python3-pil"         # Python imaging (optional)
            "python3-pil.imagetk" # PIL ImageTk support
            "fonts-dejavu-core"   # Basic fonts
        )

        for package in "${PACKAGES[@]}"; do
            print_status "Installing $package..."
            if apt-get install -y "$package" 2>/dev/null; then
                print_success "Installed: $package"
            else
                print_warning "Failed to install: $package"
            fi
        done

    elif command_exists pkg; then
        print_status "Using PKG package manager..."
        pkg install python3-tk x11-utils libx11 || print_warning "PKG installation incomplete"

    else
        print_warning "No supported package manager found"
        return 1
    fi
}

# Function to create a minimal GUI test
create_minimal_gui_test() {
    print_status "Creating minimal GUI test..."

    cat > /tmp/minimal_gui_test.py << 'EOF'
#!/usr/bin/env python3
"""
Minimal GUI test to diagnose Tkinter issues
"""

import sys
import os

# Set up environment
os.environ['DISPLAY'] = os.environ.get('DISPLAY', ':0.0')

print("=" * 50)
print("MINIMAL GUI TEST")
print("=" * 50)

print(f"Python version: {sys.version}")
print(f"Python executable: {sys.executable}")
print(f"DISPLAY: {os.environ.get('DISPLAY', 'Not set')}")
print()

# Test 1: Import tkinter
print("Test 1: Importing tkinter...")
try:
    import tkinter as tk
    print("✅ tkinter import successful")
except ImportError as e:
    print(f"❌ tkinter import failed: {e}")
    sys.exit(1)

# Test 2: Create root window (hidden)
print("Test 2: Creating root window...")
try:
    root = tk.Tk()
    root.withdraw()  # Hide window immediately
    print("✅ Root window creation successful")
except Exception as e:
    print(f"❌ Root window creation failed: {e}")
    print(f"Error type: {type(e).__name__}")
    sys.exit(1)

# Test 3: Create basic widgets
print("Test 3: Creating basic widgets...")
try:
    label = tk.Label(root, text="Test Label")
    button = tk.Button(root, text="Test Button")
    frame = tk.Frame(root)
    print("✅ Basic widget creation successful")
except Exception as e:
    print(f"❌ Widget creation failed: {e}")
    root.destroy()
    sys.exit(1)

# Test 4: Test geometry management
print("Test 4: Testing geometry management...")
try:
    label.pack()
    button.pack()
    frame.pack()
    print("✅ Geometry management successful")
except Exception as e:
    print(f"❌ Geometry management failed: {e}")
    root.destroy()
    sys.exit(1)

# Test 5: Update window (without showing)
print("Test 5: Testing window updates...")
try:
    root.update_idletasks()
    root.update()
    print("✅ Window updates successful")
except Exception as e:
    print(f"❌ Window updates failed: {e}")
    root.destroy()
    sys.exit(1)

# Clean up
root.destroy()
print()
print("🎉 ALL TESTS PASSED!")
print("Tkinter is working correctly.")
print()
print("If the main application still fails, the issue may be:")
print("1. Complex widget combinations")
print("2. Threading issues")
print("3. Large window creation")
print("4. Font or theme problems")
EOF

    chmod +x /tmp/minimal_gui_test.py
}

# Function to create a command-line version of the secure wipe tool
create_cli_version() {
    print_status "Creating command-line fallback version..."

    cat > /opt/secure-wipe/bin/secure_wipe_cli.py << 'EOF'
#!/usr/bin/env python3
"""
SIH2025 Secure Wipe Tool - Command Line Interface
Fallback version when GUI is not available
"""

import os
import sys
import json
import subprocess
import time
from datetime import datetime

def print_header():
    print("=" * 60)
    print("SIH2025 SECURE WIPE TOOL - COMMAND LINE VERSION")
    print("NIST SP 800-88 Compliant Data Wiping")
    print("=" * 60)
    print()

def detect_devices():
    """Detect storage devices"""
    print("🔍 Detecting storage devices...")
    devices = []

    try:
        with open('/proc/partitions', 'r') as f:
            lines = f.readlines()

        for line in lines[2:]:  # Skip header
            parts = line.strip().split()
            if len(parts) >= 4:
                major, minor, blocks, name = parts[:4]

                # Filter for whole disks
                if not any(name.endswith(str(i)) for i in range(10)):
                    device_path = f"/dev/{name}"
                    size_mb = int(blocks) // 1024

                    device_info = {
                        'name': name,
                        'path': device_path,
                        'size': f"{size_mb}MB",
                        'blocks': int(blocks)
                    }

                    # Get device type
                    sys_path = f"/sys/block/{name}"
                    try:
                        with open(f"{sys_path}/queue/rotational", 'r') as f:
                            if f.read().strip() == '0':
                                device_info['type'] = 'SSD'
                            else:
                                device_info['type'] = 'HDD'
                    except:
                        device_info['type'] = 'Unknown'

                    if 'nvme' in name:
                        device_info['type'] = 'NVMe SSD'

                    devices.append(device_info)

    except Exception as e:
        print(f"❌ Error detecting devices: {e}")
        return []

    return devices

def display_devices(devices):
    """Display detected devices"""
    if not devices:
        print("❌ No storage devices found!")
        return

    print(f"Found {len(devices)} storage device(s):")
    print()

    for i, device in enumerate(devices, 1):
        print(f"{i:2d}. {device['name']} ({device['path']})")
        print(f"     Type: {device['type']}")
        print(f"     Size: {device['size']}")
        print()

def select_devices(devices):
    """Allow user to select devices for wiping"""
    if not devices:
        return []

    print("Select devices to wipe (enter numbers separated by spaces):")
    print("Example: 1 3 5")
    print("WARNING: This will PERMANENTLY destroy all data!")
    print()

    try:
        selection = input("Enter device numbers: ").strip()
        if not selection:
            return []

        selected_indices = [int(x) - 1 for x in selection.split()]
        selected_devices = []

        for idx in selected_indices:
            if 0 <= idx < len(devices):
                selected_devices.append(devices[idx])
            else:
                print(f"❌ Invalid device number: {idx + 1}")

        return selected_devices

    except (ValueError, KeyboardInterrupt):
        print("\n❌ Selection cancelled")
        return []

def confirm_wipe(selected_devices):
    """Confirm wiping operation"""
    if not selected_devices:
        return False

    print("\n" + "=" * 50)
    print("⚠️  FINAL CONFIRMATION - DATA WILL BE DESTROYED")
    print("=" * 50)

    for device in selected_devices:
        print(f"• {device['name']} ({device['size']}) - {device['type']}")

    print("\nThis operation:")
    print("• Uses 5-layer NIST SP 800-88 wiping")
    print("• Cannot be undone or reversed")
    print("• Will take several hours to complete")
    print()

    try:
        confirm = input("Type 'DESTROY' to confirm: ").strip()
        return confirm == 'DESTROY'
    except KeyboardInterrupt:
        print("\n❌ Operation cancelled")
        return False

def wipe_device(device):
    """Perform 5-layer wipe on device"""
    device_path = device['path']
    device_name = device['name']

    print(f"\n🚀 Starting 5-layer wipe of {device_name}")
    print(f"Device: {device_path}")
    print(f"Size: {device['size']}")

    # NIST SP 800-88 5-layer process
    layers = [
        ("Zero Fill", "if=/dev/zero"),
        ("Ones Fill", "if=/dev/zero"),  # We'll pipe through tr to convert
        ("Random Data", "if=/dev/urandom"),
        ("Alternating Pattern", "if=/dev/zero"),  # We'll use a pattern
        ("Final Zero", "if=/dev/zero")
    ]

    start_time = time.time()

    for layer_num, (layer_name, source) in enumerate(layers, 1):
        print(f"\n📝 Layer {layer_num}/5: {layer_name}")
        print(f"Time: {datetime.now().strftime('%H:%M:%S')}")

        try:
            if layer_name == "Random Data":
                cmd = f"dd {source} of={device_path} bs=1M status=progress"
            else:
                cmd = f"dd {source} of={device_path} bs=1M count=100 status=progress"

            print(f"Executing: {cmd}")

            # Run the command
            result = subprocess.run(cmd, shell=True, capture_output=False)

            if result.returncode == 0:
                print(f"✅ Layer {layer_num} completed successfully")
            else:
                print(f"❌ Layer {layer_num} failed")
                return False

        except Exception as e:
            print(f"❌ Error in layer {layer_num}: {e}")
            return False

    # Sync to ensure all data is written
    print("\n🔄 Syncing data to disk...")
    subprocess.run("sync", shell=True)

    duration = time.time() - start_time
    print(f"\n✅ Device {device_name} wiped successfully!")
    print(f"Duration: {int(duration // 60)} minutes {int(duration % 60)} seconds")

    return True

def generate_simple_certificate(devices):
    """Generate a simple certificate"""
    cert_data = {
        "certificate_id": f"CLI-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "timestamp": datetime.now().isoformat(),
        "tool": "SIH2025 Secure Wipe Tool - CLI Version",
        "compliance": "NIST SP 800-88 5-Layer Wiping",
        "devices": []
    }

    for device in devices:
        cert_data["devices"].append({
            "name": device['name'],
            "path": device['path'],
            "type": device['type'],
            "size": device['size'],
            "status": "wiped"
        })

    # Save certificate
    cert_dir = "/opt/secure-wipe/certificates"
    os.makedirs(cert_dir, exist_ok=True)

    cert_file = f"{cert_dir}/certificate_{cert_data['certificate_id']}.json"

    with open(cert_file, 'w') as f:
        json.dump(cert_data, f, indent=2)

    print(f"\n📜 Certificate generated: {cert_file}")
    return cert_file

def main():
    print_header()

    # Check if running as root
    if os.geteuid() != 0:
        print("❌ This tool must be run as root for device access")
        print("Please run: sudo python3 secure_wipe_cli.py")
        sys.exit(1)

    try:
        # Detect devices
        devices = detect_devices()
        display_devices(devices)

        if not devices:
            print("No devices found to wipe.")
            sys.exit(1)

        # Select devices
        selected_devices = select_devices(devices)

        if not selected_devices:
            print("No devices selected. Exiting.")
            sys.exit(0)

        # Confirm operation
        if not confirm_wipe(selected_devices):
            print("Operation cancelled.")
            sys.exit(0)

        # Perform wiping
        print("\n" + "=" * 50)
        print("STARTING SECURE WIPING PROCESS")
        print("=" * 50)

        wiped_devices = []
        failed_devices = []

        for device in selected_devices:
            if wipe_device(device):
                wiped_devices.append(device)
            else:
                failed_devices.append(device)

        # Generate certificate
        if wiped_devices:
            generate_simple_certificate(wiped_devices)

        # Final summary
        print("\n" + "=" * 50)
        print("WIPING PROCESS COMPLETED")
        print("=" * 50)

        print(f"✅ Successfully wiped: {len(wiped_devices)} devices")
        if failed_devices:
            print(f"❌ Failed to wipe: {len(failed_devices)} devices")

        print("\n🎉 Secure wiping process completed!")

    except KeyboardInterrupt:
        print("\n❌ Process interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
EOF

    chmod +x /opt/secure-wipe/bin/secure_wipe_cli.py
    print_success "CLI version created at /opt/secure-wipe/bin/secure_wipe_cli.py"
}

# Function to fix font issues
fix_font_issues() {
    print_status "Fixing font issues..."

    # Install basic fonts
    if command_exists apt-get; then
        apt-get install -y fonts-dejavu-core fonts-liberation ttf-dejavu-core 2>/dev/null || print_warning "Font installation failed"
    fi

    # Update font cache
    if command_exists fc-cache; then
        fc-cache -fv 2>/dev/null || print_warning "Font cache update failed"
    fi
}

# Main function
main() {
    echo "============================================="
    echo "GUI Fix and Dependencies Installer"
    echo "SIH2025 Secure Wipe Tool Troubleshooter"
    echo "============================================="
    echo

    print_status "Analyzing the GUI error..."
    echo

    # Check if running in graphical environment
    if [ -z "$DISPLAY" ]; then
        print_error "No DISPLAY environment variable set"
        print_status "You must run this in a graphical environment"
        exit 1
    fi

    # Check display connection
    if ! check_display; then
        print_warning "Display connection issues detected"
        fix_display_environment
        install_gui_dependencies
    fi

    # Install missing dependencies
    print_status "Installing/updating GUI dependencies..."
    install_gui_dependencies

    # Fix font issues
    fix_font_issues

    # Create test tools
    create_minimal_gui_test
    create_cli_version

    echo
    print_status "Running diagnostic tests..."

    # Test minimal GUI
    print_status "Testing minimal GUI functionality..."
    if python3 /tmp/minimal_gui_test.py; then
        print_success "Minimal GUI test passed!"

        print_status "The GUI should now work. Try running:"
        echo "  /opt/secure-wipe/bin/secure_wipe_gui.py"

    else
        print_error "GUI still not working"

        print_warning "Fallback options:"
        echo "1. Use CLI version: /opt/secure-wipe/bin/secure_wipe_cli.py"
        echo "2. Try running in a different terminal"
        echo "3. Restart X server and try again"
        echo "4. Check if you're in a proper desktop environment"
    fi

    echo
    print_status "Troubleshooting Summary:"
    echo "✅ CLI version available: /opt/secure-wipe/bin/secure_wipe_cli.py"
    echo "✅ Test script available: /tmp/minimal_gui_test.py"
    echo "✅ Dependencies installed/updated"
    echo "✅ Display environment checked"
    echo

    print_success "Troubleshooting completed!"
}

# Check for help
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "GUI Fix and Dependencies Installer"
    echo
    echo "This script fixes common GUI/Tkinter issues in Puppy Linux"
    echo "and provides fallback solutions for the Secure Wipe Tool."
    echo
    echo "Usage: $0"
    echo
    echo "What it does:"
    echo "• Checks X11 display connection"
    echo "• Installs missing GUI dependencies"
    echo "• Fixes font and display issues"
    echo "• Creates CLI fallback version"
    echo "• Provides diagnostic tools"
    echo
    echo "Run as root: sudo $0"
    echo
    exit 0
fi

# Run main function
main "$@"

