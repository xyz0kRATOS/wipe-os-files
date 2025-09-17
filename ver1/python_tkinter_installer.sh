#!/bin/bash

# Python & Tkinter Installation Check and Setup for Puppy Linux
# Specifically designed for lightweight Ubuntu-based Puppy Linux variants
# SIH2025 Secure Wipe Tool - Prerequisites Installer

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

print_status() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_header() { echo -e "${PURPLE}[SETUP]${NC} $1"; }

command_exists() { command -v "$1" >/dev/null 2>&1; }

# Function to detect Puppy Linux variant
detect_puppy_variant() {
    print_header "Detecting Puppy Linux variant..."

    PUPPY_INFO=""
    UBUNTU_BASE=false
    PACKAGE_MANAGER=""

    # Check for DISTRO_SPECS (most Puppy variants have this)
    if [ -f /etc/DISTRO_SPECS ]; then
        . /etc/DISTRO_SPECS
        PUPPY_INFO="$DISTRO_NAME $DISTRO_VERSION"
        print_success "Detected: $PUPPY_INFO"

        # Check if Ubuntu-based
        if echo "$DISTRO_NAME" | grep -qi "ubuntu"; then
            UBUNTU_BASE=true
            print_success "Ubuntu-based Puppy detected"
        fi
    elif [ -f /etc/puppyversion ]; then
        PUPPY_INFO=$(cat /etc/puppyversion)
        print_success "Detected: $PUPPY_INFO"

        # Check if Ubuntu-based
        if echo "$PUPPY_INFO" | grep -qi "ubuntu"; then
            UBUNTU_BASE=true
            print_success "Ubuntu-based Puppy detected"
        fi
    else
        print_warning "Could not detect specific Puppy variant"
    fi

    # Detect package managers
    if command_exists apt-get; then
        PACKAGE_MANAGER="apt-get"
        UBUNTU_BASE=true
        print_success "APT package manager detected (Ubuntu base confirmed)"
    elif command_exists pkg; then
        PACKAGE_MANAGER="pkg"
        print_success "PKG package manager detected"
    elif command_exists ppm; then
        PACKAGE_MANAGER="ppm"
        print_success "PPM package manager detected"
    elif command_exists petget; then
        PACKAGE_MANAGER="petget"
        print_success "PETGET package manager detected"
    else
        PACKAGE_MANAGER="manual"
        print_warning "No standard package manager detected - will install manually"
    fi

    echo
    print_status "System Information:"
    echo "  Puppy Variant: $PUPPY_INFO"
    echo "  Ubuntu Base: $([ "$UBUNTU_BASE" = true ] && echo 'Yes' || echo 'No')"
    echo "  Package Manager: $PACKAGE_MANAGER"
    echo "  Architecture: $(uname -m)"
    echo "  Kernel: $(uname -r)"
    echo
}

# Function to check current Python installation
check_python_status() {
    print_header "Checking Python installation status..."

    PYTHON_INSTALLED=false
    PYTHON_VERSION=""
    PYTHON_CMD=""
    TKINTER_AVAILABLE=false
    PIP_AVAILABLE=false

    # Check for Python 3
    if command_exists python3; then
        PYTHON_INSTALLED=true
        PYTHON_CMD="python3"
        PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
        print_success "Python 3 found: $PYTHON_VERSION"
    elif command_exists python; then
        # Check if it's Python 3
        PYTHON_VER=$(python --version 2>&1)
        if echo "$PYTHON_VER" | grep -q "Python 3"; then
            PYTHON_INSTALLED=true
            PYTHON_CMD="python"
            PYTHON_VERSION=$(echo "$PYTHON_VER" | cut -d' ' -f2)
            print_success "Python 3 found: $PYTHON_VERSION"
        else
            print_warning "Only Python 2 found: $PYTHON_VER"
        fi
    else
        print_error "Python not found"
    fi

    # Check Tkinter if Python is available
    if [ "$PYTHON_INSTALLED" = true ]; then
        print_status "Checking Tkinter availability..."

        if $PYTHON_CMD -c "import tkinter; print('Tkinter OK')" 2>/dev/null; then
            TKINTER_AVAILABLE=true
            print_success "Tkinter is available"
        else
            print_error "Tkinter not available"
        fi

        # Check pip
        if command_exists pip3 || command_exists pip; then
            PIP_AVAILABLE=true
            print_success "pip is available"
        else
            print_warning "pip not found"
        fi
    fi

    # Summary
    echo
    print_status "Current Status Summary:"
    echo "  Python 3: $([ "$PYTHON_INSTALLED" = true ] && echo "✅ Installed ($PYTHON_VERSION)" || echo "❌ Not installed")"
    echo "  Tkinter: $([ "$TKINTER_AVAILABLE" = true ] && echo "✅ Available" || echo "❌ Not available")"
    echo "  pip: $([ "$PIP_AVAILABLE" = true ] && echo "✅ Available" || echo "❌ Not available")"
    echo

    # Return status
    if [ "$PYTHON_INSTALLED" = true ] && [ "$TKINTER_AVAILABLE" = true ]; then
        return 0  # All good
    else
        return 1  # Need installation
    fi
}

# Function to update package repositories
update_repositories() {
    print_status "Updating package repositories..."

    case "$PACKAGE_MANAGER" in
        "apt-get")
            print_status "Updating APT repositories..."
            apt-get update || print_warning "APT update failed (continuing anyway)"
            ;;
        "pkg")
            print_status "Updating PKG repositories..."
            pkg update || print_warning "PKG update failed (continuing anyway)"
            ;;
        *)
            print_status "No repository update needed for $PACKAGE_MANAGER"
            ;;
    esac
}

# Function to install Python via package manager
install_python_via_package_manager() {
    print_status "Installing Python via package manager ($PACKAGE_MANAGER)..."

    case "$PACKAGE_MANAGER" in
        "apt-get")
            print_status "Installing Python packages via APT..."

            # Essential packages for Ubuntu-based Puppy
            PACKAGES="python3 python3-dev python3-pip python3-tk python3-setuptools"

            # Try to install all at once
            if apt-get install -y $PACKAGES; then
                print_success "All Python packages installed via APT"
                return 0
            else
                print_warning "Bulk installation failed, trying individual packages..."

                # Try individual packages
                for pkg in $PACKAGES; do
                    if apt-get install -y "$pkg"; then
                        print_success "Installed: $pkg"
                    else
                        print_warning "Failed to install: $pkg"
                    fi
                done
            fi
            ;;

        "pkg")
            print_status "Installing Python packages via PKG..."

            pkg install python3 || print_warning "python3 installation failed"
            pkg install python3-tk || print_warning "python3-tk installation failed"
            pkg install python3-pip || print_warning "python3-pip installation failed"
            ;;

        "ppm")
            print_warning "PPM requires GUI interaction. Please install manually:"
            print_status "1. Open PPM (Puppy Package Manager)"
            print_status "2. Search for and install: python3, python3-tk, python3-pip"
            read -p "Press Enter after installing packages manually..."
            ;;

        *)
            print_warning "Package manager $PACKAGE_MANAGER not supported for automatic installation"
            return 1
            ;;
    esac
}

# Function to install Python manually from source (lightweight method)
install_python_manually() {
    print_warning "Installing Python manually - this may take some time..."

    # Check if we have essential build tools
    if ! command_exists gcc || ! command_exists make; then
        print_error "Build tools not available. Please install gcc and make first."
        print_status "Try: apt-get install build-essential (if APT available)"
        return 1
    fi

    cd /tmp

    # Download portable Python build script
    cat > install_python_portable.sh << 'EOF'
#!/bin/bash
# Portable Python installer for Puppy Linux

PYTHON_VERSION="3.9.18"
PREFIX="/opt/python3"

echo "Downloading Python $PYTHON_VERSION..."
wget -O "Python-$PYTHON_VERSION.tgz" \
    "https://www.python.org/ftp/python/$PYTHON_VERSION/Python-$PYTHON_VERSION.tgz" || {
    echo "Download failed, trying alternative mirror..."
    curl -o "Python-$PYTHON_VERSION.tgz" \
        "https://www.python.org/ftp/python/$PYTHON_VERSION/Python-$PYTHON_VERSION.tgz" || {
        echo "Could not download Python source"
        exit 1
    }
}

echo "Extracting Python..."
tar -xzf "Python-$PYTHON_VERSION.tgz"
cd "Python-$PYTHON_VERSION"

echo "Configuring Python build..."
./configure --prefix="$PREFIX" --enable-optimizations --with-ensurepip=install \
    --enable-shared --enable-ipv6 --with-system-expat --with-system-ffi \
    --enable-loadable-sqlite-extensions || {
    echo "Configure failed, trying minimal configuration..."
    ./configure --prefix="$PREFIX" --with-ensurepip=install
}

echo "Building Python (this will take several minutes)..."
make -j$(nproc) || make

echo "Installing Python..."
make install

# Create symlinks
ln -sf "$PREFIX/bin/python3" /usr/local/bin/python3
ln -sf "$PREFIX/bin/pip3" /usr/local/bin/pip3

# Add to PATH
echo "export PATH=\"$PREFIX/bin:\$PATH\"" >> /etc/profile
echo "export LD_LIBRARY_PATH=\"$PREFIX/lib:\$LD_LIBRARY_PATH\"" >> /etc/profile

echo "Python installation completed!"
EOF

    chmod +x install_python_portable.sh

    print_status "Running Python installation script..."
    if ./install_python_portable.sh; then
        print_success "Python installed manually"

        # Source the profile to get new PATH
        export PATH="/opt/python3/bin:$PATH"
        export LD_LIBRARY_PATH="/opt/python3/lib:$LD_LIBRARY_PATH"

        return 0
    else
        print_error "Manual Python installation failed"
        return 1
    fi
}

# Function to install Tkinter separately if needed
install_tkinter_separately() {
    print_status "Attempting to install Tkinter separately..."

    if [ "$UBUNTU_BASE" = true ]; then
        # For Ubuntu-based Puppy
        if command_exists apt-get; then
            apt-get install -y python3-tk tk-dev || {
                print_warning "Could not install python3-tk via APT"
            }
        fi
    fi

    # Alternative: try to install tkinter via pip
    if command_exists pip3 || command_exists pip; then
        PIP_CMD=$(command_exists pip3 && echo "pip3" || echo "pip")

        print_status "Trying to install tkinter dependencies via pip..."
        $PIP_CMD install --user tk || print_warning "pip tkinter installation failed"
    fi
}

# Function to create a lightweight Tkinter test
test_installation() {
    print_header "Testing Python and Tkinter installation..."

    # Test Python
    if ! command_exists python3 && ! command_exists python; then
        print_error "Python still not available after installation"
        return 1
    fi

    PYTHON_CMD=$(command_exists python3 && echo "python3" || echo "python")

    # Test basic Python
    if ! $PYTHON_CMD -c "print('Python test OK')"; then
        print_error "Python basic test failed"
        return 1
    fi

    print_success "Python basic test passed"

    # Test Tkinter
    print_status "Testing Tkinter..."

    cat > /tmp/tkinter_test.py << 'EOF'
#!/usr/bin/env python3
import sys

try:
    import tkinter as tk
    print("✅ Tkinter import successful")

    # Test basic Tkinter functionality
    root = tk.Tk()
    root.withdraw()  # Hide window

    # Test basic widgets
    label = tk.Label(root, text="Test")
    button = tk.Button(root, text="Test")

    print("✅ Tkinter widgets creation successful")

    root.destroy()
    print("✅ Tkinter test completed successfully")

except ImportError as e:
    print(f"❌ Tkinter import failed: {e}")
    sys.exit(1)
except Exception as e:
    print(f"❌ Tkinter test failed: {e}")
    sys.exit(1)
EOF

    if $PYTHON_CMD /tmp/tkinter_test.py; then
        print_success "Tkinter test passed!"
        rm -f /tmp/tkinter_test.py
        return 0
    else
        print_error "Tkinter test failed"
        rm -f /tmp/tkinter_test.py
        return 1
    fi
}

# Function to install additional Python packages needed for secure wipe tool
install_additional_packages() {
    print_header "Installing additional Python packages for Secure Wipe Tool..."

    # Determine pip command
    PIP_CMD=""
    if command_exists pip3; then
        PIP_CMD="pip3"
    elif command_exists pip; then
        PIP_CMD="pip"
    else
        print_warning "pip not available - skipping additional packages"
        return 1
    fi

    print_status "Using pip command: $PIP_CMD"

    # Essential packages for the secure wipe tool
    PACKAGES=(
        "setuptools"     # Package management
        "wheel"          # Package building
    )

    # Try to install packages
    for package in "${PACKAGES[@]}"; do
        print_status "Installing $package..."

        if $PIP_CMD install --user "$package"; then
            print_success "Installed: $package"
        else
            print_warning "Failed to install: $package (continuing anyway)"
        fi
    done

    print_success "Additional packages installation completed"
}

# Function to create desktop shortcut for testing
create_test_shortcut() {
    print_status "Creating Python/Tkinter test shortcut..."

    # Find desktop directory
    DESKTOP_DIR=""
    for dir in "/root/Desktop" "/home/*/Desktop" "/mnt/home/Desktop"; do
        if [ -d "$dir" ]; then
            DESKTOP_DIR="$dir"
            break
        fi
    done

    if [ -n "$DESKTOP_DIR" ]; then
        # Create test GUI application
        cat > "$DESKTOP_DIR/python_test.py" << 'EOF'
#!/usr/bin/env python3
import tkinter as tk
from tkinter import messagebox
import sys

def show_system_info():
    info = f"""
Python Version: {sys.version}
Python Executable: {sys.executable}
Tkinter Available: Yes

This confirms Python and Tkinter are working correctly
for the SIH2025 Secure Wipe Tool!
    """
    messagebox.showinfo("Python & Tkinter Test", info)

def main():
    root = tk.Tk()
    root.title("Python & Tkinter Test - SIH2025")
    root.geometry("400x200")

    label = tk.Label(root, text="Python & Tkinter Test", font=("Arial", 16))
    label.pack(pady=20)

    button = tk.Button(root, text="Show System Info", command=show_system_info,
                      font=("Arial", 12))
    button.pack(pady=10)

    quit_button = tk.Button(root, text="Quit", command=root.quit,
                           font=("Arial", 12))
    quit_button.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    main()
EOF

        chmod +x "$DESKTOP_DIR/python_test.py"

        # Create .desktop file
        cat > "$DESKTOP_DIR/Python_Test.desktop" << 'EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=Python & Tkinter Test
Comment=Test Python and Tkinter installation
Exec=python3 /root/Desktop/python_test.py
Icon=applications-development
Terminal=false
Categories=Development;
EOF

        chmod +x "$DESKTOP_DIR/Python_Test.desktop"

        print_success "Test application created on desktop"
    else
        print_warning "Could not find desktop directory"
    fi
}

# Function to provide installation summary and next steps
show_summary() {
    print_header "Installation Summary"
    echo

    # Re-check status
    if check_python_status >/dev/null 2>&1; then
        print_success "✅ Python and Tkinter are now properly installed!"
        echo
        print_status "Installation Details:"

        PYTHON_CMD=$(command_exists python3 && echo "python3" || echo "python")
        PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | cut -d' ' -f2)

        echo "  Python Command: $PYTHON_CMD"
        echo "  Python Version: $PYTHON_VERSION"
        echo "  Python Path: $(which $PYTHON_CMD)"
        echo "  Tkinter: Available"
        echo "  pip: $(command_exists pip3 && echo 'pip3' || (command_exists pip && echo 'pip' || echo 'Not available'))"
        echo

        print_status "Next Steps:"
        echo "1. Run the main installer: ./puppy_installer.sh"
        echo "2. Install secure wipe applications"
        echo "3. Test with desktop shortcut (if created)"
        echo

        print_success "System is ready for SIH2025 Secure Wipe Tool installation!"

    else
        print_error "❌ Installation incomplete - some components may be missing"
        echo
        print_status "Troubleshooting:"
        echo "1. Try running this script again"
        echo "2. Install packages manually using your package manager"
        echo "3. Check /tmp/python_install.log for detailed error messages"
        echo

        print_warning "Manual installation commands (if APT available):"
        echo "  sudo apt-get update"
        echo "  sudo apt-get install python3 python3-tk python3-pip"
        echo
    fi
}

# Main installation function
main() {
    echo "============================================="
    echo "Python & Tkinter Installer for Puppy Linux"
    echo "SIH2025 Secure Wipe Tool Prerequisites"
    echo "============================================="
    echo

    # Check if running as root
    if [ "$EUID" -ne 0 ] && [ "$(id -u)" -ne 0 ]; then
        print_error "This script should be run as root for system-wide installation"
        print_status "Run with: sudo $0"
        echo
        read -p "Continue anyway as regular user? (y/N): " continue_anyway
        if [ "$continue_anyway" != "y" ] && [ "$continue_anyway" != "Y" ]; then
            exit 1
        fi
    fi

    # Detect system
    detect_puppy_variant

    # Check current status
    if check_python_status; then
        print_success "Python and Tkinter are already properly installed!"
        read -p "Reinstall anyway? (y/N): " reinstall
        if [ "$reinstall" != "y" ] && [ "$reinstall" != "Y" ]; then
            show_summary
            exit 0
        fi
    fi

    echo
    print_header "Starting installation process..."

    # Update repositories
    update_repositories

    # Try package manager installation first
    if [ "$PACKAGE_MANAGER" != "manual" ]; then
        print_status "Attempting package manager installation..."
        if install_python_via_package_manager; then
            print_success "Package manager installation successful"
        else
            print_warning "Package manager installation failed, trying manual installation..."
            install_python_manually
        fi
    else
        print_status "No package manager available, installing manually..."
        install_python_manually
    fi

    # Check if Tkinter needs separate installation
    if ! python3 -c "import tkinter" 2>/dev/null && ! python -c "import tkinter" 2>/dev/null; then
        install_tkinter_separately
    fi

    # Test installation
    if test_installation; then
        print_success "Installation test passed!"

        # Install additional packages
        install_additional_packages

        # Create test shortcut
        create_test_shortcut

    else
        print_error "Installation test failed!"

        print_status "Trying alternative fixes..."

        # Try some common fixes
        if [ "$UBUNTU_BASE" = true ] && command_exists apt-get; then
            print_status "Trying to fix Ubuntu-based Puppy issues..."
            apt-get install -y --fix-broken 2>/dev/null || true
            apt-get install -y python3-tk tk-dev tcl-dev 2>/dev/null || true

            # Test again
            if test_installation; then
                print_success "Fix successful!"
            fi
        fi
    fi

    # Show final summary
    show_summary
}

# Handle help flag
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "Python & Tkinter Installer for Puppy Linux"
    echo
    echo "This script automatically detects and installs Python 3 and Tkinter"
    echo "on lightweight Ubuntu-based Puppy Linux systems."
    echo
    echo "Usage: $0 [--help]"
    echo
    echo "Features:"
    echo "  • Automatic Puppy variant detection"
    echo "  • Package manager detection and usage"
    echo "  • Fallback manual installation from source"
    echo "  • Tkinter installation and testing"
    echo "  • Desktop test application creation"
    echo
    echo "Supported Package Managers:"
    echo "  • APT (Ubuntu-based Puppy)"
    echo "  • PKG (standard Puppy)"
    echo "  • PPM (Puppy Package Manager)"
    echo "  • Manual source compilation"
    echo
    echo "Run as root for system-wide installation:"
    echo "  sudo $0"
    echo
    exit 0
fi

# Run main installation
main "$@"

