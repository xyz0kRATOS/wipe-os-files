#!/bin/bash

# startup.sh - Main startup script for Secure Data Wipe Tool
# This script initializes and starts all components of the system

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/secure-wipe"
LOG_DIR="/var/log/secure-wipe"
PID_FILE="/tmp/secure-wipe-backend.pid"
BACKEND_PORT=8000

# Logging function
log_message() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_DIR/startup.log"
}

print_banner() {
    clear
    echo -e "${BLUE}"
    echo "=========================================="
    echo "  Secure Data Wipe Tool"
    echo "  NIST 800-88 Rev. 1 Compliant"
    echo "  Bootable Puppy Linux Version"
    echo "=========================================="
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

# Check system requirements
check_requirements() {
    log_message "${YELLOW}Checking system requirements...${NC}"

    local missing_tools=()
    local required_tools=("python3" "hdparm" "nvme" "lsblk" "jq")

    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_message "${RED}Missing required tools: ${missing_tools[*]}${NC}"
        log_message "${YELLOW}Please run the installation script first: ./install_tools.sh${NC}"
        exit 1
    fi

    log_message "${GREEN}All requirements satisfied${NC}"
}

# Setup environment
setup_environment() {
    log_message "${YELLOW}Setting up environment...${NC}"

    # Create necessary directories
    mkdir -p "$LOG_DIR"
    mkdir -p "$INSTALL_DIR/bin"
    mkdir -p "$INSTALL_DIR/config"
    mkdir -p "$INSTALL_DIR/certs"

    # Set environment variables
    export PYTHONPATH="$INSTALL_DIR/bin:$PYTHONPATH"
    export PATH="$INSTALL_DIR/bin:$PATH"

    # Copy scripts to install directory if they don't exist
    if [[ ! -f "$INSTALL_DIR/bin/drive_detection.sh" ]]; then
        log_message "Copying scripts to installation directory..."
        # These would be copied from the current directory
        cp drive_detection.sh "$INSTALL_DIR/bin/" 2>/dev/null || true
        cp secure_wipe_core.py "$INSTALL_DIR/bin/" 2>/dev/null || true
        cp certificate_manager.py "$INSTALL_DIR/bin/" 2>/dev/null || true
        cp backend_server.py "$INSTALL_DIR/bin/" 2>/dev/null || true
        cp gui_frontend.py "$INSTALL_DIR/bin/" 2>/dev/null || true

        # Make scripts executable
        chmod +x "$INSTALL_DIR/bin/"*.sh
        chmod +x "$INSTALL_DIR/bin/"*.py
    fi

    log_message "${GREEN}Environment setup complete${NC}"
}

# Configure Supabase (if credentials provided)
setup_supabase() {
    log_message "${YELLOW}Configuring Supabase connection...${NC}"

    # Check for environment variables or config file
    if [[ -n "${SUPABASE_URL:-}" && -n "${SUPABASE_KEY:-}" ]]; then
        log_message "${GREEN}Supabase credentials found in environment${NC}"
        export SUPABASE_URL
        export SUPABASE_KEY
    elif [[ -f "$INSTALL_DIR/config/supabase.conf" ]]; then
        log_message "Loading Supabase credentials from config file..."
        source "$INSTALL_DIR/config/supabase.conf"
        export SUPABASE_URL
        export SUPABASE_KEY
        log_message "${GREEN}Supabase credentials loaded from config${NC}"
    else
        log_message "${YELLOW}No Supabase credentials found - running in offline mode${NC}"
        log_message "${YELLOW}Certificates will be stored locally only${NC}"
    fi
}

# Start backend server
start_backend() {
    log_message "${YELLOW}Starting backend server...${NC}"

    # Check if backend is already running
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            log_message "${GREEN}Backend server already running (PID: $pid)${NC}"
            return 0
        else
            log_message "Removing stale PID file..."
            rm -f "$PID_FILE"
        fi
    fi

    # Start backend server
    cd "$INSTALL_DIR/bin"
    nohup python3 backend_server.py > "$LOG_DIR/backend.log" 2>&1 &
    local backend_pid=$!

    echo "$backend_pid" > "$PID_FILE"

    # Wait for backend to start
    local attempts=0
    local max_attempts=30

    while [[ $attempts -lt $max_attempts ]]; do
        if curl -s "http://localhost:$BACKEND_PORT/api/health" > /dev/null 2>&1; then
            log_message "${GREEN}Backend server started successfully (PID: $backend_pid)${NC}"
            return 0
        fi

        sleep 1
        ((attempts++))
    done

    log_message "${RED}Failed to start backend server${NC}"
    return 1
}

# Start GUI
start_gui() {
    log_message "${YELLOW}Starting GUI application...${NC}"

    # Check if DISPLAY is set (for X11)
    if [[ -z "${DISPLAY:-}" ]]; then
        log_message "${YELLOW}No DISPLAY environment variable - starting X server${NC}"

        # Try to start X server (Puppy Linux specific)
        if command -v startx &> /dev/null; then
            log_message "Starting X server..."
            export DISPLAY=:0
            startx &
            sleep 5
        else
            log_message "${RED}Cannot start GUI - no X server available${NC}"
            return 1
        fi
    fi

    # Start GUI application
    cd "$INSTALL_DIR/bin"
    python3 gui_frontend.py &
    local gui_pid=$!

    log_message "${GREEN}GUI application started (PID: $gui_pid)${NC}"

    return 0
}

# Show system information
show_system_info() {
    echo -e "${BLUE}"
    echo "System Information:"
    echo "==================="
    echo -e "${NC}"

    echo "Hostname: $(hostname)"
    echo "Kernel: $(uname -r)"
    echo "Architecture: $(uname -m)"
    echo "Memory: $(free -h | grep '^Mem:' | awk '{print $2}')"
    echo "Disk Space: $(df -h / | tail -1 | awk '{print $4}') available"
    echo "Uptime: $(uptime -p)"
    echo ""

    echo -e "${BLUE}Network Status:${NC}"
    if ping -c 1 8.8.8.8 &> /dev/null; then
        echo "✓ Internet connection available"
    else
        echo "❌ No internet connection"
    fi

    if [[ -n "${SUPABASE_URL:-}" ]]; then
        echo "✓ Supabase configured"
    else
        echo "⚠️ Supabase not configured (offline mode)"
    fi

    echo ""
}

# Show main menu
show_menu() {
    while true; do
        echo -e "${BLUE}"
        echo "Secure Data Wipe Tool - Main Menu"
        echo "=================================="
        echo -e "${NC}"

        echo "1. Start Full Application (Backend + GUI)"
        echo "2. Start Backend Only"
        echo "3. Start GUI Only"
        echo "4. Run Drive Detection"
        echo "5. View System Information"
        echo "6. View Logs"
        echo "7. Stop Services"
        echo "8. Configuration"
        echo "9. Exit"
        echo ""

        read -p "Select option [1-9]: " choice

        case $choice in
            1)
                start_full_application
                ;;
            2)
                start_backend
                ;;
            3)
                start_gui
                ;;
            4)
                run_drive_detection
                ;;
            5)
                show_system_info
                read -p "Press Enter to continue..."
                ;;
            6)
                show_logs_menu
                ;;
            7)
                stop_services
                ;;
            8)
                configuration_menu
                ;;
            9)
                log_message "Exiting..."
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option. Please try again.${NC}"
                ;;
        esac

        echo ""
    done
}

# Start full application
start_full_application() {
    log_message "${YELLOW}Starting full application...${NC}"

    if start_backend; then
        sleep 2
        if start_gui; then
            log_message "${GREEN}Full application started successfully${NC}"

            echo ""
            echo -e "${GREEN}Application Status:${NC}"
            echo "✓ Backend server running on http://localhost:$BACKEND_PORT"
            echo "✓ GUI application started"
            echo ""
            echo "You can now use the graphical interface to:"
            echo "• Detect storage drives"
            echo "• Perform secure data wipes"
            echo "• Generate and manage certificates"
            echo ""
            echo "Press Ctrl+C to stop all services"

            # Wait for interrupt
            trap 'stop_services; exit 0' INT
            wait
        else
            log_message "${RED}Failed to start GUI${NC}"
        fi
    else
        log_message "${RED}Failed to start backend${NC}"
    fi
}

# Run drive detection
run_drive_detection() {
    log_message "${YELLOW}Running drive detection...${NC}"

    if [[ -f "$INSTALL_DIR/bin/drive_detection.sh" ]]; then
        "$INSTALL_DIR/bin/drive_detection.sh"

        if [[ -f "/tmp/detected_drives.json" ]]; then
            echo ""
            echo -e "${GREEN}Drive detection completed. Results:${NC}"
            jq -r '.detected_drives[] | "Device: \(.device) | Model: \(.model) | Type: \(.drive_type) | Size: \(.size)"' /tmp/detected_drives.json
            echo ""
        fi
    else
        log_message "${RED}Drive detection script not found${NC}"
    fi

    read -p "Press Enter to continue..."
}

# Show logs menu
show_logs_menu() {
    while true; do
        echo -e "${BLUE}Log Files:${NC}"
        echo "1. Startup Log"
        echo "2. Backend Log"
        echo "3. Drive Detection Log"
        echo "4. Wipe Operations Log"
        echo "5. Back to Main Menu"
        echo ""

        read -p "Select log to view [1-5]: " log_choice

        case $log_choice in
            1)
                show_log "$LOG_DIR/startup.log"
                ;;
            2)
                show_log "$LOG_DIR/backend.log"
                ;;
            3)
                show_log "/tmp/drive_detection.log"
                ;;
            4)
                show_log "$LOG_DIR/wipe_operations.log"
                ;;
            5)
                break
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                ;;
        esac
    done
}

# Show log file
show_log() {
    local logfile="$1"

    if [[ -f "$logfile" ]]; then
        echo -e "${BLUE}Showing: $logfile${NC}"
        echo "=========================="
        tail -50 "$logfile"
        echo ""
        read -p "Press Enter to continue..."
    else
        echo -e "${YELLOW}Log file not found: $logfile${NC}"
        read -p "Press Enter to continue..."
    fi
}

# Stop services
stop_services() {
    log_message "${YELLOW}Stopping services...${NC}"

    # Stop backend
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            log_message "Backend server stopped (PID: $pid)"
        fi
        rm -f "$PID_FILE"
    fi

    # Kill any Python processes related to our application
    pkill -f "backend_server.py" 2>/dev/null || true
    pkill -f "gui_frontend.py" 2>/dev/null || true

    log_message "${GREEN}All services stopped${NC}"
}

# Configuration menu
configuration_menu() {
    while true; do
        echo -e "${BLUE}Configuration Menu:${NC}"
        echo "1. Setup Supabase Credentials"
        echo "2. View Current Configuration"
        echo "3. Reset Configuration"
        echo "4. Back to Main Menu"
        echo ""

        read -p "Select option [1-4]: " config_choice

        case $config_choice in
            1)
                setup_supabase_credentials
                ;;
            2)
                view_configuration
                ;;
            3)
                reset_configuration
                ;;
            4)
                break
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                ;;
        esac
    done
}

# Setup Supabase credentials
setup_supabase_credentials() {
    echo -e "${YELLOW}Supabase Configuration:${NC}"
    echo ""

    read -p "Enter Supabase URL: " supabase_url
    read -p "Enter Supabase API Key: " supabase_key

    if [[ -n "$supabase_url" && -n "$supabase_key" ]]; then
        cat > "$INSTALL_DIR/config/supabase.conf" << EOF
# Supabase Configuration
export SUPABASE_URL="$supabase_url"
export SUPABASE_KEY="$supabase_key"
EOF

        chmod 600 "$INSTALL_DIR/config/supabase.conf"
        log_message "${GREEN}Supabase credentials saved${NC}"
    else
        log_message "${YELLOW}Configuration cancelled${NC}"
    fi

    read -p "Press Enter to continue..."
}

# View configuration
view_configuration() {
    echo -e "${BLUE}Current Configuration:${NC}"
    echo "======================="

    echo "Install Directory: $INSTALL_DIR"
    echo "Log Directory: $LOG_DIR"
    echo "Backend Port: $BACKEND_PORT"
    echo "PID File: $PID_FILE"

    if [[ -f "$INSTALL_DIR/config/supabase.conf" ]]; then
        echo "Supabase: Configured"
        source "$INSTALL_DIR/config/supabase.conf"
        echo "  URL: ${SUPABASE_URL:-Not Set}"
        echo "  Key: ${SUPABASE_KEY:0:20}..." # Show only first 20 chars
    else
        echo "Supabase: Not Configured"
    fi

    echo ""
    read -p "Press Enter to continue..."
}

# Reset configuration
reset_configuration() {
    read -p "Are you sure you want to reset all configuration? [y/N]: " confirm

    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        rm -f "$INSTALL_DIR/config/supabase.conf"
        log_message "${GREEN}Configuration reset${NC}"
    else
        log_message "Reset cancelled"
    fi

    read -p "Press Enter to continue..."
}

# Main execution
main() {
    print_banner

    check_root
    check_requirements
    setup_environment
    setup_supabase

    log_message "${GREEN}Secure Data Wipe Tool initialized${NC}"

    show_system_info
    show_menu
}

# Execute main function
main "$@"

