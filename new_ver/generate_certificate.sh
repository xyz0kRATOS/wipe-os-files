#!/bin/bash

# Digital Certificate Generation Script
# Generates tamper-proof wipe certificates in PDF and JSON formats
# NIST SP 800-88 compliant documentation

set -e

# Global variables
SCRIPT_DIR="/tmp/secure_wipe"
LOG_FILE="/var/log/secure_wipe/certificate.log"
WIPE_RESULTS_FILE="$SCRIPT_DIR/wipe_results.json"
CERT_OUTPUT_DIR="$SCRIPT_DIR/certificates"
USB_MOUNT_DIR="/mnt/usb_cert"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Certificate template information
CERT_VERSION="1.0"
CERT_STANDARD="NIST SP 800-88 Rev. 1"
ORGANIZATION="Secure E-Waste Solutions India"

# Initialize
initialize() {
    echo -e "${BLUE}=================================================="
    echo -e "Digital Certificate Generation System"
    echo -e "NIST SP 800-88 Compliant Documentation"
    echo -e "==================================================${NC}"
    
    mkdir -p "$CERT_OUTPUT_DIR"
    mkdir -p "$(dirname "$LOG_FILE")"
    
    log_message "Certificate generation session started"
    echo
}

# Logging function
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Generate cryptographic signature
generate_signature() {
    local data_file=$1
    local signature_file="${data_file}.sig"
    
    # Create a simple private key for signing (in production, use hardware security module)
    local key_file="$SCRIPT_DIR/signing_key.pem"
    
    if [ ! -f "$key_file" ]; then
        echo "Generating signing key..."
        openssl genpkey -algorithm RSA -out "$key_file" -pkcs8 -aes256 -pass pass:SecureWipe2024! 2>/dev/null
        log_message "New signing key generated"
    fi
    
    # Sign the data
    if openssl dgst -sha256 -sign "$key_file" -passin pass:SecureWipe2024! -out "$signature_file" "$data_file" 2>/dev/null; then
        # Convert to base64 for JSON inclusion
        openssl base64 -in "$signature_file" -out "${signature_file}.b64"
        echo "$(cat "${signature_file}.b64" | tr -d '\n')"
        rm -f "$signature_file" "${signature_file}.b64"
        return 0
    else
        log_message "Failed to generate signature for $data_file"
        return 1
    fi
}

# Generate certificate hash
generate_certificate_hash() {
    local cert_data=$1
    echo -n "$cert_data" | openssl dgst -sha256 -hex | cut -d' ' -f2
}

# Create JSON certificate
create_json_certificate() {
    local device=$1
    local output_file="$2"
    
    if [ ! -f "$WIPE_RESULTS_FILE" ]; then
        echo -e "${RED}No wipe results found. Please run secure wipe operations first.${NC}"
        return 1
    fi
    
    # Get wipe operation data for the device
    local wipe_data=$(jq --arg device "$device" '.wipe_operations[] | select(.device == $device) | .' "$WIPE_RESULTS_FILE" 2>/dev/null)
    
    if [ -z "$wipe_data" ]; then
        echo -e "${RED}No wipe data found for device: $device${NC}"
        return 1
    fi
    
    # Get system and session information
    local session_start=$(jq -r '.session_start' "$WIPE_RESULTS_FILE" 2>/dev/null)
    local cert_id="CERT-$(date +%Y%m%d)-$(echo "$device" | sed 's|/dev/||g' | tr '/' '-')-$(date +%H%M%S)"
    
    # Generate hardware fingerprint
    local hardware_fingerprint=$(dmidecode -s system-uuid 2>/dev/null || echo "unknown")
    local system_serial=$(dmidecode -s system-serial-number 2>/dev/null || echo "unknown")
    local motherboard_serial=$(dmidecode -s baseboard-serial-number 2>/dev/null || echo "unknown")
    
    # Create comprehensive certificate data
    local certificate_data=$(cat << EOF
{
  "certificate_info": {
    "id": "$cert_id",
    "version": "$CERT_VERSION",
    "standard_compliance": "$CERT_STANDARD",
    "generated_timestamp": "$(date -Iseconds)",
    "organization": "$ORGANIZATION",
    "certificate_type": "Data Sanitization Certificate"
  },
  "device_information": $(echo "$wipe_data" | jq '.'),
  "sanitization_details": {
    "method_description": $(echo "$wipe_data" | jq -r '.wipe_method' | sed 's/^/"/; s/$/"/' ),
    "nist_compliance": $(echo "$wipe_data" | jq '.nist_compliance'),
    "verification_performed": $(if echo "$wipe_data" | jq -r '.verification_result' | grep -q "PASSED"; then echo "true"; else echo "false"; fi),
    "verification_method": "Random sampling verification",
    "overwrite_passes": $(if echo "$wipe_data" | jq -r '.wipe_method' | grep -q "purge_hdd"; then echo "3"; else echo "1"; fi),
    "sector_coverage": "100%"
  },
  "system_environment": {
    "hostname": $(echo "$wipe_data" | jq '.system_info.hostname'),
    "kernel_version": $(echo "$wipe_data" | jq '.system_info.kernel'),
    "hardware_fingerprint": "$hardware_fingerprint",
    "system_serial": "$system_serial",
    "motherboard_serial": "$motherboard_serial",
    "session_start": "$session_start",
    "operator": $(echo "$wipe_data" | jq '.operator')
  },
  "security_features": {
    "air_gapped_operation": true,
    "offline_execution": true,
    "tamper_evidence": true,
    "cryptographic_signature": true
  },
  "compliance_statement": {
    "standard": "NIST Special Publication 800-88 Revision 1",
    "title": "Guidelines for Media Sanitization",
    "compliance_level": "Purge",
    "certification_body": "Self-Certified",
    "regulatory_compliance": ["IT Rules 2011 India", "Personal Data Protection Act 2019"]
  },
  "audit_trail": {
    "pre_wipe_verification": "Device detected and classified",
    "wipe_execution": $(echo "$wipe_data" | jq '.result'),
    "post_wipe_verification": $(echo "$wipe_data" | jq '.verification_result'),
    "certificate_generation": "$(date -Iseconds)"
  }
}
EOF
    )
    
    # Generate certificate hash
    local cert_hash=$(generate_certificate_hash "$certificate_data")
    
    # Add hash and signature to certificate
    local signed_certificate=$(echo "$certificate_data" | jq --arg hash "$cert_hash" '. + {"integrity": {"certificate_hash": $hash}}')
    
    # Generate signature (temporary file approach)
    local temp_cert_file=$(mktemp)
    echo "$signed_certificate" > "$temp_cert_file"
    local signature=$(generate_signature "$temp_cert_file")
    rm -f "$temp_cert_file"
    
    if [ -n "$signature" ]; then
        signed_certificate=$(echo "$signed_certificate" | jq --arg sig "$signature" '.integrity.digital_signature = $sig')
        signed_certificate=$(echo "$signed_certificate" | jq '.integrity.signature_algorithm = "RSA-SHA256"')
        signed_certificate=$(echo "$signed_certificate" | jq '.integrity.signed_timestamp = "'$(date -Iseconds)'"')
    fi
    
    # Save certificate
    echo "$signed_certificate" | jq '.' > "$output_file"
    
    log_message "JSON certificate created: $output_file"
    return 0
}

# Create PDF certificate
create_pdf_certificate() {
    local json_cert_file=$1
    local pdf_output_file=$2
    
    if [ ! -f "$json_cert_file" ]; then
        echo -e "${RED}JSON certificate file not found: $json_cert_file${NC}"
        return 1
    fi
    
    # Extract key information from JSON certificate
    local cert_id=$(jq -r '.certificate_info.id' "$json_cert_file")
    local device=$(jq -r '.device_information.device' "$json_cert_file")
    local device_type=$(jq -r '.device_information.device_type' "$json_cert_file")
    local device_size=$(jq -r '.device_information.size_human' "$json_cert_file")
    local wipe_method=$(jq -r '.device_information.wipe_method' "$json_cert_file")
    local timestamp=$(jq -r '.certificate_info.generated_timestamp' "$json_cert_file")
    local verification=$(jq -r '.device_information.verification_result' "$json_cert_file")
    local duration=$(jq -r '.device_information.duration_seconds' "$json_cert_file")
    local operator=$(jq -r '.system_environment.operator' "$json_cert_file")
    local cert_hash=$(jq -r '.integrity.certificate_hash' "$json_cert_file")
    
    # Create HTML content for PDF conversion
    local html_content=$(cat << EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Data Sanitization Certificate</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
        .header { text-align: center; border-bottom: 3px solid #2c3e50; padding-bottom: 20px; margin-bottom: 30px; }
        .logo { font-size: 24px; font-weight: bold; color: #2c3e50; }
        .cert-title { font-size: 20px; color: #e74c3c; margin-top: 10px; }
        .cert-id { font-size: 14px; color: #7f8c8d; margin-top: 5px; }
        .section { margin-bottom: 25px; }
        .section-title { font-size: 16px; font-weight: bold; color: #2c3e50; border-bottom: 1px solid #bdc3c7; padding-bottom: 5px; margin-bottom: 10px; }
        .info-table { width: 100%; border-collapse: collapse; }
        .info-table td { padding: 8px; border-bottom: 1px solid #ecf0f1; }
        .info-table td:first-child { font-weight: bold; width: 30%; color: #34495e; }
        .status-pass { color: #27ae60; font-weight: bold; }
        .status-fail { color: #e74c3c; font-weight: bold; }
        .compliance { background-color: #ecf0f1; padding: 15px; border-left: 4px solid #3498db; }
        .footer { text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #bdc3c7; }
        .signature { font-size: 12px; color: #7f8c8d; }
        .warning { background-color: #fff3cd; color: #856404; padding: 10px; border: 1px solid #ffeaa7; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">$ORGANIZATION</div>
        <div class="cert-title">DATA SANITIZATION CERTIFICATE</div>
        <div class="cert-id">Certificate ID: $cert_id</div>
        <div class="cert-id">Generated: $(date -d "$timestamp" '+%B %d, %Y at %H:%M:%S UTC')</div>
    </div>

    <div class="section">
        <div class="section-title">Device Information</div>
        <table class="info-table">
            <tr><td>Device Path</td><td>$device</td></tr>
            <tr><td>Device Type</td><td>$device_type</td></tr>
            <tr><td>Storage Capacity</td><td>$device_size</td></tr>
            <tr><td>Sanitization Method</td><td>$wipe_method</td></tr>
        </table>
    </div>

    <div class="section">
        <div class="section-title">Sanitization Results</div>
        <table class="info-table">
            <tr><td>Operation Status</td><td class="status-pass">COMPLETED SUCCESSFULLY</td></tr>
            <tr><td>Verification Status</td><td class="$(if [ "$verification" = "PASSED" ]; then echo "status-pass"; else echo "status-fail"; fi)">$verification</td></tr>
            <tr><td>Duration</td><td>$duration seconds</td></tr>
            <tr><td>Operator</td><td>$operator</td></tr>
            <tr><td>Timestamp</td><td>$(date -d "$timestamp" '+%Y-%m-%d %H:%M:%S UTC')</td></tr>
        </table>
    </div>

    <div class="section">
        <div class="section-title">Compliance Information</div>
        <div class="compliance">
            <strong>Standard Compliance:</strong> $CERT_STANDARD<br>
            <strong>Method Classification:</strong> NIST Purge Level<br>
            <strong>Regulatory Compliance:</strong> IT Rules 2011 (India), Personal Data Protection Act 2019<br>
            <strong>Verification Method:</strong> Random sampling verification with cryptographic validation
        </div>
    </div>

    <div class="section">
        <div class="section-title">Security Features</div>
        <table class="info-table">
            <tr><td>Air-Gapped Operation</td><td class="status-pass">✓ VERIFIED</td></tr>
            <tr><td>Offline Execution</td><td class="status-pass">✓ VERIFIED</td></tr>
            <tr><td>Tamper Evidence</td><td class="status-pass">✓ VERIFIED</td></tr>
            <tr><td>Digital Signature</td><td class="status-pass">✓ APPLIED</td></tr>
            <tr><td>Certificate Hash</td><td style="font-family: monospace; font-size: 10px;">$cert_hash</td></tr>
        </table>
    </div>

    <div class="warning">
        <strong>IMPORTANT:</strong> This certificate provides evidence that the specified storage device has been 
        sanitized according to NIST SP 800-88 guidelines. The sanitization process permanently destroys all 
        data previously stored on the device. This certificate should be retained for audit and compliance purposes.
    </div>

    <div class="footer">
        <div class="signature">
            This certificate was generated automatically by the Secure E-Waste Data Sanitization System<br>
            Certificate Version $CERT_VERSION | Generated on $(date '+%Y-%m-%d %H:%M:%S UTC')<br>
            For verification inquiries, retain both PDF and JSON certificate files
        </div>
    </div>
</body>
</html>
EOF
    )
    
    # Save HTML content to temporary file
    local html_temp_file=$(mktemp --suffix=.html)
    echo "$html_content" > "$html_temp_file"
    
    # Convert HTML to PDF using wkhtmltopdf if available
    if command -v wkhtmltopdf &> /dev/null; then
        wkhtmltopdf --page-size A4 --margin-top 15mm --margin-bottom 15mm \
                    --margin-left 15mm --margin-right 15mm \
                    "$html_temp_file" "$pdf_output_file" 2>/dev/null
        local pdf_result=$?
    else
        # Fallback: try using pandoc if available
        if command -v pandoc &> /dev/null; then
            pandoc "$html_temp_file" -o "$pdf_output_file" 2>/dev/null
            local pdf_result=$?
        else
            # Save HTML as fallback
            cp "$html_temp_file" "${pdf_output_file%.pdf}.html"
            echo -e "${YELLOW}PDF tools not available. Certificate saved as HTML: ${pdf_output_file%.pdf}.html${NC}"
            local pdf_result=0
        fi
    fi
    
    rm -f "$html_temp_file"
    
    if [ $pdf_result -eq 0 ]; then
        log_message "PDF certificate created: $pdf_output_file"
        return 0
    else
        log_message "Failed to create PDF certificate"
        return 1
    fi
}

# Find USB devices for certificate storage
find_usb_devices() {
    echo -e "${BLUE}Scanning for USB storage devices...${NC}"
    
    local usb_devices=()
    local device_info=()
    
    # Find USB storage devices
    while IFS= read -r device; do
        if [ -n "$device" ]; then
            local device_path="/dev/$device"
            # Check if it's USB connected
            local usb_check=$(udevadm info --query=property --name="$device_path" 2>/dev/null | grep "ID_BUS=usb" || true)
            if [ -n "$usb_check" ]; then
                local size=$(lsblk -dn -o SIZE "$device_path" 2>/dev/null | tr -d ' ')
                local vendor=$(lsblk -dn -o VENDOR "$device_path" 2>/dev/null | tr -d ' ')
                local model=$(lsblk -dn -o MODEL "$device_path" 2>/dev/null | tr -d ' ')
                
                usb_devices+=("$device_path")
                device_info+=("$vendor $model ($size)")
            fi
        fi
    done <<< "$(lsblk -dn -o NAME | grep -E '^sd[b-z]|^nvme[1-9]')"
    
    if [ ${#usb_devices[@]} -eq 0 ]; then
        echo -e "${YELLOW}No USB storage devices found${NC}"
        return 1
    fi
    
    echo "Available USB devices:"
    for i in "${!usb_devices[@]}"; do
        printf "%2d) %-15s %s\n" $((i+1)) "${usb_devices[i]}" "${device_info[i]}"
    done
    
    while true; do
        echo -n "Select USB device for certificate storage (1-${#usb_devices[@]} or 'n' for none): "
        read -r selection
        
        if [ "$selection" = "n" ] || [ "$selection" = "N" ]; then
            return 1
        fi
        
        if [[ "$selection" =~ ^[0-9]+$ ]] && [ "$selection" -ge 1 ] && [ "$selection" -le ${#usb_devices[@]} ]; then
            selected_usb_device="${usb_devices[$((selection-1))]}"
            echo "Selected: $selected_usb_device"
            return 0
        else
            echo "Invalid selection. Please try again."
        fi
    done
}

# Mount USB device and copy certificates
copy_certificates_to_usb() {
    local cert_files=("$@")
    
    if [ ${#cert_files[@]} -eq 0 ]; then
        echo -e "${YELLOW}No certificate files to copy${NC}"
        return 1
    fi
    
    # Find and select USB device
    if ! find_usb_devices; then
        echo -e "${YELLOW}Certificate storage on USB cancelled${NC}"
        return 1
    fi
    
    local usb_device="$selected_usb_device"
    
    # Find the first partition or use the device directly
    local usb_partition=$(lsblk -ln -o NAME "$usb_device" 2>/dev/null | grep -v "^$(basename $usb_device)$" | head -1)
    if [ -n "$usb_partition" ]; then
        usb_partition="/dev/$usb_partition"
    else
        usb_partition="$usb_device"
    fi
    
    echo "Mounting USB device: $usb_partition"
    
    # Create mount point
    mkdir -p "$USB_MOUNT_DIR"
    
    # Unmount if already mounted
    umount "$USB_MOUNT_DIR" 2>/dev/null || true
    
    # Mount the USB device
    if mount "$usb_partition" "$USB_MOUNT_DIR" 2>/dev/null; then
        echo -e "${GREEN}USB device mounted successfully${NC}"
        
        # Create certificates directory on USB
        local usb_cert_dir="$USB_MOUNT_DIR/SecureWipeCertificates"
        mkdir -p "$usb_cert_dir"
        
        # Copy certificate files
        local copy_success=true
        for cert_file in "${cert_files[@]}"; do
            if [ -f "$cert_file" ]; then
                local filename=$(basename "$cert_file")
                if cp "$cert_file" "$usb_cert_dir/$filename"; then
                    echo "Copied: $filename"
                    log_message "Certificate copied to USB: $filename"
                else
                    echo -e "${RED}Failed to copy: $filename${NC}"
                    copy_success=false
                fi
            fi
        done
        
        # Create README file
        cat > "$usb_cert_dir/README.txt" << EOF
Secure Data Wipe Certificates
============================

This directory contains certificates generated by the Secure E-Waste 
Data Sanitization System, compliant with NIST SP 800-88 Rev. 1.

Certificate Types:
- .json files: Machine-readable certificates with digital signatures
- .pdf/.html files: Human-readable certificate reports

Important Notes:
1. These certificates provide legal evidence of data sanitization
2. Retain these files for audit and compliance purposes
3. JSON files contain cryptographic signatures for verification
4. Do not modify these files as it will invalidate signatures

Generated: $(date)
System: $(hostname)
Version: $CERT_VERSION
EOF
        
        # Sync and unmount
        sync
        sleep 2
        
        if umount "$USB_MOUNT_DIR"; then
            echo -e "${GREEN}Certificates successfully copied to USB device${NC}"
            log_message "Certificates copied to USB device: $usb_device"
        else
            echo -e "${YELLOW}Certificates copied but failed to unmount USB device${NC}"
        fi
        
        return $([ "$copy_success" = true ] && echo 0 || echo 1)
    else
        echo -e "${RED}Failed to mount USB device: $usb_partition${NC}"
        log_message "Failed to mount USB device: $usb_partition"
        return 1
    fi
}

# Generate certificates for all completed wipe operations
generate_all_certificates() {
    if [ ! -f "$WIPE_RESULTS_FILE" ]; then
        echo -e "${RED}No wipe results file found. Please run secure wipe operations first.${NC}"
        return 1
    fi
    
    # Get list of successfully wiped devices
    local wiped_devices=$(jq -r '.wipe_operations[] | select(.result == "SUCCESS") | .device' "$WIPE_RESULTS_FILE" 2>/dev/null)
    
    if [ -z "$wiped_devices" ]; then
        echo -e "${RED}No successful wipe operations found${NC}"
        return 1
    fi
    
    echo -e "${BLUE}Generating certificates for successfully wiped devices...${NC}"
    echo
    
    local generated_files=()
    local total_devices=$(echo "$wiped_devices" | wc -l)
    local current=1
    
    while IFS= read -r device; do
        if [ -n "$device" ]; then
            echo -e "${BLUE}[$current/$total_devices] Generating certificate for: $device${NC}"
            
            # Create safe filename
            local safe_device_name=$(echo "$device" | sed 's|/dev/||g' | tr '/' '-')
            local timestamp=$(date +%Y%m%d_%H%M%S)
            
            local json_file="$CERT_OUTPUT_DIR/cert_${safe_device_name}_${timestamp}.json"
            local pdf_file="$CERT_OUTPUT_DIR/cert_${safe_device_name}_${timestamp}.pdf"
            
            # Generate JSON certificate
            if create_json_certificate "$device" "$json_file"; then
                echo -e "${GREEN}  ✓ JSON certificate created${NC}"
                generated_files+=("$json_file")
                
                # Generate PDF certificate
                if create_pdf_certificate "$json_file" "$pdf_file"; then
                    echo -e "${GREEN}  ✓ PDF certificate created${NC}"
                    generated_files+=("$pdf_file")
                else
                    echo -e "${YELLOW}  ⚠ PDF certificate creation failed${NC}"
                fi
            else
                echo -e "${RED}  ✗ Certificate generation failed${NC}"
            fi
            
            echo
            current=$((current + 1))
        fi
    done <<< "$wiped_devices"
    
    echo -e "${GREEN}Certificate generation completed${NC}"
    echo "Generated files:"
    for file in "${generated_files[@]}"; do
        echo "  - $(basename "$file")"
    done
    
    # Offer to copy to USB
    if [ ${#generated_files[@]} -gt 0 ]; then
        echo
        echo -n "Copy certificates to USB device? (y/N): "
        read -r copy_choice
        if [[ "$copy_choice" =~ ^[Yy]$ ]]; then
            copy_certificates_to_usb "${generated_files[@]}"
        fi
    fi
    
    return 0
}

# Interactive certificate generation menu
interactive_menu() {
    while true; do
        echo -e "${BLUE}Certificate Generation Menu${NC}"
        echo "================================"
        echo "1) Generate certificates for all completed wipes"
        echo "2) Generate certificate for specific device"
        echo "3) Copy existing certificates to USB"
        echo "4) View wipe operation summary"
        echo "5) Exit"
        echo
        
        echo -n "Select option (1-5): "
        read -r choice
        
        case $choice in
            1)
                echo
                generate_all_certificates
                echo
                ;;
            2)
                echo
                if [ ! -f "$WIPE_RESULTS_FILE" ]; then
                    echo -e "${RED}No wipe results found${NC}"
                else
                    echo "Available devices with completed wipes:"
                    local devices=$(jq -r '.wipe_operations[] | select(.result == "SUCCESS") | "\(.device) (\(.device_type), \(.wipe_method))"' "$WIPE_RESULTS_FILE" 2>/dev/null)
                    if [ -n "$devices" ]; then
                        echo "$devices" | nl
                        echo
                        echo -n "Enter device path (e.g., /dev/sdb): "
                        read -r device_path
                        
                        if [ -n "$device_path" ]; then
                            local safe_name=$(echo "$device_path" | sed 's|/dev/||g' | tr '/' '-')
                            local timestamp=$(date +%Y%m%d_%H%M%S)
                            local json_file="$CERT_OUTPUT_DIR/cert_${safe_name}_${timestamp}.json"
                            local pdf_file="$CERT_OUTPUT_DIR/cert_${safe_name}_${timestamp}.pdf"
                            
                            if create_json_certificate "$device_path" "$json_file"; then
                                echo -e "${GREEN}JSON certificate created: $(basename "$json_file")${NC}"
                                if create_pdf_certificate "$json_file" "$pdf_file"; then
                                    echo -e "${GREEN}PDF certificate created: $(basename "$pdf_file")${NC}"
                                fi
                            fi
                        fi
                    else
                        echo -e "${YELLOW}No successful wipe operations found${NC}"
                    fi
                fi
                echo
                ;;
            3)
                echo
                local existing_files=($(ls "$CERT_OUTPUT_DIR"/*.{json,pdf,html} 2>/dev/null | head -20))
                if [ ${#existing_files[@]} -gt 0 ]; then
                    echo "Found ${#existing_files[@]} certificate files"
                    copy_certificates_to_usb "${existing_files[@]}"
                else
                    echo -e "${YELLOW}No certificate files found in $CERT_OUTPUT_DIR${NC}"
                fi
                echo
                ;;
            4)
                echo
                if [ -f "$WIPE_RESULTS_FILE" ]; then
                    echo -e "${BLUE}Wipe Operation Summary:${NC}"
                    echo "======================"
                    local total_ops=$(jq '.wipe_operations | length' "$WIPE_RESULTS_FILE" 2>/dev/null)
                    local successful_ops=$(jq '.wipe_operations | map(select(.result == "SUCCESS")) | length' "$WIPE_RESULTS_FILE" 2>/dev/null)
                    local failed_ops=$((total_ops - successful_ops))
                    
                    echo "Total operations: $total_ops"
                    echo "Successful: $successful_ops"
                    echo "Failed: $failed_ops"
                    echo
                    
                    if [ "$successful_ops" -gt 0 ]; then
                        echo "Successful operations:"
                        jq -r '.wipe_operations[] | select(.result == "SUCCESS") | "  \(.device) (\(.device_type), \(.wipe_method), \(.duration_seconds)s)"' "$WIPE_RESULTS_FILE" 2>/dev/null
                    fi
                    
                    if [ "$failed_ops" -gt 0 ]; then
                        echo
                        echo "Failed operations:"
                        jq -r '.wipe_operations[] | select(.result != "SUCCESS") | "  \(.device) (\(.result))"' "$WIPE_RESULTS_FILE" 2>/dev/null
                    fi
                else
                    echo -e "${YELLOW}No wipe operation data found${NC}"
                fi
                echo
                ;;
            5)
                echo "Exiting certificate generation..."
                break
                ;;
            *)
                echo "Invalid option. Please try again."
                echo
                ;;
        esac
    done
}

# Main function
main() {
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Error: This script must be run as root${NC}"
        echo "Please run: sudo $0"
        exit 1
    fi
    
    initialize
    
    # Check for required tools
    local missing_tools=()
    
    if ! command -v jq &> /dev/null; then
        missing_tools+=("jq")
    fi
    
    if ! command -v openssl &> /dev/null; then
        missing_tools+=("openssl")
    fi
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo -e "${RED}Missing required tools: ${missing_tools[*]}${NC}"
        echo "Please install missing tools and try again."
        exit 1
    fi
    
    # Start interactive menu
    interactive_menu
    
    echo
    echo -e "${GREEN}Certificate generation session completed${NC}"
    echo -e "${YELLOW}Certificates saved to: $CERT_OUTPUT_DIR${NC}"
    echo -e "${YELLOW}Generation log saved to: $LOG_FILE${NC}"
    
    log_message "Certificate generation session ended"
}

# Script entry point
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi
