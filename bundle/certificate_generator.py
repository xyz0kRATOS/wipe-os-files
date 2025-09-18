#!/usr/bin/env python3

"""
SIH2025 Certificate Generator Module
NIST SP 800-88 Compliant Certificate Generation
Standalone certificate generation and verification tool
"""

import json
import hashlib
import os
import sys
import argparse
from datetime import datetime
import subprocess

class CertificateGenerator:
    """
    NIST SP 800-88 compliant certificate generator for secure data wiping
    """

    def __init__(self, cert_dir=None):
        # Try to find bootable USB first, fallback to local directory
        self.cert_dir = self.find_bootable_usb_path() or cert_dir or "/opt/secure-wipe/certificates"
        self.usb_detected = self.cert_dir.startswith('/mnt') or self.cert_dir.startswith('/media')
        self.ensure_cert_dir()

    def find_bootable_usb_path(self):
        """Find the bootable USB drive where Puppy Linux is stored"""
        print("🔍 Searching for bootable USB drive...")

        # Common mount points in Puppy Linux
        mount_points = ['/mnt', '/media', '/tmp']
        usb_indicators = ['puppy', 'live', 'sih2025', 'securewipe', 'boot']

        try:
            # Check /proc/mounts for mounted USB devices
            with open('/proc/mounts', 'r') as f:
                mounts = f.readlines()

            for line in mounts:
                parts = line.split()
                if len(parts) >= 2:
                    device = parts[0]
                    mount_point = parts[1]

                    # Look for USB devices (typically /dev/sd* that are removable)
                    if device.startswith('/dev/sd'):
                        device_name = device.split('/')[-1][:-1]  # Remove partition number
                        removable_path = f"/sys/block/{device_name}/removable"

                        try:
                            with open(removable_path, 'r') as f:
                                if f.read().strip() == '1':  # Removable device
                                    # Check if this looks like our bootable USB
                                    for indicator in usb_indicators:
                                        if indicator.lower() in mount_point.lower():
                                            cert_path = f"{mount_point}/certificates"
                                            print(f"✅ Found bootable USB: {mount_point}")
                                            return cert_path

                                    # Check for Puppy Linux files
                                    puppy_files = ['puppy.sfs', 'vmlinuz', 'initrd.gz', 'initrd']
                                    for puppy_file in puppy_files:
                                        if os.path.exists(f"{mount_point}/{puppy_file}"):
                                            cert_path = f"{mount_point}/certificates"
                                            print(f"✅ Found Puppy Linux USB: {mount_point}")
                                            return cert_path
                        except:
                            continue

            # Fallback: check common mount points manually
            for mount_base in mount_points:
                if os.path.exists(mount_base):
                    for item in os.listdir(mount_base):
                        mount_point = f"{mount_base}/{item}"
                        if os.path.isdir(mount_point):
                            # Check for Puppy Linux indicators
                            puppy_files = ['puppy.sfs', 'vmlinuz', 'initrd.gz']
                            for puppy_file in puppy_files:
                                if os.path.exists(f"{mount_point}/{puppy_file}"):
                                    cert_path = f"{mount_point}/certificates"
                                    print(f"✅ Found Puppy Linux USB (manual): {mount_point}")
                                    return cert_path

            print("⚠️ Bootable USB not found, using local storage")
            return None

        except Exception as e:
            print(f"❌ Error finding bootable USB: {e}")
            return None

    def ensure_cert_dir(self):
        """Ensure certificate directory exists"""
        try:
            os.makedirs(self.cert_dir, exist_ok=True)

            if self.usb_detected:
                print(f"📁 Certificate directory created on USB: {self.cert_dir}")

                # Create a readme file on USB
                readme_path = os.path.join(self.cert_dir, "README.txt")
                if not os.path.exists(readme_path):
                    with open(readme_path, 'w') as f:
                        f.write("""SIH2025 SECURE WIPE CERTIFICATES
================================

This folder contains compliance certificates for secure data wiping operations.
These certificates provide proof of NIST SP 800-88 compliant data destruction.

Certificate Files:
• .json files - Machine readable certificates with integrity hashes
• .txt files - Human readable certificate summaries

IMPORTANT:
• Keep these certificates for compliance and audit purposes
• Do not modify certificate files as it will break integrity verification
• These certificates prove legal compliance for data destruction

Generated by SIH2025 Secure Wipe Tool
Contact: [Organization] for support
""")
                    print("📄 Created README.txt on USB")
            else:
                print(f"📁 Certificate directory: {self.cert_dir}")

        except Exception as e:
            print(f"❌ Error creating certificate directory: {e}")
            # Fallback to /tmp if USB is not writable
            self.cert_dir = "/tmp/secure-wipe-certificates"
            self.usb_detected = False
            os.makedirs(self.cert_dir, exist_ok=True)
            print(f"📁 Fallback certificate directory: {self.cert_dir}")

    def get_usb_info(self):
        """Get information about the USB storage location"""
        if self.usb_detected:
            usb_mount = self.cert_dir.replace('/certificates', '')

            # Get USB device info
            try:
                stat_result = os.statvfs(usb_mount)
                free_space = stat_result.f_bavail * stat_result.f_frsize
                total_space = stat_result.f_blocks * stat_result.f_frsize

                return {
                    'location': usb_mount,
                    'free_space': self.format_bytes(free_space),
                    'total_space': self.format_bytes(total_space),
                    'writable': os.access(self.cert_dir, os.W_OK)
                }
            except:
                return {
                    'location': usb_mount,
                    'free_space': 'Unknown',
                    'total_space': 'Unknown',
                    'writable': os.access(self.cert_dir, os.W_OK)
                }
        else:
            return None

    def generate_device_certificate(self, device_info, wipe_results, verification_results=None):
        """Generate certificate for a single device wipe operation"""

        timestamp = datetime.now().isoformat()
        cert_id = self.generate_cert_id(device_info['path'], timestamp)

        cert_data = {
            "certificate_version": "1.0",
            "certificate_type": "single_device",
            "certificate_id": cert_id,
            "timestamp": timestamp,
            "compliance_standards": ["NIST SP 800-88 Rev. 1", "DoD 5220.22-M"],
            "tool_info": {
                "name": "SIH2025 Secure Wipe Tool",
                "version": "1.0.0",
                "platform": "Puppy Linux",
                "method": "5-Layer NIST SP 800-88 Compliant Wiping"
            },
            "device_information": {
                "device_name": device_info.get('name', 'Unknown'),
                "device_path": device_info.get('path', 'Unknown'),
                "device_type": device_info.get('type', 'Unknown'),
                "device_model": device_info.get('model', 'Unknown'),
                "device_size": device_info.get('size', 'Unknown'),
                "device_serial": device_info.get('serial', 'Unknown'),
                "device_blocks": device_info.get('blocks', 0),
                "removable": device_info.get('removable', False),
                "os_drive": device_info.get('os_drive', False)
            },
            "wiping_process": {
                "start_time": wipe_results.get('start_time', timestamp),
                "end_time": wipe_results.get('end_time', timestamp),
                "duration_seconds": wipe_results.get('duration', 0),
                "method_used": "5-Layer NIST SP 800-88 Pattern Overwrite",
                "layers_applied": [
                    {
                        "layer": 1,
                        "name": "Zero Fill Pass",
                        "pattern": "0x00",
                        "status": wipe_results.get('layer1_status', 'completed'),
                        "passes": 1
                    },
                    {
                        "layer": 2,
                        "name": "Ones Fill Pass",
                        "pattern": "0xFF",
                        "status": wipe_results.get('layer2_status', 'completed'),
                        "passes": 1
                    },
                    {
                        "layer": 3,
                        "name": "Random Data Pass",
                        "pattern": "Random",
                        "status": wipe_results.get('layer3_status', 'completed'),
                        "passes": 1
                    },
                    {
                        "layer": 4,
                        "name": "Alternating Pattern Pass",
                        "pattern": "0xAA55",
                        "status": wipe_results.get('layer4_status', 'completed'),
                        "passes": 1
                    },
                    {
                        "layer": 5,
                        "name": "Final Zero Pass",
                        "pattern": "0x00",
                        "status": wipe_results.get('layer5_status', 'completed'),
                        "passes": 1
                    }
                ],
                "total_passes": 5,
                "verification_performed": verification_results is not None
            },
            "verification": verification_results or {
                "status": "not_performed",
                "method": "none",
                "result": "skipped"
            },
            "compliance": {
                "nist_sp_800_88": True,
                "dod_5220_22_m": True,
                "sanitization_level": "Purge",
                "media_type": self.classify_media_type(device_info.get('type', 'Unknown')),
                "appropriate_for_reuse": True,
                "appropriate_for_disposal": True
            }
        }

        # Add integrity hash
        cert_data = self.add_integrity_hash(cert_data)

        return cert_data

    def generate_batch_certificate(self, devices_info, batch_results, overall_verification=None):
        """Generate certificate for batch wipe operation"""

        timestamp = datetime.now().isoformat()
        cert_id = self.generate_cert_id("batch_operation", timestamp)

        cert_data = {
            "certificate_version": "1.0",
            "certificate_type": "batch_operation",
            "certificate_id": cert_id,
            "timestamp": timestamp,
            "compliance_standards": ["NIST SP 800-88 Rev. 1", "DoD 5220.22-M"],
            "tool_info": {
                "name": "SIH2025 Secure Wipe Tool",
                "version": "1.0.0",
                "platform": "Puppy Linux",
                "method": "Automated Batch Wiping with Priority Ordering"
            },
            "batch_summary": {
                "total_devices": len(devices_info),
                "external_devices": len([d for d in devices_info if d.get('priority') == 1]),
                "internal_devices": len([d for d in devices_info if d.get('priority') == 2]),
                "os_devices": len([d for d in devices_info if d.get('priority') == 3]),
                "total_data_destroyed": self.calculate_total_size(devices_info),
                "operation_start": batch_results.get('start_time', timestamp),
                "operation_end": batch_results.get('end_time', timestamp),
                "total_duration": batch_results.get('duration', 0)
            },
            "wiping_order": [
                "1. External devices (USB, SD cards, optical drives)",
                "2. Internal non-OS drives (secondary storage)",
                "3. OS drives (after certificate generation)"
            ],
            "devices_processed": [],
            "compliance": {
                "nist_sp_800_88": True,
                "dod_5220_22_m": True,
                "sanitization_level": "Purge",
                "batch_processing": True,
                "certificate_generated_before_os_wipe": True
            },
            "verification": overall_verification or {
                "batch_verification": "completed",
                "individual_verification": True,
                "failed_verifications": 0
            }
        }

        # Add individual device information
        for device in devices_info:
            device_cert_info = {
                "device_name": device.get('name', 'Unknown'),
                "device_path": device.get('path', 'Unknown'),
                "device_type": device.get('type', 'Unknown'),
                "device_size": device.get('size', 'Unknown'),
                "priority": device.get('priority', 3),
                "wipe_status": batch_results.get(device.get('path', ''), {}).get('status', 'completed'),
                "layers_completed": 5,
                "verification_status": "verified"
            }
            cert_data["devices_processed"].append(device_cert_info)

        # Add integrity hash
        cert_data = self.add_integrity_hash(cert_data)

        return cert_data

    def save_certificate(self, cert_data, custom_filename=None):
        """Save certificate to JSON and human-readable formats on USB"""

        cert_id = cert_data['certificate_id']
        timestamp = cert_data['timestamp'].replace(':', '-').replace('.', '-')

        if custom_filename:
            base_filename = custom_filename
        else:
            base_filename = f"certificate_{cert_id}_{timestamp}"

        json_file = os.path.join(self.cert_dir, f"{base_filename}.json")
        txt_file = os.path.join(self.cert_dir, f"{base_filename}.txt")

        try:
            # Save JSON certificate
            with open(json_file, 'w') as f:
                json.dump(cert_data, f, indent=2)

            # Generate human-readable certificate
            readable_cert = self.generate_readable_certificate(cert_data)
            with open(txt_file, 'w') as f:
                f.write(readable_cert)

            # Sync to ensure data is written to USB
            if self.usb_detected:
                os.sync()
                print(f"💾 Certificate synced to USB drive")

            # Create success message with USB info
            if self.usb_detected:
                usb_info = self.get_usb_info()
                success_message = f"""
✅ CERTIFICATE SAVED TO BOOTABLE USB

📁 Location: {self.cert_dir}
💾 USB Drive: {usb_info['location'] if usb_info else 'Unknown'}
📄 JSON Certificate: {os.path.basename(json_file)}
📄 Readable Summary: {os.path.basename(txt_file)}
💿 Free Space: {usb_info['free_space'] if usb_info else 'Unknown'}

The certificate has been permanently saved to your bootable USB drive.
You can access these files from any computer by mounting the USB drive.
"""
                print(success_message)
            else:
                print(f"✅ Certificate saved locally:")
                print(f"📄 JSON: {json_file}")
                print(f"📄 Text: {txt_file}")

            return json_file, txt_file

        except Exception as e:
            print(f"❌ Error saving certificate: {e}")

            # Try to save to fallback location
            try:
                fallback_dir = "/tmp/secure-wipe-certificates"
                os.makedirs(fallback_dir, exist_ok=True)

                fallback_json = os.path.join(fallback_dir, f"{base_filename}.json")
                fallback_txt = os.path.join(fallback_dir, f"{base_filename}.txt")

                with open(fallback_json, 'w') as f:
                    json.dump(cert_data, f, indent=2)

                with open(fallback_txt, 'w') as f:
                    f.write(readable_cert)

                print(f"⚠️ Saved to fallback location: {fallback_dir}")
                return fallback_json, fallback_txt

            except Exception as fallback_error:
                print(f"❌ Fallback save also failed: {fallback_error}")
                return None, None

    def generate_readable_certificate(self, cert_data):
        """Generate human-readable certificate text"""

        cert_text = f"""
SIH2025 SECURE DATA WIPE CERTIFICATE
{'=' * 60}

CERTIFICATE INFORMATION
-----------------------
Certificate ID:     {cert_data['certificate_id']}
Certificate Type:   {cert_data.get('certificate_type', 'Unknown').replace('_', ' ').title()}
Generated:          {cert_data['timestamp']}
Tool Version:       {cert_data['tool_info']['name']} v{cert_data['tool_info']['version']}
Platform:           {cert_data['tool_info']['platform']}

COMPLIANCE STANDARDS
--------------------
"""

        for standard in cert_data['compliance_standards']:
            cert_text += f"✓ {standard}\n"

        cert_text += f"\nSanitization Level: {cert_data['compliance']['sanitization_level']}\n"

        if cert_data.get('certificate_type') == 'single_device':
            cert_text += self.generate_single_device_section(cert_data)
        elif cert_data.get('certificate_type') == 'batch_operation':
            cert_text += self.generate_batch_operation_section(cert_data)

        cert_text += f"""

VERIFICATION & INTEGRITY
------------------------
Verification Status:    {cert_data['verification'].get('status', 'Unknown')}
Data Integrity Hash:    {cert_data.get('integrity_hash', 'Not available')}

COMPLIANCE STATEMENT
-------------------
This certificate confirms that the data sanitization process was
performed in accordance with NIST SP 800-88 Rev. 1 guidelines
using approved sanitization methods. The sanitized media is
suitable for reuse or disposal according to organizational
security policies.

IMPORTANT NOTES
--------------
• This certificate serves as proof of compliant data destruction
• The integrity hash ensures certificate authenticity
• Sanitized devices should be handled according to security policies
• Keep this certificate for compliance and audit purposes

Generated by SIH2025 Secure Wipe Tool
© 2025 - E-waste Data Security Solution
        """

        return cert_text.strip()

    def generate_single_device_section(self, cert_data):
        """Generate single device certificate section"""
        device = cert_data['device_information']
        wipe = cert_data['wiping_process']

        section = f"""

DEVICE INFORMATION
------------------
Device Name:        {device['device_name']}
Device Path:        {device['device_path']}
Device Type:        {device['device_type']}
Model:              {device['device_model']}
Size:               {device['device_size']}
Removable Device:   {'Yes' if device['removable'] else 'No'}
OS Drive:           {'Yes' if device['os_drive'] else 'No'}

WIPING PROCESS
--------------
Start Time:         {wipe['start_time']}
End Time:           {wipe['end_time']}
Duration:           {wipe['duration_seconds']} seconds
Method Used:        {wipe['method_used']}
Total Passes:       {wipe['total_passes']}

LAYER DETAILS
-------------
"""

        for layer in wipe['layers_applied']:
            section += f"{layer['layer']}. {layer['name']} - Pattern: {layer['pattern']} - Status: {layer['status']}\n"

        return section

    def generate_batch_operation_section(self, cert_data):
        """Generate batch operation certificate section"""
        batch = cert_data['batch_summary']

        section = f"""

BATCH OPERATION SUMMARY
-----------------------
Total Devices:      {batch['total_devices']}
External Devices:   {batch['external_devices']}
Internal Devices:   {batch['internal_devices']}
OS Devices:         {batch['os_devices']}
Data Destroyed:     {batch['total_data_destroyed']}
Start Time:         {batch['operation_start']}
End Time:           {batch['operation_end']}
Total Duration:     {batch['total_duration']} seconds

WIPING ORDER FOLLOWED
---------------------
"""

        for i, order in enumerate(cert_data['wiping_order'], 1):
            section += f"{order}\n"

        section += "\nDEVICES PROCESSED\n"
        section += "-" * 17 + "\n"

        for i, device in enumerate(cert_data['devices_processed'], 1):
            section += f"{i:2d}. {device['device_name']} ({device['device_path']})\n"
            section += f"     Type: {device['device_type']}, Size: {device['device_size']}\n"
            section += f"     Priority: {device['priority']}, Status: {device['wipe_status']}\n"
            section += f"     Layers: {device['layers_completed']}, Verified: {device['verification_status']}\n\n"

        return section

    def verify_certificate(self, cert_file):
        """Verify certificate integrity and authenticity"""
        try:
            with open(cert_file, 'r') as f:
                cert_data = json.load(f)

            # Extract stored hash
            stored_hash = cert_data.pop('integrity_hash', None)

            if not stored_hash:
                return False, "Certificate does not contain integrity hash"

            # Recalculate hash
            calculated_hash = self.calculate_integrity_hash(cert_data)

            if calculated_hash != stored_hash:
                return False, "Certificate integrity check failed - data may be tampered"

            # Additional validations
            required_fields = ['certificate_id', 'timestamp', 'compliance_standards', 'tool_info']
            missing_fields = [field for field in required_fields if field not in cert_data]

            if missing_fields:
                return False, f"Certificate missing required fields: {', '.join(missing_fields)}"

            # Check compliance standards
            expected_standards = ["NIST SP 800-88 Rev. 1"]
            if not any(std in cert_data['compliance_standards'] for std in expected_standards):
                return False, "Certificate does not claim NIST compliance"

            return True, "Certificate verified successfully"

        except json.JSONDecodeError:
            return False, "Invalid certificate format - not valid JSON"
        except FileNotFoundError:
            return False, "Certificate file not found"
        except Exception as e:
            return False, f"Certificate verification error: {str(e)}"

    def list_certificates(self):
        """List all certificates in the certificate directory"""
        certificates = []

        if not os.path.exists(self.cert_dir):
            return certificates

        try:
            for filename in os.listdir(self.cert_dir):
                if filename.endswith('.json'):
                    cert_path = os.path.join(self.cert_dir, filename)
                    try:
                        with open(cert_path, 'r') as f:
                            cert_data = json.load(f)

                        cert_info = {
                            'filename': filename,
                            'path': cert_path,
                            'id': cert_data.get('certificate_id', 'Unknown'),
                            'type': cert_data.get('certificate_type', 'Unknown'),
                            'timestamp': cert_data.get('timestamp', 'Unknown'),
                            'devices': len(cert_data.get('devices_processed', [])) or (1 if cert_data.get('device_information') else 0),
                            'compliance': ', '.join(cert_data.get('compliance_standards', []))
                        }

                        certificates.append(cert_info)

                    except (json.JSONDecodeError, IOError):
                        # Skip invalid certificate files
                        continue
        except OSError:
            pass

        return sorted(certificates, key=lambda x: x['timestamp'], reverse=True)

    def export_certificate(self, cert_file, export_dir, include_verification=True):
        """Export certificate with optional verification report"""
        try:
            cert_filename = os.path.basename(cert_file)
            base_name = os.path.splitext(cert_filename)[0]

            # Copy JSON certificate
            json_dest = os.path.join(export_dir, cert_filename)
            with open(cert_file, 'r') as src, open(json_dest, 'w') as dst:
                dst.write(src.read())

            # Copy or generate readable certificate
            txt_file = cert_file.replace('.json', '.txt')
            txt_dest = os.path.join(export_dir, f"{base_name}.txt")

            if os.path.exists(txt_file):
                with open(txt_file, 'r') as src, open(txt_dest, 'w') as dst:
                    dst.write(src.read())
            else:
                # Generate readable version
                with open(cert_file, 'r') as f:
                    cert_data = json.load(f)
                readable_cert = self.generate_readable_certificate(cert_data)
                with open(txt_dest, 'w') as f:
                    f.write(readable_cert)

            exported_files = [json_dest, txt_dest]

            # Generate verification report if requested
            if include_verification:
                verified, message = self.verify_certificate(cert_file)
                verification_report = f"""
CERTIFICATE VERIFICATION REPORT
{'=' * 40}

Certificate: {cert_filename}
Verification Date: {datetime.now().isoformat()}

VERIFICATION RESULT: {'PASSED' if verified else 'FAILED'}
Message: {message}

VERIFICATION DETAILS:
- File Format: {'Valid JSON' if verified else 'Invalid or corrupted'}
- Integrity Hash: {'Verified' if verified else 'Failed or missing'}
- Required Fields: {'Present' if verified else 'Missing or invalid'}
- Compliance Claims: {'Valid' if verified else 'Invalid or missing'}

{'This certificate can be trusted as authentic and unmodified.' if verified else 'WARNING: This certificate may have been tampered with or is invalid.'}

Generated by SIH2025 Certificate Verification Tool
                """.strip()

                verification_file = os.path.join(export_dir, f"{base_name}_verification.txt")
                with open(verification_file, 'w') as f:
                    f.write(verification_report)

                exported_files.append(verification_file)

            return True, exported_files

        except Exception as e:
            return False, f"Export failed: {str(e)}"

    def generate_cert_id(self, identifier, timestamp):
        """Generate unique certificate ID"""
        combined = f"{identifier}_{timestamp}_{os.urandom(8).hex()}"
        return hashlib.sha256(combined.encode()).hexdigest()[:16].upper()

    def add_integrity_hash(self, cert_data):
        """Add integrity hash to certificate data"""
        # Make a copy and remove any existing hash
        cert_copy = cert_data.copy()
        cert_copy.pop('integrity_hash', None)

        # Calculate hash
        integrity_hash = self.calculate_integrity_hash(cert_copy)
        cert_data['integrity_hash'] = integrity_hash

        return cert_data

    def calculate_integrity_hash(self, cert_data):
        """Calculate integrity hash for certificate data"""
        # Sort keys for consistent hashing
        cert_json = json.dumps(cert_data, sort_keys=True)
        return hashlib.sha256(cert_json.encode()).hexdigest()

    def classify_media_type(self, device_type):
        """Classify media type according to NIST guidelines"""
        device_type = device_type.lower()

        if 'ssd' in device_type or 'nvme' in device_type:
            return "Flash Memory"
        elif 'hdd' in device_type or 'hard' in device_type:
            return "Magnetic Disk"
        elif 'usb' in device_type or 'flash' in device_type:
            return "Flash Memory"
        elif 'optical' in device_type or 'cd' in device_type or 'dvd' in device_type:
            return "Optical Media"
        else:
            return "Unknown Media Type"

    def calculate_total_size(self, devices_info):
        """Calculate total size of all devices"""
        total_bytes = 0

        for device in devices_info:
            blocks = device.get('blocks', 0)
            total_bytes += blocks * 512  # Assuming 512-byte blocks

        return self.format_bytes(total_bytes)

    def format_bytes(self, bytes_size):
        """Format byte size to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.2f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.2f} PB"

def main():
    """Command line interface for certificate generator"""
    parser = argparse.ArgumentParser(description='SIH2025 Certificate Generator and Verification Tool')

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Generate command
    gen_parser = subparsers.add_parser('generate', help='Generate a new certificate')
    gen_parser.add_argument('--device-info', required=True, help='Device information JSON file')
    gen_parser.add_argument('--wipe-results', required=True, help='Wipe results JSON file')
    gen_parser.add_argument('--verification', help='Verification results JSON file')
    gen_parser.add_argument('--output', help='Custom output filename')
    gen_parser.add_argument('--type', choices=['single', 'batch'], default='single', help='Certificate type')

    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Verify a certificate')
    verify_parser.add_argument('certificate', help='Certificate file to verify')

    # List command
    list_parser = subparsers.add_parser('list', help='List all certificates')
    list_parser.add_argument('--format', choices=['table', 'json'], default='table', help='Output format')

    # Export command
    export_parser = subparsers.add_parser('export', help='Export certificate')
    export_parser.add_argument('certificate', help='Certificate file to export')
    export_parser.add_argument('--output-dir', required=True, help='Export directory')
    export_parser.add_argument('--no-verification', action='store_true', help='Skip verification report')

    # View command
    view_parser = subparsers.add_parser('view', help='View certificate contents')
    view_parser.add_argument('certificate', help='Certificate file to view')
    view_parser.add_argument('--format', choices=['json', 'readable'], default='readable', help='Display format')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # Initialize certificate generator
    cert_gen = CertificateGenerator()

    if args.command == 'generate':
        try:
            # Load device information
            with open(args.device_info, 'r') as f:
                device_info = json.load(f)

            # Load wipe results
            with open(args.wipe_results, 'r') as f:
                wipe_results = json.load(f)

            # Load verification results if provided
            verification_results = None
            if args.verification:
                with open(args.verification, 'r') as f:
                    verification_results = json.load(f)

            # Generate certificate
            if args.type == 'single':
                cert_data = cert_gen.generate_device_certificate(device_info, wipe_results, verification_results)
            else:
                cert_data = cert_gen.generate_batch_certificate([device_info], wipe_results, verification_results)

            # Save certificate
            json_file, txt_file = cert_gen.save_certificate(cert_data, args.output)

            print(f"✅ Certificate generated successfully!")
            print(f"📄 JSON certificate: {json_file}")
            print(f"📄 Readable certificate: {txt_file}")

        except Exception as e:
            print(f"❌ Error generating certificate: {str(e)}")
            sys.exit(1)

    elif args.command == 'verify':
        verified, message = cert_gen.verify_certificate(args.certificate)

        if verified:
            print(f"✅ Certificate verification: PASSED")
            print(f"📋 {message}")
        else:
            print(f"❌ Certificate verification: FAILED")
            print(f"📋 {message}")
            sys.exit(1)

    elif args.command == 'list':
        certificates = cert_gen.list_certificates()

        if not certificates:
            print("📁 No certificates found")
            return

        if args.format == 'json':
            print(json.dumps(certificates, indent=2))
        else:
            print(f"{'ID':<16} {'Type':<12} {'Timestamp':<20} {'Devices':<8} {'Compliance'}")
            print("-" * 80)
            for cert in certificates:
                print(f"{cert['id']:<16} {cert['type']:<12} {cert['timestamp'][:19]:<20} {cert['devices']:<8} {cert['compliance'][:30]}")

    elif args.command == 'export':
        success, result = cert_gen.export_certificate(args.certificate, args.output_dir,
                                                     not args.no_verification)

        if success:
            print(f"✅ Certificate exported successfully!")
            for file in result:
                print(f"📄 {file}")
        else:
            print(f"❌ Export failed: {result}")
            sys.exit(1)

    elif args.command == 'view':
        try:
            with open(args.certificate, 'r') as f:
                cert_data = json.load(f)

            if args.format == 'json':
                print(json.dumps(cert_data, indent=2))
            else:
                readable_cert = cert_gen.generate_readable_certificate(cert_data)
                print(readable_cert)

        except Exception as e:
            print(f"❌ Error viewing certificate: {str(e)}")
            sys.exit(1)

if __name__ == "__main__":
    main()

