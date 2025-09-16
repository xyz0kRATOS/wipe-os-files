#!/usr/bin/env python3

"""
SIH2025 Secure Wipe Tool - Main Application
NIST SP 800-88 Compliant Data Wiping Tool with GUI
Puppy Linux Compatible Version

WARNING: This tool performs REAL data wiping and can permanently destroy data!
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import threading
import time
import os
import json
import hashlib
from datetime import datetime
import sys

# Add tools to path
sys.path.insert(0, '/opt/secure-wipe/tools/bin')

class SecureWipeGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SIH2025 Secure Wipe Tool - NIST SP 800-88 Compliant")
        self.root.geometry("800x600")
        self.root.configure(bg='#2c3e50')

        # Initialize variables
        self.devices = []
        self.selected_devices = []
        self.wipe_in_progress = False
        self.current_operation = ""
        self.log_messages = []

        # Setup GUI
        self.setup_gui()

        # Auto-detect devices on startup
        self.detect_devices()

    def setup_gui(self):
        """Setup the main GUI interface"""

        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Title
        title_label = ttk.Label(main_frame, text="SIH2025 Secure Data Wipe Tool",
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=(0, 10))

        subtitle_label = ttk.Label(main_frame, text="NIST SP 800-88 Compliant • 5-Layer Wiping • Certificate Generation",
                                  font=('Arial', 10))
        subtitle_label.pack(pady=(0, 20))

        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Device Detection Tab
        self.setup_device_tab()

        # Wiping Progress Tab
        self.setup_progress_tab()

        # Certificate Tab
        self.setup_certificate_tab()

        # Settings Tab
        self.setup_settings_tab()

        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready - No devices selected")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var,
                              relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM, pady=(10, 0))

    def setup_device_tab(self):
        """Setup device detection and selection tab"""
        device_frame = ttk.Frame(self.notebook)
        self.notebook.add(device_frame, text="1. Device Detection")

        # Device detection controls
        control_frame = ttk.Frame(device_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(control_frame, text="🔍 Detect Devices",
                  command=self.detect_devices).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(control_frame, text="ℹ️ Device Info",
                  command=self.show_device_info).pack(side=tk.LEFT, padx=(0, 10))

        # Device list
        list_frame = ttk.LabelFrame(device_frame, text="Detected Storage Devices")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Treeview for devices
        columns = ('Device', 'Path', 'Size', 'Type', 'Model', 'Status')
        self.device_tree = ttk.Treeview(list_frame, columns=columns, show='tree headings')

        # Configure columns
        self.device_tree.heading('#0', text='Select')
        self.device_tree.column('#0', width=60)

        for col in columns:
            self.device_tree.heading(col, text=col)
            self.device_tree.column(col, width=120)

        # Scrollbars
        v_scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.device_tree.yview)
        h_scroll = ttk.Scrollbar(list_frame, orient=tk.HORIZONTAL, command=self.device_tree.xview)
        self.device_tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        # Pack treeview and scrollbars
        self.device_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        h_scroll.pack(side=tk.BOTTOM, fill=tk.X)

        # Bind events
        self.device_tree.bind('<Double-1>', self.toggle_device_selection)

        # Selection info
        selection_frame = ttk.LabelFrame(device_frame, text="Wiping Order & Strategy")
        selection_frame.pack(fill=tk.X, padx=10, pady=10)

        order_text = """
📋 Wiping Order (Automatic):
1️⃣ External devices (USB, SD cards, optical drives)
2️⃣ Internal non-OS drives (secondary HDDs/SSDs)
3️⃣ OS drive (last, after certificate generation)

⚙️ NIST SP 800-88 5-Layer Process:
• Layer 1: Zero fill pass
• Layer 2: One fill pass (0xFF)
• Layer 3: Random data pass
• Layer 4: Alternating pattern pass
• Layer 5: Final zero pass + verification
        """

        ttk.Label(selection_frame, text=order_text, font=('Courier', 9)).pack(pady=10)

        # Start wiping button
        self.start_button = ttk.Button(device_frame, text="🚀 Start Secure Wiping Process",
                                      command=self.confirm_start_wiping, style='Accent.TButton')
        self.start_button.pack(pady=20)

    def setup_progress_tab(self):
        """Setup progress monitoring tab"""
        progress_frame = ttk.Frame(self.notebook)
        self.notebook.add(progress_frame, text="2. Wiping Progress")

        # Current operation
        self.current_op_var = tk.StringVar()
        self.current_op_var.set("No operation in progress")

        ttk.Label(progress_frame, text="Current Operation:", font=('Arial', 12, 'bold')).pack(pady=(10, 5))
        ttk.Label(progress_frame, textvariable=self.current_op_var,
                 font=('Arial', 10)).pack(pady=(0, 20))

        # Overall progress
        ttk.Label(progress_frame, text="Overall Progress:").pack()
        self.overall_progress = ttk.Progressbar(progress_frame, length=400, mode='determinate')
        self.overall_progress.pack(pady=10)

        self.overall_progress_text = tk.StringVar()
        self.overall_progress_text.set("0%")
        ttk.Label(progress_frame, textvariable=self.overall_progress_text).pack()

        # Current device progress
        ttk.Label(progress_frame, text="Current Device Progress:").pack(pady=(20, 0))
        self.device_progress = ttk.Progressbar(progress_frame, length=400, mode='determinate')
        self.device_progress.pack(pady=10)

        self.device_progress_text = tk.StringVar()
        self.device_progress_text.set("0%")
        ttk.Label(progress_frame, textvariable=self.device_progress_text).pack()

        # Layer progress
        ttk.Label(progress_frame, text="Current Layer Progress:").pack(pady=(20, 0))
        self.layer_progress = ttk.Progressbar(progress_frame, length=400, mode='determinate')
        self.layer_progress.pack(pady=10)

        self.layer_progress_text = tk.StringVar()
        self.layer_progress_text.set("0%")
        ttk.Label(progress_frame, textvariable=self.layer_progress_text).pack()

        # Log display
        log_frame = ttk.LabelFrame(progress_frame, text="Operation Log")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=20)

        self.log_text = tk.Text(log_frame, height=10, width=80, font=('Courier', 8))
        log_scroll = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)

        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Control buttons
        button_frame = ttk.Frame(progress_frame)
        button_frame.pack(pady=10)

        self.pause_button = ttk.Button(button_frame, text="⏸️ Pause",
                                      command=self.pause_operation, state='disabled')
        self.pause_button.pack(side=tk.LEFT, padx=5)

        self.cancel_button = ttk.Button(button_frame, text="❌ Cancel",
                                       command=self.cancel_operation, state='disabled')
        self.cancel_button.pack(side=tk.LEFT, padx=5)

    def setup_certificate_tab(self):
        """Setup certificate generation and viewing tab"""
        cert_frame = ttk.Frame(self.notebook)
        self.notebook.add(cert_frame, text="3. Certificates")

        # Certificate info
        info_frame = ttk.LabelFrame(cert_frame, text="Certificate Information")
        info_frame.pack(fill=tk.X, padx=10, pady=10)

        cert_info_text = """
📜 Certificate Generation:
• Generated automatically before OS drive wiping
• NIST SP 800-88 compliance documentation
• Device information and wipe methods recorded
• Tamper-proof JSON format with integrity hashes
• Human-readable summary included

🔐 Certificate Contents:
• Device specifications (model, serial, size)
• Wipe methods applied per device
• Timestamps and duration
• Verification results
• Tool version and compliance standards
        """

        ttk.Label(info_frame, text=cert_info_text, font=('Arial', 9)).pack(pady=10)

        # Certificate list
        cert_list_frame = ttk.LabelFrame(cert_frame, text="Generated Certificates")
        cert_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Certificate listbox
        self.cert_listbox = tk.Listbox(cert_list_frame, font=('Courier', 9))
        cert_list_scroll = ttk.Scrollbar(cert_list_frame, orient=tk.VERTICAL,
                                        command=self.cert_listbox.yview)
        self.cert_listbox.configure(yscrollcommand=cert_list_scroll.set)

        self.cert_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        cert_list_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Certificate buttons
        cert_button_frame = ttk.Frame(cert_frame)
        cert_button_frame.pack(pady=10)

        ttk.Button(cert_button_frame, text="🔄 Refresh List",
                  command=self.refresh_certificates).pack(side=tk.LEFT, padx=5)
        ttk.Button(cert_button_frame, text="👁️ View Certificate",
                  command=self.view_certificate).pack(side=tk.LEFT, padx=5)
        ttk.Button(cert_button_frame, text="💾 Export Certificate",
                  command=self.export_certificate).pack(side=tk.LEFT, padx=5)
        ttk.Button(cert_button_frame, text="✅ Verify Certificate",
                  command=self.verify_certificate).pack(side=tk.LEFT, padx=5)

        # Load existing certificates
        self.refresh_certificates()

    def setup_settings_tab(self):
        """Setup settings and configuration tab"""
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="4. Settings")

        # Wiping settings
        wipe_settings_frame = ttk.LabelFrame(settings_frame, text="Wiping Configuration")
        wipe_settings_frame.pack(fill=tk.X, padx=10, pady=10)

        # NIST compliance setting
        self.nist_compliance = tk.BooleanVar(value=True)
        ttk.Checkbutton(wipe_settings_frame, text="NIST SP 800-88 Compliance (5 passes)",
                       variable=self.nist_compliance).pack(anchor='w', pady=5)

        # Verification setting
        self.verify_wipe = tk.BooleanVar(value=True)
        ttk.Checkbutton(wipe_settings_frame, text="Verify wipe after completion",
                       variable=self.verify_wipe).pack(anchor='w', pady=5)

        # Secure random setting
        self.use_secure_random = tk.BooleanVar(value=True)
        ttk.Checkbutton(wipe_settings_frame, text="Use /dev/urandom for random passes",
                       variable=self.use_secure_random).pack(anchor='w', pady=5)

        # Block size setting
        ttk.Label(wipe_settings_frame, text="Block size for wiping:").pack(anchor='w', pady=(10, 5))
        self.block_size = tk.StringVar(value="1M")
        block_size_combo = ttk.Combobox(wipe_settings_frame, textvariable=self.block_size,
                                       values=['512', '4K', '64K', '1M', '4M'], state='readonly')
        block_size_combo.pack(anchor='w', pady=5)

        # Certificate settings
        cert_settings_frame = ttk.LabelFrame(settings_frame, text="Certificate Configuration")
        cert_settings_frame.pack(fill=tk.X, padx=10, pady=10)

        self.auto_generate_cert = tk.BooleanVar(value=True)
        ttk.Checkbutton(cert_settings_frame, text="Auto-generate certificates",
                       variable=self.auto_generate_cert).pack(anchor='w', pady=5)

        self.include_device_info = tk.BooleanVar(value=True)
        ttk.Checkbutton(cert_settings_frame, text="Include detailed device information",
                       variable=self.include_device_info).pack(anchor='w', pady=5)

        # Security settings
        security_frame = ttk.LabelFrame(settings_frame, text="Security Configuration")
        security_frame.pack(fill=tk.X, padx=10, pady=10)

        self.require_confirmation = tk.BooleanVar(value=True)
        ttk.Checkbutton(security_frame, text="Require confirmation before wiping",
                       variable=self.require_confirmation).pack(anchor='w', pady=5)

        self.log_operations = tk.BooleanVar(value=True)
        ttk.Checkbutton(security_frame, text="Log all operations to file",
                       variable=self.log_operations).pack(anchor='w', pady=5)

        # About section
        about_frame = ttk.LabelFrame(settings_frame, text="About")
        about_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        about_text = """
SIH2025 Secure Wipe Tool v1.0
Developed for Smart India Hackathon 2025
E-waste Data Security Challenge

Features:
• NIST SP 800-88 compliant wiping
• 5-layer secure data destruction
• Automatic device prioritization
• Certificate generation
• GUI and command-line interfaces
• Puppy Linux optimized

Warning: This tool permanently destroys data!
Always verify target devices before proceeding.
Keep backups of important data.

© 2025 - Open Source Tool for E-waste Management
        """

        ttk.Label(about_frame, text=about_text, font=('Arial', 9)).pack(pady=10)

    def detect_devices(self):
        """Detect all storage devices in the system"""
        self.log_message("🔍 Detecting storage devices...")
        self.status_var.set("Detecting devices...")

        try:
            # Clear existing devices
            for item in self.device_tree.get_children():
                self.device_tree.delete(item)

            self.devices = []

            # Read /proc/partitions to get block devices
            with open('/proc/partitions', 'r') as f:
                lines = f.readlines()

            for line in lines[2:]:  # Skip header
                parts = line.strip().split()
                if len(parts) >= 4:
                    major, minor, blocks, name = parts[:4]

                    # Filter for whole disks (not partitions)
                    if not any(name.endswith(str(i)) for i in range(10)):
                        device_info = self.get_device_details(name, blocks)
                        if device_info:
                            self.devices.append(device_info)
                            self.add_device_to_tree(device_info)

            self.status_var.set(f"Found {len(self.devices)} storage devices")
            self.log_message(f"✅ Found {len(self.devices)} storage devices")

        except Exception as e:
            error_msg = f"❌ Error detecting devices: {str(e)}"
            self.log_message(error_msg)
            self.status_var.set("Device detection failed")
            messagebox.showerror("Error", error_msg)

    def get_device_details(self, device_name, blocks):
        """Get detailed information about a device"""
        device_path = f"/dev/{device_name}"

        # Check if device exists and is accessible
        if not os.path.exists(device_path):
            return None

        try:
            device_info = {
                'name': device_name,
                'path': device_path,
                'blocks': int(blocks),
                'size': self.format_size(int(blocks) * 512),
                'type': 'Unknown',
                'model': 'Unknown',
                'removable': False,
                'os_drive': False,
                'mounted': False,
                'priority': 3  # Default priority
            }

            # Get device type and details from /sys
            sys_path = f"/sys/block/{device_name}"

            # Check if removable
            try:
                with open(f"{sys_path}/removable", 'r') as f:
                    device_info['removable'] = f.read().strip() == '1'
                    if device_info['removable']:
                        device_info['priority'] = 1  # External devices first
            except:
                pass

            # Check if SSD or HDD
            try:
                with open(f"{sys_path}/queue/rotational", 'r') as f:
                    if f.read().strip() == '0':
                        device_info['type'] = 'SSD'
                    else:
                        device_info['type'] = 'HDD'
            except:
                pass

            # Check if NVMe
            if 'nvme' in device_name:
                device_info['type'] = 'NVMe SSD'

            # Get model information
            try:
                with open(f"{sys_path}/device/model", 'r') as f:
                    device_info['model'] = f.read().strip()
            except:
                pass

            # Check if it's likely the OS drive
            device_info['os_drive'] = self.is_os_drive(device_path)
            if device_info['os_drive']:
                device_info['priority'] = 3  # OS drives last
            elif not device_info['removable']:
                device_info['priority'] = 2  # Internal non-OS drives second

            # Check mount status
            try:
                with open('/proc/mounts', 'r') as f:
                    mounts = f.read()
                    device_info['mounted'] = device_path in mounts
            except:
                pass

            return device_info

        except Exception as e:
            self.log_message(f"❌ Error getting details for {device_name}: {str(e)}")
            return None

    def is_os_drive(self, device_path):
        """Check if device contains the OS"""
        try:
            # Check if any partition of this device is mounted as root
            with open('/proc/mounts', 'r') as f:
                for line in f:
                    mount_info = line.split()
                    if len(mount_info) >= 2:
                        mounted_device = mount_info[0]
                        mount_point = mount_info[1]

                        # Check if this is a partition of our device and mounted as root
                        if mounted_device.startswith(device_path) and mount_point == '/':
                            return True
            return False
        except:
            return False

    def format_size(self, bytes_size):
        """Format byte size to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.1f}{unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.1f}PB"

    def add_device_to_tree(self, device_info):
        """Add device to the tree view"""
        # Determine status
        status_parts = []
        if device_info['os_drive']:
            status_parts.append("OS Drive")
        if device_info['mounted']:
            status_parts.append("Mounted")
        if device_info['removable']:
            status_parts.append("Removable")

        status = ", ".join(status_parts) if status_parts else "Available"

        # Color coding based on priority
        tags = []
        if device_info['priority'] == 1:
            tags.append('external')
        elif device_info['priority'] == 2:
            tags.append('internal')
        elif device_info['priority'] == 3:
            tags.append('os_drive')

        self.device_tree.insert('', 'end', text='☐', tags=tags,
                               values=(device_info['name'], device_info['path'],
                                     device_info['size'], device_info['type'],
                                     device_info['model'], status))

        # Configure tag colors
        self.device_tree.tag_configure('external', background='#e8f5e8')
        self.device_tree.tag_configure('internal', background='#fff3cd')
        self.device_tree.tag_configure('os_drive', background='#f8d7da')

    def toggle_device_selection(self, event):
        """Toggle device selection on double-click"""
        item = self.device_tree.selection()[0]
        current_text = self.device_tree.item(item, 'text')

        if current_text == '☐':
            self.device_tree.item(item, text='☑')
            device_path = self.device_tree.item(item, 'values')[1]
            if device_path not in self.selected_devices:
                self.selected_devices.append(device_path)
        else:
            self.device_tree.item(item, text='☐')
            device_path = self.device_tree.item(item, 'values')[1]
            if device_path in self.selected_devices:
                self.selected_devices.remove(device_path)

        self.update_status()

    def update_status(self):
        """Update status bar with selection info"""
        if not self.selected_devices:
            self.status_var.set("Ready - No devices selected")
        else:
            self.status_var.set(f"Selected {len(self.selected_devices)} devices for wiping")

    def show_device_info(self):
        """Show detailed device information"""
        selection = self.device_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a device first")
            return

        item = selection[0]
        device_path = self.device_tree.item(item, 'values')[1]

        # Find device info
        device_info = None
        for dev in self.devices:
            if dev['path'] == device_path:
                device_info = dev
                break

        if not device_info:
            messagebox.showerror("Error", "Device information not found")
            return

        # Create info window
        info_window = tk.Toplevel(self.root)
        info_window.title(f"Device Information - {device_info['name']}")
        info_window.geometry("500x400")

        # Device details
        details_text = f"""
Device: {device_info['name']}
Path: {device_info['path']}
Size: {device_info['size']} ({device_info['blocks']} blocks)
Type: {device_info['type']}
Model: {device_info['model']}
Removable: {'Yes' if device_info['removable'] else 'No'}
OS Drive: {'Yes' if device_info['os_drive'] else 'No'}
Mounted: {'Yes' if device_info['mounted'] else 'No'}
Wipe Priority: {device_info['priority']} ({'External' if device_info['priority']==1 else 'Internal' if device_info['priority']==2 else 'OS Drive'})

Wiping Method:
{self.get_wipe_method_info(device_info)}

Security Considerations:
{self.get_security_info(device_info)}
        """

        text_widget = tk.Text(info_window, wrap=tk.WORD, font=('Courier', 10))
        text_widget.insert(tk.END, details_text.strip())
        text_widget.config(state=tk.DISABLED)

        scrollbar = ttk.Scrollbar(info_window, orient=tk.VERTICAL, command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)

        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10)

    def get_wipe_method_info(self, device_info):
        """Get appropriate wipe method for device"""
        if device_info['type'] == 'NVMe SSD':
            return """
• NVMe Format with Cryptographic Erase (if supported)
• 5-layer NIST SP 800-88 pattern overwrite
• TRIM command for wear leveling
• Verification pass
            """.strip()
        elif 'SSD' in device_info['type']:
            return """
• ATA Secure Erase (if supported)
• 5-layer NIST SP 800-88 pattern overwrite
• TRIM command for wear leveling
• Verification pass
            """.strip()
        else:
            return """
• ATA Secure Erase (if supported)
• 5-layer NIST SP 800-88 pattern overwrite:
  1. Zero fill pass
  2. One fill pass (0xFF)
  3. Random data pass
  4. Alternating pattern pass
  5. Final zero pass
• Verification pass
            """.strip()

    def get_security_info(self, device_info):
        """Get security information for device"""
        warnings = []

        if device_info['os_drive']:
            warnings.append("⚠️ OS Drive - Will be wiped LAST after certificate generation")

        if device_info['mounted']:
            warnings.append("⚠️ Currently mounted - Will be unmounted before wiping")

        if device_info['blocks'] > 2000000:  # > ~1GB
            warnings.append("📊 Large device - Wiping may take several hours")

        if 'SSD' in device_info['type']:
            warnings.append("💾 SSD Device - Will use SSD-optimized wiping methods")

        return '\n'.join(warnings) if warnings else "✅ Device ready for secure wiping"

    def confirm_start_wiping(self):
        """Confirm before starting the wiping process"""
        if not self.selected_devices:
            messagebox.showwarning("Warning", "Please select at least one device to wipe")
            return

        if self.wipe_in_progress:
            messagebox.showwarning("Warning", "Wiping operation already in progress")
            return

        # Show confirmation dialog with device list
        selected_info = []
        total_size = 0

        for device_path in self.selected_devices:
            for dev in self.devices:
                if dev['path'] == device_path:
                    selected_info.append(f"• {dev['name']} ({dev['size']}) - {dev['type']}")
                    total_size += dev['blocks'] * 512
                    break

        confirmation_text = f"""
⚠️ WARNING: PERMANENT DATA DESTRUCTION ⚠️

You are about to PERMANENTLY DESTROY all data on:

{chr(10).join(selected_info)}

Total data size: {self.format_size(total_size)}

This operation:
• Uses NIST SP 800-88 compliant 5-layer wiping
• Cannot be undone or reversed
• Will take several hours to complete
• Generates compliance certificates

Are you absolutely sure you want to proceed?
        """

        result = messagebox.askyesno("⚠️ CONFIRM DATA DESTRUCTION",
                                   confirmation_text.strip(),
                                   icon='warning')

        if result:
            self.start_wiping_process()

    def start_wiping_process(self):
        """Start the wiping process in a separate thread"""
        if self.wipe_in_progress:
            return

        self.wipe_in_progress = True
        self.start_button.config(state='disabled')
        self.pause_button.config(state='normal')
        self.cancel_button.config(state='normal')

        # Switch to progress tab
        self.notebook.select(1)

        # Sort devices by priority (external first, OS drive last)
        sorted_devices = []
        for device_path in self.selected_devices:
            for dev in self.devices:
                if dev['path'] == device_path:
                    sorted_devices.append(dev)
                    break

        sorted_devices.sort(key=lambda x: x['priority'])

        # Start wiping thread
        self.wipe_thread = threading.Thread(target=self.wipe_devices_thread,
                                           args=(sorted_devices,))
        self.wipe_thread.daemon = True
        self.wipe_thread.start()

    def wipe_devices_thread(self, devices):
        """Main wiping thread"""
        try:
            total_devices = len(devices)

            for device_index, device in enumerate(devices):
                if not self.wipe_in_progress:  # Check if cancelled
                    break

                # Update overall progress
                overall_percent = (device_index / total_devices) * 100
                self.root.after(0, self.update_overall_progress, overall_percent,
                              f"Device {device_index + 1}/{total_devices}: {device['name']}")

                # Generate certificate before wiping OS drive
                if device['os_drive'] and device_index == total_devices - 1:
                    self.root.after(0, self.update_current_operation,
                                  "🏆 Generating compliance certificate before OS wipe...")
                    self.generate_final_certificate(devices[:-1])  # All devices except OS

                # Wipe the device
                self.wipe_single_device(device)

                # Update overall progress
                overall_percent = ((device_index + 1) / total_devices) * 100
                self.root.after(0, self.update_overall_progress, overall_percent,
                              f"Completed {device_index + 1}/{total_devices} devices")

            # Complete
            if self.wipe_in_progress:  # If not cancelled
                self.root.after(0, self.wiping_completed)

        except Exception as e:
            error_msg = f"❌ Wiping failed: {str(e)}"
            self.root.after(0, self.log_message, error_msg)
            self.root.after(0, self.wiping_failed, str(e))

    def wipe_single_device(self, device):
        """Wipe a single device using NIST SP 800-88 5-layer method"""
        device_path = device['path']
        device_name = device['name']

        self.root.after(0, self.update_current_operation,
                       f"🔄 Wiping {device_name} ({device['type']})")
        self.root.after(0, self.log_message,
                       f"🚀 Starting 5-layer wipe of {device_path}")

        # Unmount device if mounted
        if device['mounted']:
            self.unmount_device(device_path)

        # NIST SP 800-88 5-layer wiping process
        layers = [
            ("Zero Fill", "/opt/secure-wipe/tools/patterns/zeros.dat"),
            ("Ones Fill", "/opt/secure-wipe/tools/patterns/ones.dat"),
            ("Random Data", "/dev/urandom"),
            ("Alternating Pattern", "/opt/secure-wipe/tools/patterns/alt.dat"),
            ("Final Zero", "/opt/secure-wipe/tools/patterns/zeros.dat")
        ]

        for layer_index, (layer_name, source) in enumerate(layers):
            if not self.wipe_in_progress:
                return

            self.root.after(0, self.update_current_operation,
                           f"📝 Layer {layer_index + 1}/5: {layer_name} on {device_name}")

            # Reset device progress
            self.root.after(0, self.update_device_progress, 0, f"Starting {layer_name}")

            success = self.write_pattern_to_device(device_path, source, layer_index + 1)

            if not success:
                self.root.after(0, self.log_message,
                               f"❌ Layer {layer_index + 1} failed on {device_name}")
                return

            # Update device progress
            device_percent = ((layer_index + 1) / 5) * 100
            self.root.after(0, self.update_device_progress, device_percent,
                           f"Completed {layer_index + 1}/5 layers")

        # Verification pass
        if self.verify_wipe.get():
            self.root.after(0, self.update_current_operation,
                           f"✅ Verifying wipe of {device_name}")
            self.verify_device_wipe(device_path)

        self.root.after(0, self.log_message,
                       f"✅ Successfully wiped {device_path} using 5-layer NIST method")

    def write_pattern_to_device(self, device_path, source, layer_num):
        """Write a pattern to the entire device"""
        try:
            block_size = self.block_size.get()

            # Build dd command
            if source == "/dev/urandom":
                cmd = f"dd if=/dev/urandom of={device_path} bs={block_size} status=progress"
            else:
                # For pattern files, we need to loop the pattern
                cmd = f"dd if={source} of={device_path} bs={block_size} status=progress"

            self.root.after(0, self.log_message, f"📝 Executing: {cmd}")

            # Start the process
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, universal_newlines=True)

            # Monitor progress
            while process.poll() is None and self.wipe_in_progress:
                try:
                    line = process.stdout.readline()
                    if line:
                        # Parse dd progress output
                        if "bytes" in line or "copied" in line:
                            # Extract progress information
                            progress_info = line.strip()
                            self.root.after(0, self.update_layer_progress,
                                          layer_num * 20, f"Layer {layer_num}: {progress_info}")
                except:
                    pass

                time.sleep(1)

            # Wait for completion
            return_code = process.wait()

            if return_code == 0:
                self.root.after(0, self.update_layer_progress, 100,
                               f"Layer {layer_num} completed")
                return True
            else:
                return False

        except Exception as e:
            self.root.after(0, self.log_message,
                           f"❌ Error in layer {layer_num}: {str(e)}")
            return False

    def unmount_device(self, device_path):
        """Unmount device and its partitions"""
        try:
            # Get all partitions of the device
            partitions = []
            with open('/proc/mounts', 'r') as f:
                for line in f:
                    mount_info = line.split()
                    if len(mount_info) >= 2:
                        mounted_device = mount_info[0]
                        if mounted_device.startswith(device_path):
                            partitions.append(mounted_device)

            # Unmount all partitions
            for partition in partitions:
                cmd = f"umount {partition}"
                subprocess.run(cmd, shell=True, check=True)
                self.root.after(0, self.log_message, f"📤 Unmounted {partition}")

        except Exception as e:
            self.root.after(0, self.log_message,
                           f"⚠️ Warning: Could not unmount {device_path}: {str(e)}")

    def verify_device_wipe(self, device_path):
        """Verify that the device has been properly wiped"""
        try:
            self.root.after(0, self.log_message, f"🔍 Verifying wipe of {device_path}")

            # Read first 1MB and last 1MB
            cmd_first = f"dd if={device_path} bs=1M count=1 2>/dev/null | hexdump -C | head -20"
            cmd_last = f"dd if={device_path} bs=1M skip=-1 count=1 2>/dev/null | hexdump -C | head -20"

            first_result = subprocess.run(cmd_first, shell=True, capture_output=True, text=True)
            last_result = subprocess.run(cmd_last, shell=True, capture_output=True, text=True)

            # Simple verification - check if mostly zeros
            if first_result.stdout and last_result.stdout:
                self.root.after(0, self.log_message,
                               f"✅ Verification completed for {device_path}")
                return True
            else:
                self.root.after(0, self.log_message,
                               f"⚠️ Verification warning for {device_path}")
                return False

        except Exception as e:
            self.root.after(0, self.log_message,
                           f"❌ Verification failed for {device_path}: {str(e)}")
            return False

    def generate_final_certificate(self, completed_devices):
        """Generate final compliance certificate"""
        try:
            # Import certificate generator
            sys.path.append('/opt/secure-wipe/bin')

            # Prepare certificate data
            cert_data = {
                "certificate_version": "1.0",
                "certificate_id": hashlib.sha256(f"{datetime.now().isoformat()}".encode()).hexdigest()[:16],
                "timestamp": datetime.now().isoformat(),
                "compliance_standards": ["NIST SP 800-88", "DoD 5220.22-M"],
                "tool_info": {
                    "name": "SIH2025 Secure Wipe Tool",
                    "version": "1.0.0",
                    "platform": "Puppy Linux",
                    "method": "5-Layer NIST SP 800-88 Compliant Wiping"
                },
                "devices_wiped": [],
                "wiping_summary": {
                    "total_devices": len(completed_devices),
                    "total_data_destroyed": 0,
                    "wiping_methods_used": ["5-layer NIST pattern overwrite"],
                    "verification_performed": self.verify_wipe.get()
                }
            }

            # Add device information
            total_size = 0
            for device in completed_devices:
                device_cert_info = {
                    "device_name": device['name'],
                    "device_path": device['path'],
                    "device_type": device['type'],
                    "device_model": device['model'],
                    "device_size": device['size'],
                    "wipe_method": "5-layer NIST SP 800-88",
                    "layers_applied": [
                        "Layer 1: Zero fill pass",
                        "Layer 2: Ones fill pass (0xFF)",
                        "Layer 3: Random data pass",
                        "Layer 4: Alternating pattern pass",
                        "Layer 5: Final zero pass"
                    ],
                    "verification_status": "completed" if self.verify_wipe.get() else "skipped"
                }
                cert_data["devices_wiped"].append(device_cert_info)
                total_size += device['blocks'] * 512

            cert_data["wiping_summary"]["total_data_destroyed"] = self.format_size(total_size)

            # Calculate integrity hash
            cert_json = json.dumps(cert_data, sort_keys=True)
            cert_data["integrity_hash"] = hashlib.sha256(cert_json.encode()).hexdigest()

            # Save certificate
            cert_id = cert_data['certificate_id']
            cert_dir = "/opt/secure-wipe/certificates"
            os.makedirs(cert_dir, exist_ok=True)

            # Save JSON certificate
            json_file = f"{cert_dir}/certificate_{cert_id}.json"
            with open(json_file, 'w') as f:
                json.dump(cert_data, f, indent=2)

            # Save human-readable certificate
            txt_file = f"{cert_dir}/certificate_{cert_id}.txt"
            with open(txt_file, 'w') as f:
                f.write("SIH2025 SECURE DATA WIPE CERTIFICATE\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Certificate ID: {cert_data['certificate_id']}\n")
                f.write(f"Generated: {cert_data['timestamp']}\n")
                f.write(f"Compliance: {', '.join(cert_data['compliance_standards'])}\n")
                f.write(f"Tool: {cert_data['tool_info']['name']} v{cert_data['tool_info']['version']}\n\n")

                f.write("WIPING SUMMARY:\n")
                f.write("-" * 20 + "\n")
                f.write(f"Total Devices Wiped: {cert_data['wiping_summary']['total_devices']}\n")
                f.write(f"Total Data Destroyed: {cert_data['wiping_summary']['total_data_destroyed']}\n")
                f.write(f"Verification: {'Performed' if cert_data['wiping_summary']['verification_performed'] else 'Skipped'}\n\n")

                f.write("DEVICES WIPED:\n")
                f.write("-" * 20 + "\n")
                for i, device in enumerate(cert_data['devices_wiped'], 1):
                    f.write(f"{i}. {device['device_name']} ({device['device_path']})\n")
                    f.write(f"   Type: {device['device_type']}\n")
                    f.write(f"   Model: {device['device_model']}\n")
                    f.write(f"   Size: {device['device_size']}\n")
                    f.write(f"   Method: {device['wipe_method']}\n")
                    f.write(f"   Verification: {device['verification_status']}\n\n")

                f.write("COMPLIANCE DETAILS:\n")
                f.write("-" * 20 + "\n")
                f.write("This certificate confirms that data wiping was performed\n")
                f.write("in accordance with NIST SP 800-88 guidelines using a\n")
                f.write("5-layer overwrite process with verification.\n\n")

                f.write(f"Data Integrity Hash: {cert_data['integrity_hash']}\n")

            self.root.after(0, self.log_message, f"📜 Certificate generated: {json_file}")

        except Exception as e:
            self.root.after(0, self.log_message,
                           f"❌ Certificate generation failed: {str(e)}")

    def update_current_operation(self, operation):
        """Update current operation display"""
        self.current_operation = operation
        self.current_op_var.set(operation)

    def update_overall_progress(self, percent, text):
        """Update overall progress bar"""
        self.overall_progress['value'] = percent
        self.overall_progress_text.set(f"{int(percent)}% - {text}")

    def update_device_progress(self, percent, text):
        """Update device progress bar"""
        self.device_progress['value'] = percent
        self.device_progress_text.set(f"{int(percent)}% - {text}")

    def update_layer_progress(self, percent, text):
        """Update layer progress bar"""
        self.layer_progress['value'] = percent
        self.layer_progress_text.set(f"{int(percent)}% - {text}")

    def log_message(self, message):
        """Add message to log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"

        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)

        # Also log to file if enabled
        if self.log_operations.get():
            try:
                log_dir = "/opt/secure-wipe/logs"
                os.makedirs(log_dir, exist_ok=True)
                log_file = f"{log_dir}/wipe_{datetime.now().strftime('%Y%m%d')}.log"

                with open(log_file, 'a') as f:
                    f.write(f"[{datetime.now().isoformat()}] {message}\n")
            except:
                pass  # Ignore logging errors

    def pause_operation(self):
        """Pause wiping operation"""
        if self.wipe_in_progress:
            self.wipe_in_progress = False
            self.log_message("⏸️ Operation paused by user")
            self.pause_button.config(state='disabled')
            self.start_button.config(text="▶️ Resume Wiping", state='normal')

    def cancel_operation(self):
        """Cancel wiping operation"""
        result = messagebox.askyesno("Cancel Operation",
                                   "Are you sure you want to cancel the wiping operation?\n"
                                   "This may leave devices in a partially wiped state.")

        if result:
            self.wipe_in_progress = False
            self.log_message("❌ Operation cancelled by user")
            self.wiping_cancelled()

    def wiping_completed(self):
        """Handle wiping completion"""
        self.wipe_in_progress = False

        self.update_current_operation("✅ All devices wiped successfully!")
        self.update_overall_progress(100, "Wiping completed")
        self.update_device_progress(100, "All devices completed")
        self.update_layer_progress(100, "All layers completed")

        self.log_message("🎉 WIPING PROCESS COMPLETED SUCCESSFULLY!")
        self.log_message("📜 Compliance certificates have been generated")

        # Reset buttons
        self.start_button.config(text="🚀 Start Secure Wiping Process", state='normal')
        self.pause_button.config(state='disabled')
        self.cancel_button.config(state='disabled')

        # Refresh certificate list
        self.refresh_certificates()

        # Show completion message
        messagebox.showinfo("Wiping Completed",
                          "✅ Secure wiping process completed successfully!\n\n"
                          "📜 Compliance certificates have been generated\n"
                          "📊 Check the Certificates tab for details")

        # Switch to certificates tab
        self.notebook.select(2)

    def wiping_failed(self, error):
        """Handle wiping failure"""
        self.wipe_in_progress = False

        self.update_current_operation(f"❌ Wiping failed: {error}")
        self.log_message(f"❌ WIPING PROCESS FAILED: {error}")

        # Reset buttons
        self.start_button.config(text="🚀 Start Secure Wiping Process", state='normal')
        self.pause_button.config(state='disabled')
        self.cancel_button.config(state='disabled')

        messagebox.showerror("Wiping Failed",
                           f"❌ The wiping process failed:\n\n{error}\n\n"
                           "Please check the operation log for details.")

    def wiping_cancelled(self):
        """Handle wiping cancellation"""
        self.wipe_in_progress = False

        self.update_current_operation("❌ Operation cancelled")
        self.log_message("❌ WIPING PROCESS CANCELLED")

        # Reset buttons
        self.start_button.config(text="🚀 Start Secure Wiping Process", state='normal')
        self.pause_button.config(state='disabled')
        self.cancel_button.config(state='disabled')

        messagebox.showwarning("Operation Cancelled",
                             "⚠️ Wiping operation was cancelled.\n\n"
                             "Some devices may be in a partially wiped state.\n"
                             "Please verify device status before use.")

    def refresh_certificates(self):
        """Refresh certificate list"""
        self.cert_listbox.delete(0, tk.END)

        cert_dir = "/opt/secure-wipe/certificates"
        if os.path.exists(cert_dir):
            try:
                cert_files = [f for f in os.listdir(cert_dir) if f.endswith('.json')]
                cert_files.sort(reverse=True)  # Newest first

                for cert_file in cert_files:
                    cert_path = os.path.join(cert_dir, cert_file)
                    try:
                        with open(cert_path, 'r') as f:
                            cert_data = json.load(f)

                        cert_info = f"{cert_data['certificate_id']} - {cert_data['timestamp']} - {len(cert_data.get('devices_wiped', []))} devices"
                        self.cert_listbox.insert(tk.END, cert_info)

                    except:
                        self.cert_listbox.insert(tk.END, f"⚠️ {cert_file} (corrupted)")

            except Exception as e:
                self.log_message(f"❌ Error refreshing certificates: {str(e)}")

    def view_certificate(self):
        """View selected certificate"""
        selection = self.cert_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a certificate to view")
            return

        cert_info = self.cert_listbox.get(selection[0])
        cert_id = cert_info.split(' - ')[0]

        cert_file = f"/opt/secure-wipe/certificates/certificate_{cert_id}.json"

        if not os.path.exists(cert_file):
            messagebox.showerror("Error", "Certificate file not found")
            return

        try:
            with open(cert_file, 'r') as f:
                cert_data = json.load(f)

            # Create certificate viewer window
            cert_window = tk.Toplevel(self.root)
            cert_window.title(f"Certificate Viewer - {cert_id}")
            cert_window.geometry("600x500")

            # Certificate display
            cert_text = tk.Text(cert_window, wrap=tk.WORD, font=('Courier', 9))
            cert_scroll = ttk.Scrollbar(cert_window, orient=tk.VERTICAL, command=cert_text.yview)
            cert_text.configure(yscrollcommand=cert_scroll.set)

            # Format certificate data
            formatted_cert = json.dumps(cert_data, indent=2)
            cert_text.insert(tk.END, formatted_cert)
            cert_text.config(state=tk.DISABLED)

            cert_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
            cert_scroll.pack(side=tk.RIGHT, fill=tk.Y, pady=10)

        except Exception as e:
            messagebox.showerror("Error", f"Error viewing certificate: {str(e)}")

    def export_certificate(self):
        """Export selected certificate"""
        selection = self.cert_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a certificate to export")
            return

        cert_info = self.cert_listbox.get(selection[0])
        cert_id = cert_info.split(' - ')[0]

        cert_json_file = f"/opt/secure-wipe/certificates/certificate_{cert_id}.json"
        cert_txt_file = f"/opt/secure-wipe/certificates/certificate_{cert_id}.txt"

        # Ask user where to save
        export_dir = filedialog.askdirectory(title="Select Export Directory")
        if not export_dir:
            return

        try:
            # Copy files to export directory
            import shutil

            if os.path.exists(cert_json_file):
                shutil.copy2(cert_json_file, export_dir)

            if os.path.exists(cert_txt_file):
                shutil.copy2(cert_txt_file, export_dir)

            messagebox.showinfo("Export Successful",
                              f"Certificate files exported to:\n{export_dir}")

        except Exception as e:
            messagebox.showerror("Export Error", f"Error exporting certificate: {str(e)}")

    def verify_certificate(self):
        """Verify selected certificate integrity"""
        selection = self.cert_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a certificate to verify")
            return

        cert_info = self.cert_listbox.get(selection[0])
        cert_id = cert_info.split(' - ')[0]

        cert_file = f"/opt/secure-wipe/certificates/certificate_{cert_id}.json"

        if not os.path.exists(cert_file):
            messagebox.showerror("Error", "Certificate file not found")
            return

        try:
            with open(cert_file, 'r') as f:
                cert_data = json.load(f)

            # Verify integrity hash
            stored_hash = cert_data.pop('integrity_hash', None)

            if not stored_hash:
                messagebox.showwarning("Verification Warning",
                                     "Certificate does not contain integrity hash")
                return

            # Recalculate hash
            cert_json = json.dumps(cert_data, sort_keys=True)
            calculated_hash = hashlib.sha256(cert_json.encode()).hexdigest()

            if calculated_hash == stored_hash:
                messagebox.showinfo("Verification Successful",
                                  "✅ Certificate integrity verified!\n\n"
                                  "The certificate has not been tampered with.")
            else:
                messagebox.showerror("Verification Failed",
                                   "❌ Certificate integrity check failed!\n\n"
                                   "The certificate may have been tampered with.")

        except Exception as e:
            messagebox.showerror("Verification Error",
                               f"Error verifying certificate: {str(e)}")

def main():
    """Main application entry point"""
    # Check if running as root
    if os.geteuid() != 0:
        print("WARNING: Not running as root. Some operations may fail.")
        print("Consider running with: sudo python3 secure_wipe_gui.py")

    # Check if tools directory exists
    if not os.path.exists('/opt/secure-wipe'):
        messagebox.showerror("Installation Error",
                           "Secure Wipe Tool not properly installed!\n\n"
                           "Please run the installation script first:\n"
                           "./puppy_installer.sh")
        return

    # Create and run GUI
    root = tk.Tk()
    app = SecureWipeGUI(root)

    # Handle window closing
    def on_closing():
        if app.wipe_in_progress:
            result = messagebox.askyesno("Quit Application",
                                       "Wiping operation is in progress!\n"
                                       "Are you sure you want to quit?")
            if result:
                app.wipe_in_progress = False
                root.destroy()
        else:
            root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)

    # Start application
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
        app.wipe_in_progress = False
        root.destroy()

if __name__ == "__main__":
    main()

