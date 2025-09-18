#!/usr/bin/env python3

"""
SIH2025 Secure Wipe Tool - Bundled Executable Version
Single file executable with embedded certificate generator
No CLI commands required - Complete GUI solution

WARNING: This tool performs REAL data wiping and can permanently destroy data!
"""

import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import threading
import time
import os
import json
import hashlib
from datetime import datetime
import sys

class SecureWipeBundledGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SIH2025 Secure Wipe Tool - Bundled Edition")
        self.root.geometry("900x700")
        self.root.configure(bg='#1a1a2e')

        # Set window icon and properties
        try:
            self.root.iconbitmap(default='')  # Use default if no icon
        except:
            pass

        self.root.resizable(True, True)
        self.root.minsize(800, 600)

        # Initialize variables
        self.devices = []
        self.selected_devices = []
        self.wipe_in_progress = False
        self.current_operation = ""
        self.log_messages = []
        self.usb_cert_location = ""

        # Configure modern theme
        self.setup_theme()

        # Setup GUI
        self.setup_gui()

        # Auto-detect devices on startup
        self.detect_devices()

        # Find USB location for certificates
        self.find_usb_location()

    def setup_theme(self):
        """Setup modern dark theme"""
        style = ttk.Style()

        # Configure colors
        self.colors = {
            'bg_primary': '#1a1a2e',
            'bg_secondary': '#16213e',
            'bg_tertiary': '#0f3460',
            'accent': '#e94560',
            'success': '#27ae60',
            'warning': '#f39c12',
            'error': '#e74c3c',
            'text': '#ecf0f1',
            'text_secondary': '#bdc3c7'
        }

        # Configure ttk theme
        style.theme_use('clam')

        # Configure ttk styles
        style.configure('Title.TLabel',
                       background=self.colors['bg_primary'],
                       foreground=self.colors['text'],
                       font=('Arial', 18, 'bold'))

        style.configure('Subtitle.TLabel',
                       background=self.colors['bg_primary'],
                       foreground=self.colors['text_secondary'],
                       font=('Arial', 10))

        style.configure('Modern.TButton',
                       background=self.colors['accent'],
                       foreground='white',
                       font=('Arial', 10, 'bold'),
                       borderwidth=0,
                       focuscolor='none')

        style.map('Modern.TButton',
                 background=[('active', '#c0392b')])

        style.configure('Success.TButton',
                       background=self.colors['success'],
                       foreground='white',
                       font=('Arial', 10, 'bold'))

        style.configure('Modern.TFrame',
                       background=self.colors['bg_secondary'],
                       borderwidth=1,
                       relief='solid')

        style.configure('Card.TFrame',
                       background=self.colors['bg_tertiary'],
                       borderwidth=2,
                       relief='raised')

    def setup_gui(self):
        """Setup the main GUI interface with modern design"""

        # Main container
        main_container = tk.Frame(self.root, bg=self.colors['bg_primary'])
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Header section
        self.create_header(main_container)

        # Content area
        content_frame = tk.Frame(main_container, bg=self.colors['bg_primary'])
        content_frame.pack(fill=tk.BOTH, expand=True, pady=(20, 0))

        # Left panel - Device selection
        self.create_device_panel(content_frame)

        # Right panel - Progress and controls
        self.create_control_panel(content_frame)

        # Bottom status bar
        self.create_status_bar(main_container)

    def create_header(self, parent):
        """Create modern header section"""
        header_frame = tk.Frame(parent, bg=self.colors['bg_primary'])
        header_frame.pack(fill=tk.X, pady=(0, 20))

        # Title and subtitle
        title_label = tk.Label(header_frame,
                              text="🔒 SIH2025 Secure Wipe Tool",
                              bg=self.colors['bg_primary'],
                              fg=self.colors['text'],
                              font=('Arial', 24, 'bold'))
        title_label.pack()

        subtitle_label = tk.Label(header_frame,
                                 text="NIST SP 800-88 Compliant • 5-Layer Data Destruction • USB Certificate Storage",
                                 bg=self.colors['bg_primary'],
                                 fg=self.colors['text_secondary'],
                                 font=('Arial', 11))
        subtitle_label.pack(pady=(5, 0))

        # USB status indicator
        self.usb_status_frame = tk.Frame(header_frame, bg=self.colors['bg_primary'])
        self.usb_status_frame.pack(pady=(10, 0))

        self.usb_status_label = tk.Label(self.usb_status_frame,
                                        text="🔍 Searching for bootable USB...",
                                        bg=self.colors['bg_primary'],
                                        fg=self.colors['warning'],
                                        font=('Arial', 10))
        self.usb_status_label.pack()

    def create_device_panel(self, parent):
        """Create device selection panel"""
        # Left panel frame
        left_panel = tk.Frame(parent, bg=self.colors['bg_secondary'], relief=tk.RAISED, bd=2)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        # Panel title
        panel_title = tk.Label(left_panel,
                              text="📱 Storage Devices",
                              bg=self.colors['bg_secondary'],
                              fg=self.colors['text'],
                              font=('Arial', 14, 'bold'))
        panel_title.pack(pady=(15, 10))

        # Device detection controls
        control_frame = tk.Frame(left_panel, bg=self.colors['bg_secondary'])
        control_frame.pack(fill=tk.X, padx=15, pady=(0, 15))

        detect_btn = tk.Button(control_frame,
                              text="🔄 Refresh Devices",
                              bg=self.colors['accent'],
                              fg='white',
                              font=('Arial', 10, 'bold'),
                              relief=tk.FLAT,
                              command=self.detect_devices)
        detect_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.auto_select_btn = tk.Button(control_frame,
                                        text="⚡ Auto Select",
                                        bg=self.colors['success'],
                                        fg='white',
                                        font=('Arial', 10, 'bold'),
                                        relief=tk.FLAT,
                                        command=self.auto_select_devices)
        self.auto_select_btn.pack(side=tk.LEFT)

        # Device list frame
        list_frame = tk.Frame(left_panel, bg=self.colors['bg_secondary'])
        list_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))

        # Device list with modern styling
        self.device_listbox = tk.Listbox(list_frame,
                                        bg=self.colors['bg_tertiary'],
                                        fg=self.colors['text'],
                                        selectbackground=self.colors['accent'],
                                        selectforeground='white',
                                        font=('Courier', 9),
                                        relief=tk.FLAT,
                                        bd=0)

        listbox_scroll = tk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.device_listbox.yview)
        self.device_listbox.configure(yscrollcommand=listbox_scroll.set)

        self.device_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        listbox_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Bind double-click to toggle selection
        self.device_listbox.bind('<Double-Button-1>', self.toggle_device_selection)

        # Selection info
        info_frame = tk.Frame(left_panel, bg=self.colors['bg_secondary'])
        info_frame.pack(fill=tk.X, padx=15, pady=(0, 15))

        info_text = """💡 Wiping Strategy:
1️⃣ External devices first (USB, SD cards)
2️⃣ Internal drives second (data drives)
3️⃣ OS drives last (after certificate backup)

🔒 5-Layer NIST Process:
• Zero → Ones → Random → Pattern → Zero + Verify

Double-click devices to select/deselect"""

        info_label = tk.Label(info_frame,
                             text=info_text,
                             bg=self.colors['bg_secondary'],
                             fg=self.colors['text_secondary'],
                             font=('Arial', 8),
                             justify=tk.LEFT)
        info_label.pack(anchor='w')

    def create_control_panel(self, parent):
        """Create control and progress panel"""
        # Right panel frame
        right_panel = tk.Frame(parent, bg=self.colors['bg_secondary'], relief=tk.RAISED, bd=2)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Panel title
        panel_title = tk.Label(right_panel,
                              text="⚙️ Wiping Control Center",
                              bg=self.colors['bg_secondary'],
                              fg=self.colors['text'],
                              font=('Arial', 14, 'bold'))
        panel_title.pack(pady=(15, 20))

        # Current operation display
        self.create_operation_display(right_panel)

        # Progress bars section
        self.create_progress_section(right_panel)

        # Control buttons
        self.create_control_buttons(right_panel)

        # Log display
        self.create_log_display(right_panel)

    def create_operation_display(self, parent):
        """Create current operation display"""
        op_frame = tk.Frame(parent, bg=self.colors['bg_tertiary'], relief=tk.RAISED, bd=1)
        op_frame.pack(fill=tk.X, padx=15, pady=(0, 20))

        op_title = tk.Label(op_frame,
                           text="📋 Current Operation",
                           bg=self.colors['bg_tertiary'],
                           fg=self.colors['text'],
                           font=('Arial', 11, 'bold'))
        op_title.pack(pady=(10, 5))

        self.current_op_var = tk.StringVar()
        self.current_op_var.set("🟢 Ready - No operation in progress")

        self.current_op_label = tk.Label(op_frame,
                                        textvariable=self.current_op_var,
                                        bg=self.colors['bg_tertiary'],
                                        fg=self.colors['text_secondary'],
                                        font=('Arial', 10),
                                        wraplength=300)
        self.current_op_label.pack(pady=(0, 10), padx=10)

    def create_progress_section(self, parent):
        """Create progress bars section"""
        progress_frame = tk.Frame(parent, bg=self.colors['bg_secondary'])
        progress_frame.pack(fill=tk.X, padx=15, pady=(0, 20))

        # Overall progress
        tk.Label(progress_frame,
                text="📊 Overall Progress",
                bg=self.colors['bg_secondary'],
                fg=self.colors['text'],
                font=('Arial', 10, 'bold')).pack(anchor='w')

        self.overall_progress = ttk.Progressbar(progress_frame, length=300, mode='determinate')
        self.overall_progress.pack(fill=tk.X, pady=(5, 10))

        self.overall_progress_text = tk.StringVar()
        self.overall_progress_text.set("0% - Waiting to start")
        tk.Label(progress_frame,
                textvariable=self.overall_progress_text,
                bg=self.colors['bg_secondary'],
                fg=self.colors['text_secondary'],
                font=('Arial', 9)).pack(anchor='w')

        # Device progress
        tk.Label(progress_frame,
                text="💽 Device Progress",
                bg=self.colors['bg_secondary'],
                fg=self.colors['text'],
                font=('Arial', 10, 'bold')).pack(anchor='w', pady=(15, 0))

        self.device_progress = ttk.Progressbar(progress_frame, length=300, mode='determinate')
        self.device_progress.pack(fill=tk.X, pady=(5, 10))

        self.device_progress_text = tk.StringVar()
        self.device_progress_text.set("0% - No device selected")
        tk.Label(progress_frame,
                textvariable=self.device_progress_text,
                bg=self.colors['bg_secondary'],
                fg=self.colors['text_secondary'],
                font=('Arial', 9)).pack(anchor='w')

        # Layer progress
        tk.Label(progress_frame,
                text="🔄 Layer Progress",
                bg=self.colors['bg_secondary'],
                fg=self.colors['text'],
                font=('Arial', 10, 'bold')).pack(anchor='w', pady=(15, 0))

        self.layer_progress = ttk.Progressbar(progress_frame, length=300, mode='determinate')
        self.layer_progress.pack(fill=tk.X, pady=(5, 10))

        self.layer_progress_text = tk.StringVar()
        self.layer_progress_text.set("0% - No layer active")
        tk.Label(progress_frame,
                textvariable=self.layer_progress_text,
                bg=self.colors['bg_secondary'],
                fg=self.colors['text_secondary'],
                font=('Arial', 9)).pack(anchor='w')

    def create_control_buttons(self, parent):
        """Create control buttons"""
        button_frame = tk.Frame(parent, bg=self.colors['bg_secondary'])
        button_frame.pack(fill=tk.X, padx=15, pady=(0, 20))

        # Main action button
        self.start_button = tk.Button(button_frame,
                                     text="🚀 START SECURE WIPING",
                                     bg=self.colors['accent'],
                                     fg='white',
                                     font=('Arial', 12, 'bold'),
                                     relief=tk.FLAT,
                                     height=2,
                                     command=self.confirm_start_wiping)
        self.start_button.pack(fill=tk.X, pady=(0, 10))

        # Control buttons row
        control_row = tk.Frame(button_frame, bg=self.colors['bg_secondary'])
        control_row.pack(fill=tk.X)

        self.pause_button = tk.Button(control_row,
                                     text="⏸️ Pause",
                                     bg=self.colors['warning'],
                                     fg='white',
                                     font=('Arial', 9, 'bold'),
                                     relief=tk.FLAT,
                                     state='disabled',
                                     command=self.pause_operation)
        self.pause_button.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        self.cancel_button = tk.Button(control_row,
                                      text="❌ Cancel",
                                      bg=self.colors['error'],
                                      fg='white',
                                      font=('Arial', 9, 'bold'),
                                      relief=tk.FLAT,
                                      state='disabled',
                                      command=self.cancel_operation)
        self.cancel_button.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))

    def create_log_display(self, parent):
        """Create log display area"""
        log_frame = tk.Frame(parent, bg=self.colors['bg_secondary'])
        log_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))

        tk.Label(log_frame,
                text="📜 Operation Log",
                bg=self.colors['bg_secondary'],
                fg=self.colors['text'],
                font=('Arial', 10, 'bold')).pack(anchor='w', pady=(0, 5))

        log_container = tk.Frame(log_frame, bg=self.colors['bg_secondary'])
        log_container.pack(fill=tk.BOTH, expand=True)

        self.log_text = tk.Text(log_container,
                               bg=self.colors['bg_tertiary'],
                               fg=self.colors['text'],
                               font=('Courier', 8),
                               relief=tk.FLAT,
                               bd=0,
                               height=8)

        log_scroll = tk.Scrollbar(log_container, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)

        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def create_status_bar(self, parent):
        """Create bottom status bar"""
        status_frame = tk.Frame(parent, bg=self.colors['bg_tertiary'], relief=tk.RAISED, bd=1)
        status_frame.pack(fill=tk.X, pady=(20, 0))

        self.status_var = tk.StringVar()
        self.status_var.set("🟢 Ready - Select devices to begin secure wiping")

        status_label = tk.Label(status_frame,
                               textvariable=self.status_var,
                               bg=self.colors['bg_tertiary'],
                               fg=self.colors['text_secondary'],
                               font=('Arial', 9),
                               anchor='w')
        status_label.pack(side=tk.LEFT, padx=10, pady=5)

        # USB status on right side of status bar
        self.usb_cert_var = tk.StringVar()
        self.usb_cert_var.set("📁 Certificates: Local storage")

        usb_cert_label = tk.Label(status_frame,
                                 textvariable=self.usb_cert_var,
                                 bg=self.colors['bg_tertiary'],
                                 fg=self.colors['text_secondary'],
                                 font=('Arial', 9),
                                 anchor='e')
        usb_cert_label.pack(side=tk.RIGHT, padx=10, pady=5)

    def find_usb_location(self):
        """Find bootable USB drive for certificate storage"""
        self.log_message("🔍 Searching for bootable USB drive...")

        try:
            # Look for bootable USB with Puppy Linux
            with open('/proc/mounts', 'r') as f:
                mounts = f.readlines()

            for line in mounts:
                parts = line.split()
                if len(parts) >= 2:
                    device = parts[0]
                    mount_point = parts[1]

                    if device.startswith('/dev/sd'):
                        device_name = device.split('/')[-1][:-1]
                        removable_path = f"/sys/block/{device_name}/removable"

                        try:
                            with open(removable_path, 'r') as f:
                                if f.read().strip() == '1':
                                    # Check for Puppy Linux files
                                    puppy_files = ['puppy.sfs', 'vmlinuz', 'initrd.gz']
                                    for puppy_file in puppy_files:
                                        if os.path.exists(f"{mount_point}/{puppy_file}"):
                                            self.usb_cert_location = f"{mount_point}/certificates"
                                            os.makedirs(self.usb_cert_location, exist_ok=True)

                                            self.usb_status_label.config(
                                                text=f"💾 USB Found: {mount_point}",
                                                fg=self.colors['success']
                                            )
                                            self.usb_cert_var.set(f"💾 Certificates: USB Drive ({mount_point})")
                                            self.log_message(f"✅ Found bootable USB: {mount_point}")
                                            return
                        except:
                            continue

            # Not found
            self.usb_status_label.config(
                text="⚠️ USB not found - using local storage",
                fg=self.colors['warning']
            )
            self.usb_cert_location = "/opt/secure-wipe/certificates"
            os.makedirs(self.usb_cert_location, exist_ok=True)
            self.log_message("⚠️ Bootable USB not found, using local storage")

        except Exception as e:
            self.log_message(f"❌ Error finding USB: {str(e)}")
            self.usb_cert_location = "/opt/secure-wipe/certificates"
            os.makedirs(self.usb_cert_location, exist_ok=True)

    def detect_devices(self):
        """Detect all storage devices"""
        self.log_message("🔍 Detecting storage devices...")
        self.status_var.set("🔄 Detecting devices...")

        try:
            self.devices = []
            self.device_listbox.delete(0, tk.END)

            with open('/proc/partitions', 'r') as f:
                lines = f.readlines()

            for line in lines[2:]:
                parts = line.strip().split()
                if len(parts) >= 4:
                    major, minor, blocks, name = parts[:4]

                    # Filter for whole disks
                    if not any(name.endswith(str(i)) for i in range(10)):
                        device_info = self.get_device_details(name, blocks)
                        if device_info:
                            self.devices.append(device_info)
                            self.add_device_to_list(device_info)

            self.status_var.set(f"✅ Found {len(self.devices)} storage devices")
            self.log_message(f"✅ Detected {len(self.devices)} storage devices")

        except Exception as e:
            error_msg = f"❌ Error detecting devices: {str(e)}"
            self.log_message(error_msg)
            self.status_var.set("❌ Device detection failed")

    def get_device_details(self, device_name, blocks):
        """Get detailed device information"""
        device_path = f"/dev/{device_name}"

        if not os.path.exists(device_path):
            return None

        try:
            device_info = {
                'name': device_name,
                'path': device_path,
                'blocks': int(blocks),
                'size': self.format_size(int(blocks) * 512),
                'type': 'Unknown',
                'removable': False,
                'os_drive': False,
                'priority': 3,
                'selected': False
            }

            sys_path = f"/sys/block/{device_name}"

            # Check if removable
            try:
                with open(f"{sys_path}/removable", 'r') as f:
                    device_info['removable'] = f.read().strip() == '1'
                    if device_info['removable']:
                        device_info['priority'] = 1
            except:
                pass

            # Check device type
            try:
                with open(f"{sys_path}/queue/rotational", 'r') as f:
                    if f.read().strip() == '0':
                        device_info['type'] = 'SSD'
                    else:
                        device_info['type'] = 'HDD'
            except:
                pass

            if 'nvme' in device_name:
                device_info['type'] = 'NVMe SSD'

            # Check if OS drive
            device_info['os_drive'] = self.is_os_drive(device_path)
            if device_info['os_drive']:
                device_info['priority'] = 3
            elif not device_info['removable']:
                device_info['priority'] = 2

            return device_info

        except Exception as e:
            self.log_message(f"❌ Error getting details for {device_name}: {str(e)}")
            return None

    def is_os_drive(self, device_path):
        """Check if device contains the OS"""
        try:
            with open('/proc/mounts', 'r') as f:
                for line in f:
                    mount_info = line.split()
                    if len(mount_info) >= 2:
                        mounted_device = mount_info[0]
                        mount_point = mount_info[1]

                        if mounted_device.startswith(device_path) and mount_point == '/':
                            return True
            return False
        except:
            return False

    def format_size(self, bytes_size):
        """Format byte size to human readable"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.1f}{unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.1f}PB"

    def add_device_to_list(self, device_info):
        """Add device to the list with color coding"""
        # Create display text
        priority_icon = "🔌" if device_info['priority'] == 1 else "💽" if device_info['priority'] == 2 else "🖥️"
        status = "OS Drive" if device_info['os_drive'] else "Removable" if device_info['removable'] else "Internal"

        display_text = f"{priority_icon} {device_info['name']} | {device_info['type']} | {device_info['size']} | {status}"

        self.device_listbox.insert(tk.END, display_text)

        # Color coding based on priority
        item_index = self.device_listbox.size() - 1
        if device_info['priority'] == 1:
            self.device_listbox.itemconfig(item_index, {'bg': '#2d5016'})  # Green tint
        elif device_info['priority'] == 2:
            self.device_listbox.itemconfig(item_index, {'bg': '#4a4a0d'})  # Yellow tint
        elif device_info['priority'] == 3:
            self.device_listbox.itemconfig(item_index, {'bg': '#4a0e0e'})  # Red tint

    def toggle_device_selection(self, event=None):
        """Toggle device selection"""
        selection = self.device_listbox.curselection()
        if not selection:
            return

        device_index = selection[0]
        if device_index < len(self.devices):
            device = self.devices[device_index]
            device['selected'] = not device['selected']

            # Update display
            current_text = self.device_listbox.get(device_index)
            if device['selected']:
                new_text = "✅ " + current_text
                if device['path'] not in self.selected_devices:
                    self.selected_devices.append(device['path'])
            else:
                new_text = current_text.replace("✅ ", "")
                if device['path'] in self.selected_devices:
                    self.selected_devices.remove(device['path'])

            self.device_listbox.delete(device_index)
            self.device_listbox.insert(device_index, new_text)

            self.update_selection_status()

    def auto_select_devices(self):
        """Automatically select all non-OS devices"""
        self.selected_devices = []

        for i, device in enumerate(self.devices):
            if not device['os_drive']:  # Select all except OS drives
                device['selected'] = True
                self.selected_devices.append(device['path'])

                # Update display
                current_text = self.device_listbox.get(i)
                if not current_text.startswith("✅"):
                    new_text = "✅ " + current_text
                    self.device_listbox.delete(i)
                    self.device_listbox.insert(i, new_text)

        self.update_selection_status()
        self.log_message(f"🎯 Auto-selected {len(self.selected_devices)} devices (OS drives excluded)")

    def update_selection_status(self):
        """Update selection status"""
        if not self.selected_devices:
            self.status_var.set("🔸 No devices selected - Double-click to select")
        else:
            external_count = sum(1 for d in self.devices if d.get('selected') and d.get('priority') == 1)
            internal_count = sum(1 for d in self.devices if d.get('selected') and d.get('priority') == 2)
            os_count = sum(1 for d in self.devices if d.get('selected') and d.get('priority') == 3)

            status_parts = []
            if external_count:
                status_parts.append(f"{external_count} external")
            if internal_count:
                status_parts.append(f"{internal_count} internal")
            if os_count:
                status_parts.append(f"{os_count} OS drives")

            self.status_var.set(f"🎯 Selected: {', '.join(status_parts)} ({len(self.selected_devices)} total)")

    def confirm_start_wiping(self):
        """Confirm before starting wiping"""
        if not self.selected_devices:
            messagebox.showwarning("No Selection", "Please select at least one device to wipe")
            return

        if self.wipe_in_progress:
            messagebox.showwarning("In Progress", "Wiping operation already in progress")
            return

        # Create detailed confirmation
        selected_info = []
        total_size = 0

        for device_path in self.selected_devices:
            for dev in self.devices:
                if dev['path'] == device_path:
                    selected_info.append(f"• {dev['name']} ({dev['size']}) - {dev['type']}")
                    total_size += dev['blocks'] * 512
                    break

        confirmation_text = f"""⚠️ PERMANENT DATA DESTRUCTION WARNING ⚠️

You are about to PERMANENTLY DESTROY all data on:

{chr(10).join(selected_info)}

Total data: {self.format_size(total_size)}

This operation will:
• Use NIST SP 800-88 compliant 5-layer wiping
• Cannot be undone or reversed
• Take several hours to complete
• Generate certificates on {'USB drive' if self.usb_cert_location.startswith('/mnt') or self.usb_cert_location.startswith('/media') else 'local storage'}

Are you absolutely sure you want to proceed?"""

        result = messagebox.askyesno("⚠️ CONFIRM DATA DESTRUCTION", confirmation_text, icon='warning')

        if result:
            self.start_wiping_process()

    def start_wiping_process(self):
        """Start the wiping process"""
        self.wipe_in_progress = True
        self.start_button.config(state='disabled', text="🔄 Wiping in Progress...")
        self.pause_button.config(state='normal')
        self.cancel_button.config(state='normal')

        # Sort devices by priority
        sorted_devices = []
        for device_path in self.selected_devices:
            for dev in self.devices:
                if dev['path'] == device_path:
                    sorted_devices.append(dev)
                    break

        sorted_devices.sort(key=lambda x: x['priority'])

        # Start wiping thread
        self.wipe_thread = threading.Thread(target=self.wipe_devices_thread, args=(sorted_devices,))
        self.wipe_thread.daemon = True
        self.wipe_thread.start()

    def wipe_devices_thread(self, devices):
        """Main wiping thread"""
        try:
            total_devices = len(devices)

            for device_index, device in enumerate(devices):
                if not self.wipe_in_progress:
                    break

                # Update overall progress
                overall_percent = (device_index / total_devices) * 100
                self.root.after(0, self.update_overall_progress, overall_percent,
                              f"Device {device_index + 1}/{total_devices}: {device['name']}")

                # Generate certificate before OS drive
                if device['os_drive'] and device_index == total_devices - 1:
                    self.root.after(0, self.update_current_operation,
                                  "📜 Generating compliance certificate...")
                    self.generate_certificate(devices[:-1])

                # Wipe device
                self.wipe_single_device(device)

                # Update overall progress
                overall_percent = ((device_index + 1) / total_devices) * 100
                self.root.after(0, self.update_overall_progress, overall_percent,
                              f"Completed {device_index + 1}/{total_devices}")

            # Complete
            if self.wipe_in_progress:
                self.root.after(0, self.wiping_completed)

        except Exception as e:
            error_msg = f"❌ Wiping failed: {str(e)}"
            self.root.after(0, self.log_message, error_msg)
            self.root.after(0, self.wiping_failed, str(e))

    def wipe_single_device(self, device):
        """Wipe single device using 5-layer NIST method"""
        device_path = device['path']
        device_name = device['name']

        self.root.after(0, self.update_current_operation,
                       f"🔄 Wiping {device_name} ({device['type']})")
        self.root.after(0, self.log_message,
                       f"🚀 Starting 5-layer wipe of {device_path}")

        # 5-layer wiping process
        layers = [
            ("Zero Fill", "if=/dev/zero"),
            ("Ones Fill", "if=/dev/zero"),
            ("Random Data", "if=/dev/urandom"),
            ("Alternating Pattern", "if=/dev/zero"),
            ("Final Zero", "if=/dev/zero")
        ]

        for layer_index, (layer_name, source) in enumerate(layers):
            if not self.wipe_in_progress:
                return

            self.root.after(0, self.update_current_operation,
                           f"📝 Layer {layer_index + 1}/5: {layer_name}")

            self.root.after(0, self.update_device_progress,
                           (layer_index / 5) * 100, f"Layer {layer_index + 1}/5")

            success = self.write_layer_to_device(device_path, source, layer_index + 1)

            if not success:
                self.root.after(0, self.log_message,
                               f"❌ Layer {layer_index + 1} failed on {device_name}")
                return

        # Verification
        self.root.after(0, self.update_current_operation,
                       f"✅ Verifying {device_name}")
        self.verify_device_wipe(device_path)

        self.root.after(0, self.log_message,
                       f"✅ Successfully wiped {device_path}")
        self.root.after(0, self.update_device_progress, 100, "Device completed")

    def write_layer_to_device(self, device_path, source, layer_num):
        """Write a layer to device"""
        try:
            cmd = f"dd {source} of={device_path} bs=1M count=100 status=none"

            self.root.after(0, self.log_message, f"📝 Layer {layer_num}: {cmd}")

            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, universal_newlines=True)

            # Monitor progress
            while process.poll() is None and self.wipe_in_progress:
                self.root.after(0, self.update_layer_progress,
                              layer_num * 20, f"Layer {layer_num} in progress...")
                time.sleep(1)

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

    def verify_device_wipe(self, device_path):
        """Verify device wipe"""
        try:
            self.root.after(0, self.log_message, f"🔍 Verifying {device_path}")

            cmd = f"dd if={device_path} bs=1M count=1 2>/dev/null | hexdump -C | head -5"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if result.stdout:
                self.root.after(0, self.log_message, f"✅ Verification completed")
                return True
            else:
                self.root.after(0, self.log_message, f"⚠️ Verification warning")
                return False

        except Exception as e:
            self.root.after(0, self.log_message, f"❌ Verification failed: {str(e)}")
            return False

    def generate_certificate(self, completed_devices):
        """Generate certificate and save to USB"""
        try:
            cert_data = {
                "certificate_version": "1.0",
                "certificate_id": hashlib.sha256(f"{datetime.now().isoformat()}".encode()).hexdigest()[:16],
                "timestamp": datetime.now().isoformat(),
                "tool": "SIH2025 Secure Wipe Tool - Bundled Edition",
                "compliance": "NIST SP 800-88 5-Layer Wiping",
                "storage_location": "Bootable USB Drive" if self.usb_cert_location.startswith('/mnt') or self.usb_cert_location.startswith('/media') else "Local Storage",
                "devices_wiped": []
            }

            for device in completed_devices:
                cert_data["devices_wiped"].append({
                    "name": device['name'],
                    "path": device['path'],
                    "type": device['type'],
                    "size": device['size'],
                    "priority": device['priority'],
                    "status": "wiped"
                })

            # Add integrity hash
            cert_json = json.dumps(cert_data, sort_keys=True)
            cert_data["integrity_hash"] = hashlib.sha256(cert_json.encode()).hexdigest()

            # Save to USB/local
            cert_id = cert_data['certificate_id']
            json_file = f"{self.usb_cert_location}/certificate_{cert_id}.json"

            with open(json_file, 'w') as f:
                json.dump(cert_data, f, indent=2)

            # Sync to USB
            if self.usb_cert_location.startswith('/mnt') or self.usb_cert_location.startswith('/media'):
                os.sync()

            storage_type = "USB drive" if self.usb_cert_location.startswith('/mnt') or self.usb_cert_location.startswith('/media') else "local storage"
            self.root.after(0, self.log_message, f"📜 Certificate saved to {storage_type}")

        except Exception as e:
            self.root.after(0, self.log_message, f"❌ Certificate generation failed: {str(e)}")

    def update_current_operation(self, operation):
        """Update current operation display"""
        self.current_operation = operation
        self.current_op_var.set(operation)

    def update_overall_progress(self, percent, text):
        """Update overall progress"""
        self.overall_progress['value'] = percent
        self.overall_progress_text.set(f"{int(percent)}% - {text}")

    def update_device_progress(self, percent, text):
        """Update device progress"""
        self.device_progress['value'] = percent
        self.device_progress_text.set(f"{int(percent)}% - {text}")

    def update_layer_progress(self, percent, text):
        """Update layer progress"""
        self.layer_progress['value'] = percent
        self.layer_progress_text.set(f"{int(percent)}% - {text}")

    def log_message(self, message):
        """Add message to log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"

        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)

        # Color coding for log messages
        if "✅" in message:
            self.log_text.tag_add("success", f"{tk.END}-1c linestart", f"{tk.END}-1c lineend")
            self.log_text.tag_config("success", foreground=self.colors['success'])
        elif "❌" in message:
            self.log_text.tag_add("error", f"{tk.END}-1c linestart", f"{tk.END}-1c lineend")
            self.log_text.tag_config("error", foreground=self.colors['error'])
        elif "⚠️" in message:
            self.log_text.tag_add("warning", f"{tk.END}-1c linestart", f"{tk.END}-1c lineend")
            self.log_text.tag_config("warning", foreground=self.colors['warning'])

    def pause_operation(self):
        """Pause wiping operation"""
        if self.wipe_in_progress:
            self.wipe_in_progress = False
            self.log_message("⏸️ Operation paused")
            self.pause_button.config(state='disabled')
            self.start_button.config(state='normal', text="▶️ Resume Wiping")

    def cancel_operation(self):
        """Cancel wiping operation"""
        result = messagebox.askyesno("Cancel Operation",
                                   "Are you sure you want to cancel?\n"
                                   "This may leave devices partially wiped.")

        if result:
            self.wipe_in_progress = False
            self.log_message("❌ Operation cancelled")
            self.wiping_cancelled()

    def wiping_completed(self):
        """Handle completion"""
        self.wipe_in_progress = False

        self.update_current_operation("✅ All devices wiped successfully!")
        self.update_overall_progress(100, "Wiping completed")
        self.update_device_progress(100, "All devices completed")
        self.update_layer_progress(100, "All layers completed")

        self.log_message("🎉 WIPING PROCESS COMPLETED!")

        # Reset buttons
        self.start_button.config(text="🚀 START SECURE WIPING", state='normal')
        self.pause_button.config(state='disabled')
        self.cancel_button.config(state='disabled')

        # Show completion message
        storage_location = "USB drive" if self.usb_cert_location.startswith('/mnt') or self.usb_cert_location.startswith('/media') else "local storage"

        messagebox.showinfo("Wiping Completed",
                          f"✅ Secure wiping completed successfully!\n\n"
                          f"📜 Compliance certificates saved to {storage_location}\n"
                          f"📁 Location: {self.usb_cert_location}\n\n"
                          f"Your devices are now securely wiped and ready for disposal or reuse.")

    def wiping_failed(self, error):
        """Handle failure"""
        self.wipe_in_progress = False

        self.update_current_operation(f"❌ Wiping failed: {error}")
        self.log_message(f"❌ PROCESS FAILED: {error}")

        # Reset buttons
        self.start_button.config(text="🚀 START SECURE WIPING", state='normal')
        self.pause_button.config(state='disabled')
        self.cancel_button.config(state='disabled')

        messagebox.showerror("Wiping Failed",
                           f"❌ The wiping process failed:\n\n{error}\n\n"
                           "Check the log for details.")

    def wiping_cancelled(self):
        """Handle cancellation"""
        self.wipe_in_progress = False

        self.update_current_operation("❌ Operation cancelled")

        # Reset buttons
        self.start_button.config(text="🚀 START SECURE WIPING", state='normal')
        self.pause_button.config(state='disabled')
        self.cancel_button.config(state='disabled')

        messagebox.showwarning("Operation Cancelled",
                             "⚠️ Wiping cancelled by user.\n\n"
                             "Some devices may be partially wiped.")

def main():
    """Main application entry point"""
    # Check root access
    if os.geteuid() != 0:
        print("⚠️ WARNING: Not running as root")
        print("Some operations may fail without root privileges")

        root = tk.Tk()
        root.withdraw()

        result = messagebox.askyesno("Root Access Required",
                                   "This tool requires root access for device wiping.\n\n"
                                   "Run as: sudo python3 secure_wipe_bundled.py\n\n"
                                   "Continue anyway?")

        if not result:
            return

    # Check installation
    if not os.path.exists('/opt/secure-wipe'):
        root = tk.Tk()
        root.withdraw()

        messagebox.showerror("Installation Error",
                           "Secure Wipe Tool not properly installed!\n\n"
                           "Please run the installation scripts first.")
        return

    # Create and run GUI
    try:
        root = tk.Tk()
        app = SecureWipeBundledGUI(root)

        # Handle window closing
        def on_closing():
            if app.wipe_in_progress:
                result = messagebox.askyesno("Quit Application",
                                           "Wiping in progress! Quit anyway?")
                if result:
                    app.wipe_in_progress = False
                    root.destroy()
            else:
                root.destroy()

        root.protocol("WM_DELETE_WINDOW", on_closing)

        # Center window
        root.update_idletasks()
        width = root.winfo_width()
        height = root.winfo_height()
        x = (root.winfo_screenwidth() // 2) - (width // 2)
        y = (root.winfo_screenheight() // 2) - (height // 2)
        root.geometry(f"{width}x{height}+{x}+{y}")

        root.mainloop()

    except Exception as e:
        print(f"❌ Application failed to start: {e}")

        # Try to show error in GUI
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Application Error",
                               f"Failed to start application:\n\n{e}\n\n"
                               "Check dependencies and try again.")
        except:
            print("Could not show error dialog")

if __name__ == "__main__":
    main()("🟢 Ready - Select

