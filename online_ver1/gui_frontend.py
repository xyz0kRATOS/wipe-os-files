#!/usr/bin/env python3

"""
gui_frontend.py - Tkinter GUI Frontend for Secure Data Wiping Tool
User-friendly interface for drive detection, wiping, and certificate management
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Optional
import logging
import webbrowser
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecureWipeGUI:
    """Main GUI Application"""

    def __init__(self):
        self.root = tk.Tk()
        self.backend_url = "http://localhost:8000/api"
        self.selected_drive = None
        self.selected_method = None
        self.current_operation = None
        self.drives_data = []

        self.setup_gui()
        self.check_backend_connection()

    def setup_gui(self):
        """Initialize the GUI components"""
        self.root.title("Secure Data Wipe Tool - NIST 800-88 Compliant")
        self.root.geometry("1200x800")
        self.root.configure(bg='#f0f0f0')

        # Configure styles
        self.setup_styles()

        # Create main notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # Create tabs
        self.create_drive_detection_tab()
        self.create_wipe_operation_tab()
        self.create_certificates_tab()
        self.create_settings_tab()

        # Status bar
        self.create_status_bar()

        # Menu bar
        self.create_menu_bar()

    def setup_styles(self):
        """Configure TTK styles"""
        style = ttk.Style()

        # Configure button styles
        style.configure('Action.TButton',
                       background='#007bff',
                       foreground='white',
                       font=('Arial', 10, 'bold'))

        style.configure('Danger.TButton',
                       background='#dc3545',
                       foreground='white',
                       font=('Arial', 10, 'bold'))

        style.configure('Success.TButton',
                       background='#28a745',
                       foreground='white',
                       font=('Arial', 10, 'bold'))

    def create_menu_bar(self):
        """Create application menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Logs", command=self.export_logs)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="System Information", command=self.show_system_info)
        tools_menu.add_command(label="Check Backend", command=self.check_backend_connection)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About NIST 800-88", command=self.show_nist_info)
        help_menu.add_command(label="User Guide", command=self.show_user_guide)
        help_menu.add_command(label="About", command=self.show_about)

    def create_drive_detection_tab(self):
        """Create drive detection and selection tab"""
        self.drive_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.drive_frame, text="Drive Detection")

        # Title
        title_label = ttk.Label(self.drive_frame, text="Drive Detection & Selection",
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=10)

        # Detection button
        detect_frame = ttk.Frame(self.drive_frame)
        detect_frame.pack(pady=10)

        self.detect_btn = ttk.Button(detect_frame, text="🔍 Detect Drives",
                                    style='Action.TButton',
                                    command=self.detect_drives)
        self.detect_btn.pack(side='left', padx=5)

        self.refresh_btn = ttk.Button(detect_frame, text="↻ Refresh",
                                     command=self.detect_drives)
        self.refresh_btn.pack(side='left', padx=5)

        # Drives treeview
        columns = ('Device', 'Model', 'Size', 'Type', 'Status', 'Wipe Capable')
        self.drives_tree = ttk.Treeview(self.drive_frame, columns=columns, show='headings', height=12)

        for col in columns:
            self.drives_tree.heading(col, text=col)
            self.drives_tree.column(col, width=150)

        # Scrollbar for treeview
        scrollbar = ttk.Scrollbar(self.drive_frame, orient='vertical', command=self.drives_tree.yview)
        self.drives_tree.configure(yscrollcommand=scrollbar.set)

        # Pack treeview and scrollbar
        tree_frame = ttk.Frame(self.drive_frame)
        tree_frame.pack(fill='both', expand=True, padx=20, pady=10)

        self.drives_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        # Bind selection event
        self.drives_tree.bind('<<TreeviewSelect>>', self.on_drive_select)

        # Drive details frame
        details_frame = ttk.LabelFrame(self.drive_frame, text="Drive Details", padding=10)
        details_frame.pack(fill='x', padx=20, pady=10)

        self.details_text = scrolledtext.ScrolledText(details_frame, height=8, width=80)
        self.details_text.pack(fill='both', expand=True)

        # Warning label
        warning_label = ttk.Label(self.drive_frame,
                                 text="⚠️ WARNING: Data wiping is irreversible. Ensure you have backups!",
                                 foreground='red', font=('Arial', 12, 'bold'))
        warning_label.pack(pady=10)

    def create_wipe_operation_tab(self):
        """Create wipe operation tab"""
        self.wipe_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.wipe_frame, text="Wipe Operation")

        # Title
        title_label = ttk.Label(self.wipe_frame, text="Secure Data Wipe Operation",
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=10)

        # Selected drive info
        self.drive_info_frame = ttk.LabelFrame(self.wipe_frame, text="Selected Drive", padding=10)
        self.drive_info_frame.pack(fill='x', padx=20, pady=10)

        self.drive_info_label = ttk.Label(self.drive_info_frame,
                                         text="No drive selected. Please go to Drive Detection tab.",
                                         font=('Arial', 10))
        self.drive_info_label.pack()

        # Wipe method selection
        method_frame = ttk.LabelFrame(self.wipe_frame, text="Wipe Method Selection", padding=10)
        method_frame.pack(fill='x', padx=20, pady=10)

        self.method_var = tk.StringVar()
        self.method_descriptions = {}

        # Create method selection buttons (will be populated after backend connection)
        self.method_buttons_frame = ttk.Frame(method_frame)
        self.method_buttons_frame.pack(fill='x')

        # Method description
        self.method_desc_frame = ttk.LabelFrame(method_frame, text="Method Description", padding=10)
        self.method_desc_frame.pack(fill='x', pady=(10, 0))

        self.method_desc_text = tk.Text(self.method_desc_frame, height=6, wrap='word', state='disabled')
        self.method_desc_text.pack(fill='both', expand=True)

        # Operation controls
        controls_frame = ttk.Frame(self.wipe_frame)
        controls_frame.pack(pady=20)

        self.start_wipe_btn = ttk.Button(controls_frame, text="🗑️ Start Wipe Operation",
                                        style='Danger.TButton',
                                        command=self.start_wipe,
                                        state='disabled')
        self.start_wipe_btn.pack(side='left', padx=10)

        self.cancel_btn = ttk.Button(controls_frame, text="❌ Cancel",
                                    command=self.cancel_operation,
                                    state='disabled')
        self.cancel_btn.pack(side='left', padx=10)

        # Progress section
        progress_frame = ttk.LabelFrame(self.wipe_frame, text="Operation Progress", padding=10)
        progress_frame.pack(fill='x', padx=20, pady=10)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var,
                                           maximum=100, length=400)
        self.progress_bar.pack(pady=5)

        self.progress_label = ttk.Label(progress_frame, text="No operation in progress")
        self.progress_label.pack(pady=5)

        # Operation log
        log_frame = ttk.LabelFrame(self.wipe_frame, text="Operation Log", padding=10)
        log_frame.pack(fill='both', expand=True, padx=20, pady=10)

        self.operation_log = scrolledtext.ScrolledText(log_frame, height=10, width=80)
        self.operation_log.pack(fill='both', expand=True)

    def create_certificates_tab(self):
        """Create certificates management tab"""
        self.cert_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.cert_frame, text="Certificates")

        # Title
        title_label = ttk.Label(self.cert_frame, text="Wipe Certificates Management",
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=10)

        # Controls
        controls_frame = ttk.Frame(self.cert_frame)
        controls_frame.pack(pady=10)

        self.refresh_certs_btn = ttk.Button(controls_frame, text="↻ Refresh Certificates",
                                           command=self.refresh_certificates)
        self.refresh_certs_btn.pack(side='left', padx=5)

        # Certificates treeview
        cert_columns = ('Certificate ID', 'Device', 'Method', 'Date', 'Status')
        self.certs_tree = ttk.Treeview(self.cert_frame, columns=cert_columns, show='headings', height=15)

        for col in cert_columns:
            self.certs_tree.heading(col, text=col)
            self.certs_tree.column(col, width=200)

        # Scrollbar
        cert_scrollbar = ttk.Scrollbar(self.cert_frame, orient='vertical', command=self.certs_tree.yview)
        self.certs_tree.configure(yscrollcommand=cert_scrollbar.set)

        # Pack certificates treeview
        cert_tree_frame = ttk.Frame(self.cert_frame)
        cert_tree_frame.pack(fill='both', expand=True, padx=20, pady=10)

        self.certs_tree.pack(side='left', fill='both', expand=True)
        cert_scrollbar.pack(side='right', fill='y')

        # Certificate actions
        cert_actions_frame = ttk.Frame(self.cert_frame)
        cert_actions_frame.pack(pady=10)

        self.view_cert_btn = ttk.Button(cert_actions_frame, text="👁️ View Certificate",
                                       command=self.view_certificate)
        self.view_cert_btn.pack(side='left', padx=5)

        self.download_json_btn = ttk.Button(cert_actions_frame, text="📥 Download JSON",
                                           command=lambda: self.download_certificate('json'))
        self.download_json_btn.pack(side='left', padx=5)

                self.download_html_btn = ttk.Button(cert_actions_frame, text="📄 Download HTML", 
                                           command=lambda: self.download_certificate('html'))
        self.download_html_btn.pack(side='left', padx=5)
        
        self.verify_cert_btn = ttk.Button(cert_actions_frame, text="✓ Verify Certificate", 
                                         command=self.verify_certificate)
        self.verify_cert_btn.pack(side='left', padx=5)
        
        # Bind certificate selection
        self.certs_tree.bind('<<TreeviewSelect>>', self.on_certificate_select)
    
    def create_settings_tab(self):
        """Create settings and configuration tab"""
        self.settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_frame, text="Settings")
        
        # Title
        title_label = ttk.Label(self.settings_frame, text="Settings & Configuration", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=10)
        
        # Backend connection settings
        backend_frame = ttk.LabelFrame(self.settings_frame, text="Backend Connection", padding=10)
        backend_frame.pack(fill='x', padx=20, pady=10)
        
        ttk.Label(backend_frame, text="Backend URL:").pack(anchor='w')
        self.backend_url_var = tk.StringVar(value=self.backend_url)
        backend_entry = ttk.Entry(backend_frame, textvariable=self.backend_url_var, width=50)
        backend_entry.pack(fill='x', pady=5)
        
        ttk.Button(backend_frame, text="Test Connection", 
                  command=self.test_backend_connection).pack(pady=5)
        
        # System information
        system_frame = ttk.LabelFrame(self.settings_frame, text="System Information", padding=10)
        system_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        self.system_info_text = scrolledtext.ScrolledText(system_frame, height=15, width=80)
        self.system_info_text.pack(fill='both', expand=True)
        
        # Load system info
        self.load_system_info()
    
    def create_status_bar(self):
        """Create status bar at bottom"""
        self.status_frame = ttk.Frame(self.root)
        self.status_frame.pack(side='bottom', fill='x')
        
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(self.status_frame, textvariable=self.status_var, 
                                     relief='sunken', anchor='w')
        self.status_label.pack(side='left', fill='x', expand=True)
        
        # Connection status
        self.connection_var = tk.StringVar(value="Disconnected")
        self.connection_label = ttk.Label(self.status_frame, textvariable=self.connection_var, 
                                         relief='sunken')
        self.connection_label.pack(side='right', padx=5)
    
    def check_backend_connection(self):
        """Check backend server connection"""
        def check_connection():
            try:
                response = requests.get(f"{self.backend_url}/health", timeout=5)
                if response.status_code == 200:
                    self.connection_var.set("✓ Connected")
                    self.status_var.set("Backend connection successful")
                    self.load_wipe_methods()
                else:
                    self.connection_var.set("❌ Error")
                    self.status_var.set(f"Backend error: {response.status_code}")
            except requests.ConnectionError:
                self.connection_var.set("❌ Disconnected")
                self.status_var.set("Cannot connect to backend server")
            except Exception as e:
                self.connection_var.set("❌ Error")
                self.status_var.set(f"Connection error: {str(e)}")
        
        threading.Thread(target=check_connection, daemon=True).start()
    
    def test_backend_connection(self):
        """Test backend connection with current URL"""
        self.backend_url = self.backend_url_var.get()
        self.check_backend_connection()
    
    def load_wipe_methods(self):
        """Load available wipe methods from backend"""
        def load_methods():
            try:
                response = requests.get(f"{self.backend_url}/wipe/methods")
                if response.status_code == 200:
                    methods_data = response.json()
                    self.method_descriptions = methods_data.get('data', {})
                    self.update_method_selection()
                else:
                    logger.error(f"Failed to load wipe methods: {response.status_code}")
            except Exception as e:
                logger.error(f"Error loading wipe methods: {e}")
        
        threading.Thread(target=load_methods, daemon=True).start()
    
    def update_method_selection(self):
        """Update method selection radio buttons"""
        # Clear existing buttons
        for widget in self.method_buttons_frame.winfo_children():
            widget.destroy()
        
        # Create radio buttons for each method
        row = 0
        for method_id, method_info in self.method_descriptions.items():
            rb = ttk.Radiobutton(self.method_buttons_frame, 
                               text=method_info['name'],
                               variable=self.method_var,
                               value=method_id,
                               command=self.on_method_select)
            rb.grid(row=row//2, column=row%2, sticky='w', padx=10, pady=2)
            row += 1
    
    def on_method_select(self):
        """Handle method selection"""
        selected_method = self.method_var.get()
        if selected_method in self.method_descriptions:
            method_info = self.method_descriptions[selected_method]
            
            # Update description text
            self.method_desc_text.config(state='normal')
            self.method_desc_text.delete(1.0, tk.END)
            
            desc_text = f"Method: {method_info['name']}\n"
            desc_text += f"Description: {method_info['description']}\n"
            desc_text += f"Passes: {method_info['passes']}\n"
            desc_text += f"Time Estimate: {method_info['time_estimate']}\n"
            desc_text += f"Compliance: {method_info['compliance']}\n"
            desc_text += f"Suitable for: {', '.join(method_info['suitable_for'])}\n"
            
            self.method_desc_text.insert(1.0, desc_text)
            self.method_desc_text.config(state='disabled')
            
            self.selected_method = selected_method
            self.update_start_button_state()
    
    def detect_drives(self):
        """Detect available drives"""
        def detect():
            self.status_var.set("Detecting drives...")
            self.detect_btn.config(state='disabled')
            
            try:
                response = requests.get(f"{self.backend_url}/drives/detect", timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    if data['status'] == 'success':
                        self.drives_data = data['data']['detected_drives']
                        self.update_drives_tree()
                        self.status_var.set(f"Found {len(self.drives_data)} drives")
                    else:
                        messagebox.showerror("Error", f"Drive detection failed: {data.get('message', 'Unknown error')}")
                else:
                    messagebox.showerror("Error", f"Server error: {response.status_code}")
            except requests.Timeout:
                messagebox.showerror("Error", "Drive detection timed out")
            except Exception as e:
                messagebox.showerror("Error", f"Drive detection failed: {str(e)}")
            finally:
                self.detect_btn.config(state='normal')
                if not self.drives_data:
                    self.status_var.set("No drives detected")
        
        threading.Thread(target=detect, daemon=True).start()
    
    def update_drives_tree(self):
        """Update drives treeview with detected drives"""
        # Clear existing items
        for item in self.drives_tree.get_children():
            self.drives_tree.delete(item)
        
        # Add drives to treeview
        for drive in self.drives_data:
            device = drive.get('device', 'Unknown')
            model = drive.get('model', 'Unknown')
            size = drive.get('size', 'Unknown')
            drive_type = drive.get('drive_type', 'Unknown')
            status = "Mounted" if drive.get('is_mounted', False) else "Available"
            wipe_capable = "Yes" if drive.get('wipe_capable', False) else "No"
            
            self.drives_tree.insert('', 'end', values=(device, model, size, drive_type, status, wipe_capable))
    
    def on_drive_select(self, event):
        """Handle drive selection"""
        selection = self.drives_tree.selection()
        if selection:
            item = self.drives_tree.item(selection[0])
            device = item['values'][0]
            
            # Find the drive data
            selected_drive_data = None
            for drive in self.drives_data:
                if drive.get('device') == device:
                    selected_drive_data = drive
                    break
            
            if selected_drive_data:
                self.selected_drive = selected_drive_data
                self.update_drive_details(selected_drive_data)
                self.update_wipe_drive_info()
                self.update_start_button_state()
    
    def update_drive_details(self, drive_data):
        """Update drive details display"""
        details = f"Device: {drive_data.get('device', 'Unknown')}\n"
        details += f"Model: {drive_data.get('model', 'Unknown')}\n"
        details += f"Serial: {drive_data.get('serial', 'Unknown')}\n"
        details += f"Size: {drive_data.get('size', 'Unknown')}\n"
        details += f"Type: {drive_data.get('drive_type', 'Unknown')}\n"
        details += f"Interface: {drive_data.get('interface', 'Unknown')}\n"
        details += f"Firmware: {drive_data.get('firmware', 'Unknown')}\n"
        details += f"Security Status: {drive_data.get('security_status', 'Unknown')}\n"
        details += f"Mounted: {'Yes' if drive_data.get('is_mounted', False) else 'No'}\n"
        
        if drive_data.get('mount_points'):
            details += f"Mount Points: {', '.join(drive_data['mount_points'])}\n"
        
        details += f"HPA Status: {drive_data.get('hpa_status', 'Unknown')}\n"
        details += f"DCO Status: {drive_data.get('dco_status', 'Unknown')}\n"
        details += f"Wipe Capable: {'Yes' if drive_data.get('wipe_capable', False) else 'No'}\n"
        
        if drive_data.get('supported_methods'):
            details += f"Supported Methods: {', '.join(drive_data['supported_methods'])}\n"
        
        if drive_data.get('partitions'):
            details += "\nPartitions:\n"
            for partition in drive_data['partitions']:
                details += f"  - {partition.get('name', 'Unknown')}: {partition.get('size', 'Unknown')} ({partition.get('filesystem', 'Unknown')})\n"
        
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(1.0, details)
    
    def update_wipe_drive_info(self):
        """Update selected drive info in wipe tab"""
        if self.selected_drive:
            info_text = f"Device: {self.selected_drive.get('device', 'Unknown')} | "
            info_text += f"Model: {self.selected_drive.get('model', 'Unknown')} | "
            info_text += f"Size: {self.selected_drive.get('size', 'Unknown')}"
            self.drive_info_label.config(text=info_text)
        else:
            self.drive_info_label.config(text="No drive selected. Please go to Drive Detection tab.")
    
    def update_start_button_state(self):
        """Update start button state based on selection"""
        if self.selected_drive and self.selected_method and not self.current_operation:
            if self.selected_drive.get('wipe_capable', False):
                self.start_wipe_btn.config(state='normal')
            else:
                self.start_wipe_btn.config(state='disabled')
        else:
            self.start_wipe_btn.config(state='disabled')
    
    def start_wipe(self):
        """Start wipe operation"""
        if not self.selected_drive or not self.selected_method:
            messagebox.showerror("Error", "Please select a drive and wipe method")
            return
        
        # Confirmation dialog
        device = self.selected_drive.get('device', 'Unknown')
        method_name = self.method_descriptions.get(self.selected_method, {}).get('name', self.selected_method)
        
        confirm_msg = f"WARNING: This will permanently erase all data on {device}\n\n"
        confirm_msg += f"Drive: {self.selected_drive.get('model', 'Unknown')}\n"
        confirm_msg += f"Method: {method_name}\n\n"
        confirm_msg += "This action cannot be undone!\n\n"
        confirm_msg += "Are you absolutely sure you want to continue?"
        
        if not messagebox.askyesno("Confirm Wipe Operation", confirm_msg, icon='warning'):
            return
        
        # Final confirmation
        if not messagebox.askyesno("Final Confirmation", 
                                  "This is your last chance to cancel.\n\nProceed with data wipe?", 
                                  icon='error'):
            return
        
        def start_wipe_operation():
            try:
                self.log_operation("Starting wipe operation...")
                self.start_wipe_btn.config(state='disabled')
                self.cancel_btn.config(state='normal')
                
                # Start wipe operation
                wipe_data = {
                    'device': device,
                    'method': self.selected_method
                }
                
                response = requests.post(f"{self.backend_url}/wipe/start", json=wipe_data)
                
                if response.status_code == 200:
                    result = response.json()
                    if result['status'] == 'success':
                        self.current_operation = result['operation_id']
                        self.log_operation(f"Wipe operation started: {self.current_operation}")
                        self.start_progress_monitoring()
                    else:
                        messagebox.showerror("Error", f"Failed to start wipe: {result.get('message', 'Unknown error')}")
                        self.reset_operation_state()
                else:
                    messagebox.showerror("Error", f"Server error: {response.status_code}")
                    self.reset_operation_state()
                    
            except Exception as e:
                messagebox.showerror("Error", f"Failed to start wipe operation: {str(e)}")
                self.reset_operation_state()
        
        threading.Thread(target=start_wipe_operation, daemon=True).start()
    
    def start_progress_monitoring(self):
        """Start monitoring wipe progress"""
        def monitor_progress():
            while self.current_operation:
                try:
                    response = requests.get(f"{self.backend_url}/wipe/status/{self.current_operation}")
                    if response.status_code == 200:
                        data = response.json()
                        if data['status'] == 'success':
                            operation_data = data['data']
                            
                            # Update progress
                            progress = operation_data.get('progress_percentage', 0)
                            status = operation_data.get('status', 'Unknown')
                            passes = f"{operation_data.get('passes_completed', 0)}/{operation_data.get('total_passes', 1)}"
                            
                            self.progress_var.set(progress)
                            self.progress_label.config(text=f"Status: {status} | Progress: {progress:.1f}% | Passes: {passes}")
                            
                            self.log_operation(f"Progress: {progress:.1f}% - Status: {status}")
                            
                            # Check if operation is complete
                            if status in ['COMPLETED', 'FAILED', 'VERIFIED']:
                                self.operation_complete(operation_data)
                                break
                        else:
                            self.log_operation(f"Error getting status: {data.get('message', 'Unknown error')}")
                            break
                    else:
                        self.log_operation(f"Status check failed: {response.status_code}")
                        break
                        
                except Exception as e:
                    self.log_operation(f"Progress monitoring error: {str(e)}")
                    break
                
                time.sleep(2)  # Check every 2 seconds
        
        threading.Thread(target=monitor_progress, daemon=True).start()
    
    def operation_complete(self, operation_data):
        """Handle operation completion"""
        status = operation_data.get('status', 'Unknown')
        duration = operation_data.get('duration', 0)
        
        self.log_operation(f"Operation completed with status: {status}")
        self.log_operation(f"Duration: {duration:.1f} seconds")
        
        if status == 'COMPLETED' or status == 'VERIFIED':
            messagebox.showinfo("Success", f"Wipe operation completed successfully!\n\nDuration: {duration:.1f} seconds")
            # Refresh certificates to show the new certificate
            self.refresh_certificates()
        else:
            error_msg = operation_data.get('error_message', 'Unknown error')
            messagebox.showerror("Operation Failed", f"Wipe operation failed: {error_msg}")
        
        self.reset_operation_state()
    
    def cancel_operation(self):
        """Cancel current operation"""
        if messagebox.askyesno("Cancel Operation", "Are you sure you want to cancel the current operation?"):
            self.current_operation = None
            self.reset_operation_state()
            self.log_operation("Operation cancelled by user")
    
    def reset_operation_state(self):
        """Reset operation state"""
        self.current_operation = None
        self.start_wipe_btn.config(state='normal' if self.selected_drive and self.selected_method else 'disabled')
        self.cancel_btn.config(state='disabled')
        self.progress_var.set(0)
        self.progress_label.config(text="No operation in progress")
        self.update_start_button_state()
    
    def log_operation(self, message):
        """Log operation message"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        self.operation_log.insert(tk.END, log_entry)
        self.operation_log.see(tk.END)
        self.root.update_idletasks()
    
    def refresh_certificates(self):
        """Refresh certificates list"""
        def refresh():
            try:
                response = requests.get(f"{self.backend_url}/certificates")
                if response.status_code == 200:
                    data = response.json()
                    if data['status'] == 'success':
                        self.update_certificates_tree(data['data']['certificates'])
                    else:
                        self.status_var.set(f"Failed to load certificates: {data.get('message', 'Unknown error')}")
                else:
                    self.status_var.set(f"Server error loading certificates: {response.status_code}")
            except Exception as e:
                self.status_var.set(f"Error loading certificates: {str(e)}")
        
        threading.Thread(target=refresh, daemon=True).start()
    
    def update_certificates_tree(self, certificates):
        """Update certificates treeview"""
        # Clear existing items
        for item in self.certs_tree.get_children():
            self.certs_tree.delete(item)
        
        # Add certificates
        for cert in certificates:
            cert_id = cert.get('certificate_id', 'Unknown')
            device = cert.get('device_model', 'Unknown')
            method = cert.get('wipe_method', 'Unknown')
            date = cert.get('timestamp', 'Unknown')
            status = cert.get('status', 'Unknown')
            
            # Format date
            try:
                if date != 'Unknown':
                    date_obj = datetime.fromisoformat(date.replace('Z', '+00:00'))
                    date = date_obj.strftime("%Y-%m-%d %H:%M")
            except:
                pass
            
            self.certs_tree.insert('', 'end', values=(cert_id, device, method, date, status))
    
    def on_certificate_select(self, event):
        """Handle certificate selection"""
        # Enable certificate action buttons when a certificate is selected
        selection = self.certs_tree.selection()
        if selection:
            # Enable action buttons
            pass
    
    def view_certificate(self):
        """View selected certificate"""
        selection = self.certs_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a certificate to view")
            return
        
        item = self.certs_tree.item(selection[0])
        cert_id = item['values'][0]
        
        def get_certificate():
            try:
                response = requests.get(f"{self.backend_url}/certificates/{cert_id}")
                if response.status_code == 200:
                    data = response.json()
                    if data['status'] == 'success':
                        self.show_certificate_details(data['data'])
                    else:
                        messagebox.showerror("Error", f"Failed to load certificate: {data.get('message', 'Unknown error')}")
                else:
                    messagebox.showerror("Error", f"Server error: {response.status_code}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load certificate: {str(e)}")
        
        threading.Thread(target=get_certificate, daemon=True).start()
    
    def show_certificate_details(self, cert_data):
        """Show certificate details in a new window"""
        details_window = tk.Toplevel(self.root)
        details_window.title(f"Certificate Details - {cert_data.get('certificate_id', 'Unknown')}")
        details_window.geometry("800x600")
        
        # Create text widget with scrollbar
        text_frame = ttk.Frame(details_window)
        text_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        details_text = scrolledtext.ScrolledText(text_frame, wrap='word')
        details_text.pack(fill='both', expand=True)
        
        # Format certificate data
        details = json.dumps(cert_data, indent=2, sort_keys=True)
        details_text.insert(1.0, details)
        details_text.config(state='disabled')
    
    def download_certificate(self, format_type):
        """Download certificate in specified format"""
        selection = self.certs_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", f"Please select a certificate to download as {format_type.upper()}")
            return
        
        item = self.certs_tree.item(selection[0])
        cert_id = item['values'][0]
        
        # Choose save location
        file_extension = 'json' if format_type == 'json' else 'html'
        filename = filedialog.asksaveasfilename(
            defaultextension=f'.{file_extension}',
            filetypes=[(f'{format_type.upper()} files', f'*.{file_extension}'), ('All files', '*.*')],
            initialname=f"{cert_id}.{file_extension}"
        )
        
        if not filename:
            return
        
        def download():
            try:
                response = requests.get(f"{self.backend_url}/certificates/{cert_id}/download?format={format_type}")
                if response.status_code == 200:
                    with open(filename, 'wb') as f:
                        f.write(response.content)
                    messagebox.showinfo("Success", f"Certificate downloaded to: {filename}")
                else:
                    messagebox.showerror("Error", f"Download failed: {response.status_code}")
            except Exception as e:
                messagebox.showerror("Error", f"Download failed: {str(e)}")
        
        threading.Thread(target=download, daemon=True).start()
    
    def verify_certificate(self):
        """Verify selected certificate"""
        selection = self.certs_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a certificate to verify")
            return
        
        item = self.certs_tree.item(selection[0])
        cert_id = item['values'][0]
        
        def verify():
            try:
                response = requests.post(f"{self.backend_url}/certificates/{cert_id}/verify")
                if response.status_code == 200:
                    data = response.json()
                    if data['status'] == 'success':
                        verification = data['data']
                        
                        if verification['overall_valid']:
                            messagebox.showinfo("Verification Success", 
                                              f"Certificate {cert_id} is valid and authentic!\n\n"
                                              f"Signature: {'✓' if verification['signature_valid'] else '❌'}\n"
                                              f"Hash: {'✓' if verification['hash_valid'] else '❌'}\n"
                                              f"Database: {'✓' if verification['supabase_integrity'] else '❌'}")
                        else:
                            messagebox.showwarning("Verification Failed", 
                                                 f"Certificate {cert_id} verification failed!\n\n"
                                                 f"Signature: {'✓' if verification['signature_valid'] else '❌'}\n"
                                                 f"Hash: {'✓' if verification['hash_valid'] else '❌'}\n"
                                                 f"Database: {'✓' if verification['supabase_integrity'] else '❌'}")
                    else:
                        messagebox.showerror("Error", f"Verification failed: {data.get('message', 'Unknown error')}")
                else:
                    messagebox.showerror("Error", f"Server error: {response.status_code}")
            except Exception as e:
                messagebox.showerror("Error", f"Verification failed: {str(e)}")
        
        threading.Thread(target=verify, daemon=True).start()
    
    def load_system_info(self):
        """Load system information"""
        def load_info():
            try:
                response = requests.get(f"{self.backend_url}/system/info")
                if response.status_code == 200:
                    data = response.json()
                    if data['status'] == 'success':
                        info = data['data']
                        
                        info_text = "System Information:\n"
                        info_text += "=" * 50 + "\n"
                        for key, value in info.items():
                            info_text += f"{key.replace('_', ' ').title()}: {value}\n"
                        
                        info_text += "\n" + "=" * 50 + "\n"
                        
                        # Add configuration info
                        config_response = requests.get(f"{self.backend_url}/config")
                        if config_response.status_code == 200:
                            config_data = config_response.json()
                            if config_data['status'] == 'success':
                                config_info = config_data['data']
                                info_text += "Configuration:\n"
                                info_text += "=" * 50 + "\n"
                                for key, value in config_info.items():
                                    info_text += f"{key.replace('_', ' ').title()}: {value}\n"
                        
                        self.system_info_text.delete(1.0, tk.END)
                        self.system_info_text.insert(1.0, info_text)
                    else:
                        self.system_info_text.delete(1.0, tk.END)
                        self.system_info_text.insert(1.0, f"Error loading system info: {data.get('message', 'Unknown error')}")
                else:
                    self.system_info_text.delete(1.0, tk.END)
                    self.system_info_text.insert(1.0, f"Server error: {response.status_code}")
            except Exception as e:
                self.system_info_text.delete(1.0, tk.END)
                self.system_info_text.insert(1.0, f"Failed to load system info: {str(e)}")
        
        threading.Thread(target=load_info, daemon=True).start()
    
    def export_logs(self):
        """Export operation logs"""
        filename = filedialog.asksaveasfilename(
            defaultextension='.txt',
            filetypes=[('Text files', '*.txt'), ('All files', '*.*')],
            initialname=f"wipe_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        
        if filename:
            try:
                logs = self.operation_log.get(1.0, tk.END)
                with open(filename, 'w') as f:
                    f.write(logs)
                messagebox.showinfo("Success", f"Logs exported to: {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export logs: {str(e)}")
    
    def show_system_info(self):
        """Show system information dialog"""
        self.notebook.select(3)  # Switch to settings tab
    
    def show_nist_info(self):
        """Show NIST 800-88 information"""
        info_text = """
NIST SP 800-88 Rev. 1: Guidelines for Media Sanitization

This tool implements NIST Special Publication 800-88 Revision 1 guidelines for secure media sanitization.

Sanitization Categories:
• CLEAR: Applies logical techniques to sanitize data. Suitable for information that doesn't require high security.
• PURGE: Applies physical or logical techniques that render target data recovery infeasible using state-of-the-art laboratory techniques.
• DESTROY: Renders target data recovery infeasible using state-of-the-art laboratory techniques and results in the subsequent inability to use the media for storage of data.

Media Types:
• Magnetic Storage (HDDs): Requires overwrite or degaussing for PURGE level
• Flash Memory (SSDs): Block erase, cryptographic erase, or overwrite with verification
• Hybrid Storage: Combines magnetic and flash sanitization techniques

Compliance Features:
✓ Digitally signed certificates
✓ Tamper-proof documentation
✓ Third-party verification capability
✓ Audit trail maintenance
✓ Standards-compliant methods

For more information, visit: https://csrc.nist.gov/publications/detail/sp/800-88/rev-1/final
"""
        messagebox.showinfo("NIST 800-88 Information", info_text)
    
    def show_user_guide(self):
        """Show user guide"""
        guide_text = """
Secure Data Wipe Tool - User Guide

1. Drive Detection:
   - Click "Detect Drives" to scan for available storage devices
   - Select a drive from the list to view detailed information
   - Ensure the drive is not mounted or in use

2. Wipe Method Selection:
   - Choose an appropriate method based on your security requirements
   - NIST Clear: Fast, suitable for low security data
   - NIST Purge: More secure, suitable for sensitive data
   - Hardware methods: Fastest, uses built-in drive features

3. Starting Wipe Operation:
   - Select both a drive and method
   - Click "Start Wipe Operation"
   - Confirm the operation (irreversible!)
   - Monitor progress in real-time

4. Certificates:
   - Automatically generated after successful wipe
   - Download in JSON or HTML format
   - Verify authenticity using digital signatures
   - Store certificates for compliance records

5. Safety Guidelines:
   - Always backup important data before wiping
   - Ensure correct drive selection
   - Do not interrupt the wipe process
   - Verify wipe completion through certificates

For technical support, check the system logs or contact your administrator.
"""
        
        # Create a new window for the user guide
        guide_window = tk.Toplevel(self.root)
        guide_window.title("User Guide")
        guide_window.geometry("700x500")
        
        guide_text_widget = scrolledtext.ScrolledText(guide_window, wrap='word', padx=10, pady=10)
        guide_text_widget.pack(fill='both', expand=True)
        guide_text_widget.insert(1.0, guide_text)
        guide_text_widget.config(state='disabled')
    
    def show_about(self):
        """Show about dialog"""
        about_text = """
Secure Data Wipe Tool v1.0

A NIST 800-88 Rev. 1 compliant data sanitization solution designed for secure disposal and reuse of electronic devices.

Features:
• Cross-platform support (Windows, Linux, Android)
• Hardware-accelerated secure erase
• Digitally signed certificates
• Real-time progress monitoring
• Third-party verification
• Cloud certificate storage

Developed for India's e-waste management and circular economy initiatives.

Built with Python, Flask, Tkinter, and modern cryptography standards.

© 2024 Secure Wipe Tool Project
"""
        messagebox.showinfo("About Secure Data Wipe Tool", about_text)
    
    def run(self):
        """Start the GUI application"""
        # Load certificates on startup
        self.refresh_certificates()
        
        # Start the main event loop
        self.root.mainloop()

def main():
    """Main application entry point"""
    try:
        app = SecureWipeGUI()
        app.run()
    except Exception as e:
        logger.error(f"Application failed to start: {e}")
        messagebox.showerror("Startup Error", f"Failed to start application: {str(e)}")

if __name__ == "__main__":
    main()

