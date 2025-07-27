#!/usr/bin/env python3
"""
vlan10_agent.py - Enhanced VLAN10 (HR) Agent for Distributed Inter-VLAN Monitoring
- Monitors local traffic and sends file/message transfer requests
- Sends events to enhanced_router_monitor.py
- Receives permission responses
- Provides enhanced GUI with file transfer capabilities
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import socket
import time
import datetime
import json
import random
import logging
import os
import base64
from PIL import Image, ImageTk
import io
import hashlib

# --- CONFIGURATION ---
ROUTER_IP = '127.0.0.1'  # Router PC's WiFi IP address for multi-PC connection
ROUTER_PORT = 50050
VLAN = 'VLAN10'
LOCAL_DEPT = 'HR'
SHARED_SECRET = 'SHARED_SECRET'  # Shared authentication token

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vlan10_agent.log'),
        logging.StreamHandler()
    ]
)

class EnhancedVLAN10Agent:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Enhanced VLAN10 Agent - HR Department")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2b2b2b')

        self.connected = False
        self.sock = None
        self.running = False
        self.status_var = tk.StringVar(value="Disconnected")
        self.permission_status = tk.StringVar(value="N/A")
        self.last_permission = None
        self.transfer_history = []
        self.stats = {
            'sent_transfers': 0,
            'allowed_transfers': 0,
            'denied_transfers': 0
        }
        
        # Message storage
        self.received_messages = []
        
        self.setup_gui()

    def setup_gui(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Title
        title = tk.Label(main_frame, text="Enhanced VLAN10 Agent - HR Department", 
                        font=("Arial", 16, "bold"), bg='#2b2b2b', fg='white')
        title.pack(pady=(0, 10))

        # Create notebook for tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)

        # Dashboard tab
        self.create_dashboard_tab(notebook)
        
        # File Transfer tab
        self.create_file_transfer_tab(notebook)
        
        # Message Transfer tab
        self.create_message_transfer_tab(notebook)
        
        # Received Files tab
        self.create_received_files_tab(notebook)
        
        # Transfer History tab
        self.create_transfer_history_tab(notebook)
        
        # Logs tab
        self.create_logs_tab(notebook)

        # Control buttons
        self.create_control_buttons(main_frame)

    def create_dashboard_tab(self, notebook):
        dashboard_frame = ttk.Frame(notebook)
        notebook.add(dashboard_frame, text="Dashboard")

        # Connection status
        status_frame = ttk.LabelFrame(dashboard_frame, text="Connection Status", padding=10)
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(status_frame, textvariable=self.status_var, fg='red', font=("Arial", 12, "bold")).pack()

        # Permission status
        perm_frame = ttk.LabelFrame(dashboard_frame, text="Last Permission Response", padding=10)
        perm_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(perm_frame, textvariable=self.permission_status, fg='blue', font=("Arial", 12, "bold")).pack()

        # Statistics
        stats_frame = ttk.LabelFrame(dashboard_frame, text="Transfer Statistics", padding=10)
        stats_frame.pack(fill=tk.X, padx=10, pady=5)

        self.stats_vars = {}
        stats_items = [
            ("Sent Transfers", "0"),
            ("Allowed Transfers", "0"),
            ("Denied Transfers", "0"),
            ("Success Rate", "0%")
        ]

        for i, (label, initial_value) in enumerate(stats_items):
            frame = ttk.Frame(stats_frame)
            frame.pack(side=tk.LEFT, padx=15)
            ttk.Label(frame, text=label, font=("Arial", 8)).pack()
            var = tk.StringVar(value=initial_value)
            self.stats_vars[label] = var
            ttk.Label(frame, textvariable=var, font=("Arial", 10, "bold")).pack()

        # Recent activity
        activity_frame = ttk.LabelFrame(dashboard_frame, text="Recent Activity", padding=10)
        activity_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.activity_text = scrolledtext.ScrolledText(
            activity_frame, height=15, font=("Consolas", 9), 
            bg='#1e1e1e', fg='#00ff00'
        )
        self.activity_text.pack(fill=tk.BOTH, expand=True)

    def create_file_transfer_tab(self, notebook):
        file_frame = ttk.Frame(notebook)
        notebook.add(file_frame, text="File Transfer")

        # File selection
        file_select_frame = ttk.LabelFrame(file_frame, text="File Selection", padding=10)
        file_select_frame.pack(fill=tk.X, padx=10, pady=5)

        self.file_path_var = tk.StringVar()
        ttk.Entry(file_select_frame, textvariable=self.file_path_var, width=50).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_select_frame, text="Browse", command=self.browse_file).pack(side=tk.LEFT, padx=5)

        # Destination selection
        dest_frame = ttk.LabelFrame(file_frame, text="Destination", padding=10)
        dest_frame.pack(fill=tk.X, padx=10, pady=5)

        self.dest_vlan_var = tk.StringVar(value="VLAN20")
        ttk.Radiobutton(dest_frame, text="VLAN20 (Finance)", variable=self.dest_vlan_var, 
                       value="VLAN20").pack(side=tk.LEFT, padx=10)

        # Transfer controls
        transfer_frame = ttk.LabelFrame(file_frame, text="Transfer Controls", padding=10)
        transfer_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(transfer_frame, text="Send File", command=self.send_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(transfer_frame, text="Clear Selection", command=self.clear_file_selection).pack(side=tk.LEFT, padx=5)

        # File preview
        preview_frame = ttk.LabelFrame(file_frame, text="File Preview", padding=10)
        preview_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.file_preview_text = scrolledtext.ScrolledText(
            preview_frame, height=10, font=("Consolas", 9), 
            bg='#1e1e1e', fg='#4ecdc4'
        )
        self.file_preview_text.pack(fill=tk.BOTH, expand=True)

    def create_message_transfer_tab(self, notebook):
        msg_frame = ttk.Frame(notebook)
        notebook.add(msg_frame, text="Message Transfer")

        # Message input
        msg_input_frame = ttk.LabelFrame(msg_frame, text="Message Input", padding=10)
        msg_input_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        ttk.Label(msg_input_frame, text="Message:").pack(anchor=tk.W)
        self.message_text = scrolledtext.ScrolledText(
            msg_input_frame, height=10, font=("Arial", 10), 
            bg='#1e1e1e', fg='white'
        )
        self.message_text.pack(fill=tk.BOTH, expand=True, pady=5)

        # Message type selection
        type_frame = ttk.Frame(msg_frame)
        type_frame.pack(fill=tk.X, padx=10, pady=5)

        self.msg_type_var = tk.StringVar(value="text")
        ttk.Radiobutton(type_frame, text="Text Message", variable=self.msg_type_var, 
                       value="text").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(type_frame, text="Image Message", variable=self.msg_type_var, 
                       value="image").pack(side=tk.LEFT, padx=10)

        # Destination and send
        send_frame = ttk.Frame(msg_frame)
        send_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(send_frame, text="To:").pack(side=tk.LEFT, padx=5)
        self.msg_dest_var = tk.StringVar(value="VLAN20")
        ttk.Radiobutton(send_frame, text="VLAN20 (Finance)", variable=self.msg_dest_var, 
                       value="VLAN20").pack(side=tk.LEFT, padx=10)
        
        ttk.Button(send_frame, text="Send Message", command=self.send_message).pack(side=tk.RIGHT, padx=5)

        # Message inbox
        inbox_frame = ttk.LabelFrame(msg_frame, text="Message Inbox (Received Messages)", padding=10)
        inbox_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Inbox controls
        inbox_controls_frame = ttk.Frame(inbox_frame)
        inbox_controls_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Button(inbox_controls_frame, text="Refresh Inbox", command=self.refresh_inbox).pack(side=tk.LEFT, padx=5)
        ttk.Button(inbox_controls_frame, text="Clear Inbox", command=self.clear_inbox).pack(side=tk.LEFT, padx=5)
        ttk.Button(inbox_controls_frame, text="Export Messages", command=self.export_messages).pack(side=tk.LEFT, padx=5)

        # Inbox display
        self.inbox_text = scrolledtext.ScrolledText(
            inbox_frame, height=12, font=("Consolas", 9), 
            bg='#1e1e1e', fg='#4ecdc4'
        )
        self.inbox_text.pack(fill=tk.BOTH, expand=True)

    def create_received_files_tab(self, notebook):
        received_files_frame = ttk.Frame(notebook)
        notebook.add(received_files_frame, text="Received Files")

        # Received files display
        received_files_display_frame = ttk.LabelFrame(received_files_frame, text="Received Files", padding=10)
        received_files_display_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Create treeview for received files
        columns = ('Time', 'Type', 'From', 'Size', 'Status', 'Details')
        self.received_files_tree = ttk.Treeview(received_files_display_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.received_files_tree.heading(col, text=col)
            self.received_files_tree.column(col, width=120)

        self.received_files_tree.pack(fill=tk.BOTH, expand=True)

        # Received files controls
        received_files_controls_frame = ttk.Frame(received_files_frame)
        received_files_controls_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(received_files_controls_frame, text="Clear Received Files", command=self.clear_received_files).pack(side=tk.LEFT, padx=5)
        ttk.Button(received_files_controls_frame, text="Export Received Files", command=self.export_received_files).pack(side=tk.LEFT, padx=5)

    def create_transfer_history_tab(self, notebook):
        history_frame = ttk.Frame(notebook)
        notebook.add(history_frame, text="Transfer History")

        # Transfer history
        history_display_frame = ttk.LabelFrame(history_frame, text="Transfer History", padding=10)
        history_display_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Create treeview for transfer history
        columns = ('Time', 'Type', 'To', 'Size', 'Status', 'Details')
        self.transfer_tree = ttk.Treeview(history_display_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.transfer_tree.heading(col, text=col)
            self.transfer_tree.column(col, width=120)

        self.transfer_tree.pack(fill=tk.BOTH, expand=True)

        # History controls
        history_controls_frame = ttk.Frame(history_frame)
        history_controls_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(history_controls_frame, text="Clear History", command=self.clear_transfer_history).pack(side=tk.LEFT, padx=5)
        ttk.Button(history_controls_frame, text="Export History", command=self.export_transfer_history).pack(side=tk.LEFT, padx=5)

    def create_logs_tab(self, notebook):
        logs_frame = ttk.Frame(notebook)
        notebook.add(logs_frame, text="System Logs")

        # Logs display
        logs_display_frame = ttk.LabelFrame(logs_frame, text="System Logs", padding=10)
        logs_display_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.logs_text = scrolledtext.ScrolledText(
            logs_display_frame, height=25, font=("Consolas", 9), 
            bg='#1e1e1e', fg='#ff6b6b'
        )
        self.logs_text.pack(fill=tk.BOTH, expand=True)

        # Log controls
        log_controls_frame = ttk.Frame(logs_frame)
        log_controls_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(log_controls_frame, text="Clear Logs", command=self.clear_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(log_controls_frame, text="Export Logs", command=self.export_logs).pack(side=tk.LEFT, padx=5)

    def create_control_buttons(self, parent):
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=tk.X, pady=10)

        ttk.Button(button_frame, text="Connect to Router", command=self.connect_to_router).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Disconnect", command=self.disconnect_from_router).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Exit", command=self.root.quit).pack(side=tk.RIGHT, padx=5)

    def connect_to_router(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            #self.sock.settimeout(30)  # 30 second timeout for operations
            self.sock.connect((ROUTER_IP, ROUTER_PORT))
            # Send agent info
            agent_info = {'vlan': VLAN, 'dept': LOCAL_DEPT, 'timestamp': time.time()}
            self.sock.send(json.dumps(agent_info).encode())
            self.connected = True
            self.status_var.set("Connected")
            self.running = True
            threading.Thread(target=self.listen_to_router, daemon=True).start()
            self.log("[INFO] Connected to router at {}:{}".format(ROUTER_IP, ROUTER_PORT))
            self.activity_log("[INFO] Connected to router")
        except Exception as e:
            self.status_var.set("Disconnected")
            self.log(f"[ERROR] Connection failed: {e}")
            messagebox.showerror("Connection", f"Failed to connect: {e}")

    def disconnect_from_router(self):
        if not self.connected:
            messagebox.showinfo("Connection", "Not connected to router.")
            return
        self.running = False
        self.connected = False
        self.status_var.set("Disconnected")
        try:
            self.sock.close()
        except:
            pass
        self.log("[INFO] Disconnected from router")
        self.activity_log("[INFO] Disconnected from router")

    def listen_to_router(self):
        try:
            while self.running and self.connected:
                # Read data in chunks and accumulate until we have a complete JSON message
                data_buffer = b""
                max_buffer_size = 50 * 1024 * 1024  # 50MB limit to prevent memory issues
                
                while self.running and self.connected:
                    chunk = self.sock.recv(4096)
                    if not chunk:
                        break
                    data_buffer += chunk
                    
                    # Check if buffer is getting too large
                    if len(data_buffer) > max_buffer_size:
                        self.log(f"[ERROR] Received data too large ({len(data_buffer)} bytes), discarding")
                        break
                    
                    # Try to parse JSON - if it fails, continue reading
                    try:
                        response = json.loads(data_buffer.decode('utf-8'))
                        break  # Successfully parsed JSON, exit the inner loop
                    except json.JSONDecodeError:
                        # Incomplete JSON, continue reading
                        continue
                
                if not data_buffer:
                    break
                
                # Parse the complete JSON message
                try:
                    response = json.loads(data_buffer.decode('utf-8'))
                except json.JSONDecodeError as e:
                    self.log(f"[ERROR] Invalid JSON received: {e}")
                    continue
                
                response_type = response.get('type')
                
                if response_type in ['file_transfer_response', 'message_transfer_response']:
                    allowed = response.get('allowed', None)
                    message = response.get('message', '')
                    self.last_permission = allowed
                    self.permission_status.set("Allowed" if allowed else "Denied")
                    
                    if allowed:
                        self.stats['allowed_transfers'] += 1
                    else:
                        self.stats['denied_transfers'] += 1
                    
                    self.log(f"[PERMISSION] {response_type}: {'ALLOWED' if allowed else 'DENIED'} - {message}")
                    self.activity_log(f"[PERMISSION] {response_type}: {'ALLOWED' if allowed else 'DENIED'}")
                
                elif response_type == 'message_received':
                    # Handle received message
                    sender = response.get('sender', 'Unknown')
                    message_type = response.get('message_type', 'text')
                    content = response.get('content', '')
                    message_hash = response.get('message_hash', None)
                    
                    # Add to inbox
                    self.add_received_message(sender, message_type, content, message_hash)
                
                elif response_type == 'file_received':
                    # Handle received file
                    sender = response.get('sender', 'Unknown')
                    file_name = response.get('file_name', 'unknown_file')
                    file_size = response.get('file_size', 0)
                    file_data = response.get('file_data', '')
                    file_hash = response.get('file_hash', None) # Get the hash from the response
                    
                    # Save the file
                    self.save_received_file(sender, file_name, file_data, file_hash)
                
        except Exception as e:
            self.log(f"[ERROR] Router connection lost: {e}")
        finally:
            self.connected = False
            self.status_var.set("Disconnected")

    def browse_file(self):
        file_path = filedialog.askopenfilename(
            title="Select file to transfer",
            filetypes=[
                ("Text files", "*.txt"),
                ("Image files", "*.jpg *.jpeg *.png *.gif *.bmp"),
                ("All files", "*.*")
            ]
        )
        if file_path:
            self.file_path_var.set(file_path)
            self.preview_file(file_path)

    def preview_file(self, file_path):
        try:
            self.file_preview_text.delete(1.0, tk.END)
            
            # Check if it's an image file
            image_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp']
            if any(file_path.lower().endswith(ext) for ext in image_extensions):
                self.file_preview_text.insert(tk.END, f"Image file: {os.path.basename(file_path)}\n")
                self.file_preview_text.insert(tk.END, f"Size: {os.path.getsize(file_path)} bytes\n")
                self.file_preview_text.insert(tk.END, "Preview: [Image file - cannot display in text]\n")
            else:
                # Text file preview
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(1000)  # Read first 1000 characters
                    self.file_preview_text.insert(tk.END, f"File: {os.path.basename(file_path)}\n")
                    self.file_preview_text.insert(tk.END, f"Size: {os.path.getsize(file_path)} bytes\n")
                    self.file_preview_text.insert(tk.END, f"Preview:\n{content}")
                    if len(content) == 1000:
                        self.file_preview_text.insert(tk.END, "\n... (truncated)")
        except Exception as e:
            self.file_preview_text.insert(tk.END, f"Error previewing file: {e}")

    def send_file(self):
        if not self.connected:
            messagebox.showwarning("Not Connected", "Connect to router first.")
            return
        
        file_path = self.file_path_var.get()
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", "Please select a valid file.")
            return

        # Check file size (limit to 10MB to prevent memory issues)
        file_size = os.path.getsize(file_path)
        if file_size > 10 * 1024 * 1024:  # 10MB limit
            messagebox.showerror("Error", f"File too large ({file_size / (1024*1024):.1f}MB). Maximum size is 10MB.")
            return

        try:
            # Read file data
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Encode file data as base64
            file_data_b64 = base64.b64encode(file_data).decode('utf-8')
            file_hash = hashlib.sha256(file_data).hexdigest()
            self.log(f"[DEBUG] SHA-256 hash for {os.path.basename(file_path)}: {file_hash}")
            
            # Check if the encoded data is too large for a single JSON message
            if len(file_data_b64) > 1000000:  # 1MB limit for JSON payload
                messagebox.showerror("Error", "File too large to send. Please select a smaller file.")
                return
            
            # Create transfer request
            event = {
                'type': 'file_transfer_request',
                'src_vlan': VLAN,
                'dst_vlan': self.dest_vlan_var.get(),
                'file_name': os.path.basename(file_path),
                'file_size': len(file_data),
                'file_data': file_data_b64,
                'file_hash': file_hash, # Include hash in the request
                'auth_token': SHARED_SECRET,  # Shared token for authentication
                'timestamp': time.time()  # Ensure timestamp is included
            }
            
            # Send to router with error handling
            json_data = json.dumps(event)
            data_bytes = json_data.encode('utf-8')
            
            # Send in chunks if necessary
            chunk_size = 8192  # 8KB chunks
            total_sent = 0
            
            while total_sent < len(data_bytes):
                chunk = data_bytes[total_sent:total_sent + chunk_size]
                sent = self.sock.send(chunk)
                if sent == 0:
                    raise Exception("Connection broken")
                total_sent += sent
            
            # Update statistics
            self.stats['sent_transfers'] += 1
            
            # Add to history
            timestamp = datetime.datetime.now()
            transfer_info = {
                'timestamp': timestamp,
                'type': 'File',
                'to': self.dest_vlan_var.get(),
                'size': len(file_data),
                'status': 'Pending',
                'details': os.path.basename(file_path)
            }
            self.transfer_history.append(transfer_info)
            
            # Add to treeview
            self.transfer_tree.insert('', 0, values=(
                timestamp.strftime('%H:%M:%S'),
                'File',
                self.dest_vlan_var.get(),
                f"{len(file_data)} bytes",
                'Pending',
                os.path.basename(file_path)
            ))
            
            self.log(f"[TRANSFER] Sent file: {os.path.basename(file_path)} to {self.dest_vlan_var.get()}")
            self.activity_log(f"[TRANSFER] Sent file: {os.path.basename(file_path)} to {self.dest_vlan_var.get()}")
            
            # Clear file selection
            self.clear_file_selection()
            
        except Exception as e:
            self.log(f"[ERROR] Failed to send file: {e}")
            messagebox.showerror("Error", f"Failed to send file: {e}")

    def send_message(self):
        if not self.connected:
            messagebox.showwarning("Not Connected", "Connect to router first.")
            return
        
        message = self.message_text.get(1.0, tk.END).strip()
        if not message:
            messagebox.showerror("Error", "Please enter a message.")
            return

        try:
            message_type = self.msg_type_var.get()
            message_hash = hashlib.sha256(message.encode('utf-8')).hexdigest()
            self.log(f"[DEBUG] SHA-256 hash for message: {message_hash}")
            
            # Create transfer request
            event = {
                'type': 'message_transfer_request',
                'src_vlan': VLAN,
                'dst_vlan': self.msg_dest_var.get(),
                'message': message,
                'message_type': message_type,
                'message_hash': message_hash,
                'auth_token': SHARED_SECRET,  # Shared token for authentication
                'timestamp': time.time()  # Ensure timestamp is included
            }
            
            # Send to router
            start_time = time.time()
            self.sock.send(json.dumps(event).encode())
            end_time = time.time()
            transfer_time = end_time - start_time
            speed = len(message) / transfer_time if transfer_time > 0 else 0
            
            # Update statistics
            self.stats['sent_transfers'] += 1
            
            # Add to history
            timestamp = datetime.datetime.now()
            transfer_info = {
                'timestamp': timestamp,
                'type': message_type.capitalize(),
                'to': self.msg_dest_var.get(),
                'size': len(message),
                'status': 'Pending',
                'details': message[:50] + '...' if len(message) > 50 else message,
                'speed': speed,
                'latency': transfer_time
            }
            self.transfer_history.append(transfer_info)
            
            # Add to treeview
            self.transfer_tree.insert('', 0, values=(
                timestamp.strftime('%H:%M:%S'),
                message_type.capitalize(),
                self.msg_dest_var.get(),
                f"{len(message)} chars",
                'Pending',
                (message[:50] + '...' if len(message) > 50 else message) + f" | Speed: {speed:.2f} B/s | Latency: {transfer_time:.2f}s"
            ))
            
            self.log(f"[TRANSFER] Sent {message_type} message to {self.msg_dest_var.get()} | Speed: {speed:.2f} B/s | Latency: {transfer_time:.2f}s")
            self.activity_log(f"[TRANSFER] Sent {message_type} message to {self.msg_dest_var.get()}")
            
            # Clear message
            self.message_text.delete(1.0, tk.END)
            
        except Exception as e:
            self.log(f"[ERROR] Failed to send message: {e}")
            messagebox.showerror("Error", f"Failed to send message: {e}")

    def clear_file_selection(self):
        self.file_path_var.set("")
        self.file_preview_text.delete(1.0, tk.END)

    def clear_transfer_history(self):
        self.transfer_tree.delete(*self.transfer_tree.get_children())
        self.transfer_history.clear()

    def export_transfer_history(self):
        fname = f"vlan10_transfer_history_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(fname, 'w') as f:
            f.write("VLAN10 Transfer History Export\n")
            f.write("=" * 50 + "\n\n")
            for transfer in self.transfer_history:
                f.write(f"Time: {transfer['timestamp']}\n")
                f.write(f"Type: {transfer['type']}\n")
                f.write(f"To: {transfer['to']}\n")
                f.write(f"Size: {transfer['size']}\n")
                f.write(f"Status: {transfer['status']}\n")
                f.write(f"Details: {transfer['details']}\n")
                f.write("-" * 30 + "\n")
        messagebox.showinfo("Export", f"Transfer history exported to {fname}")

    def clear_logs(self):
        self.logs_text.delete(1.0, tk.END)

    def export_logs(self):
        fname = f"vlan10_logs_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(fname, 'w') as f:
            f.write(self.logs_text.get(1.0, tk.END))
        messagebox.showinfo("Export", f"Logs exported to {fname}")

    def refresh_inbox(self):
        """Refresh the message inbox display"""
        self.inbox_text.delete(1.0, tk.END)
        if not self.received_messages:
            self.inbox_text.insert(tk.END, "No messages received yet.\n")
            return
        
        for msg in self.received_messages:
            timestamp = msg.get('timestamp', 'Unknown')
            sender = msg.get('sender', 'Unknown')
            message_type = msg.get('type', 'text')
            content = msg.get('content', '')
            message_hash = msg.get('message_hash', None)
            
            self.inbox_text.insert(tk.END, f"[{timestamp}] From {sender} ({message_type}):\n")
            self.inbox_text.insert(tk.END, f"{content}\n")
            if message_hash:
                computed_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
                self.inbox_text.insert(tk.END, f"Hash: {message_hash} (Computed: {computed_hash})\n")
            self.inbox_text.insert(tk.END, "-" * 50 + "\n")
        
        self.inbox_text.see(tk.END)

    def clear_inbox(self):
        """Clear all received messages"""
        self.received_messages.clear()
        self.inbox_text.delete(1.0, tk.END)
        self.inbox_text.insert(tk.END, "Inbox cleared.\n")
        messagebox.showinfo("Inbox", "All messages cleared from inbox.")

    def export_messages(self):
        """Export received messages to file"""
        if not self.received_messages:
            messagebox.showinfo("Export", "No messages to export.")
            return
        
        fname = f"vlan10_messages_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(fname, 'w', encoding='utf-8') as f:
            f.write("VLAN10 (HR) - Received Messages\n")
            f.write("=" * 50 + "\n\n")
            for msg in self.received_messages:
                timestamp = msg.get('timestamp', 'Unknown')
                sender = msg.get('sender', 'Unknown')
                message_type = msg.get('type', 'text')
                content = msg.get('content', '')
                message_hash = msg.get('message_hash', None)
                
                f.write(f"Time: {timestamp}\n")
                f.write(f"From: {sender}\n")
                f.write(f"Type: {message_type}\n")
                f.write(f"Content: {content}\n")
                if message_hash:
                    computed_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
                    f.write(f"Hash: {message_hash} (Computed: {computed_hash})\n")
                f.write("-" * 30 + "\n")
        
        messagebox.showinfo("Export", f"Messages exported to {fname}")

    def add_received_message(self, sender, message_type, content, message_hash=None):
        """Add a received message to the inbox"""
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        if message_hash:
            computed_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
            self.log(f"[DEBUG] Received message hash: {message_hash}, Computed hash: {computed_hash}")
            if computed_hash != message_hash:
                self.log(f"[SECURITY] Message hash mismatch from {sender}! Possible corruption or tampering.")
        message = {
            'timestamp': timestamp,
            'sender': sender,
            'type': message_type,
            'content': content,
            'message_hash': message_hash  # Store the hash for export/inbox
        }
        self.received_messages.append(message)
        
        # Update inbox display
        self.inbox_text.insert(tk.END, f"[{timestamp}] From {sender} ({message_type}):\n")
        self.inbox_text.insert(tk.END, f"{content}\n")
        if message_hash:
            computed_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
            self.inbox_text.insert(tk.END, f"Hash: {message_hash} (Computed: {computed_hash})\n")
        self.inbox_text.insert(tk.END, "-" * 50 + "\n")
        self.inbox_text.see(tk.END)
        
        # Log the received message
        self.log(f"[RECEIVED] Message from {sender}: {content[:50]}...")
        self.activity_log(f"[RECEIVED] Message from {sender}")

    def save_received_file(self, sender, file_name, file_data, file_hash=None):
        """Save a received file to the local filesystem"""
        try:
            # Decode file data from base64
            file_data_decoded = base64.b64decode(file_data)
            
            # Create received_files directory if it doesn't exist
            received_dir = "received_files"
            if not os.path.exists(received_dir):
                os.makedirs(received_dir)
            
            # Save the file to received_files directory
            file_path = os.path.join(received_dir, file_name)
            
            # Handle duplicate filenames
            counter = 1
            original_name = file_name
            while os.path.exists(file_path):
                name, ext = os.path.splitext(original_name)
                file_name = f"{name}_{counter}{ext}"
                file_path = os.path.join(received_dir, file_name)
                counter += 1
            
            with open(file_path, 'wb') as f:
                f.write(file_data_decoded)
            
            # Add to history
            timestamp = datetime.datetime.now()
            transfer_info = {
                'timestamp': timestamp,
                'type': 'File',
                'from': sender,
                'size': len(file_data_decoded),
                'status': 'Received',
                'details': file_name
            }
            self.transfer_history.append(transfer_info)
            
            # Add to treeview
            self.transfer_tree.insert('', 0, values=(
                timestamp.strftime('%H:%M:%S'),
                'File',
                sender,
                f"{len(file_data_decoded)} bytes",
                'Received',
                file_name
            ))
            
            # Also add to received files treeview
            self.received_files_tree.insert('', 0, values=(
                timestamp.strftime('%H:%M:%S'),
                'File',
                sender,
                f"{len(file_data_decoded)} bytes",
                'Received',
                file_name
            ))
            
            self.log(f"[RECEIVED] Received file: {file_name} from {sender}")
            self.activity_log(f"[RECEIVED] Received file: {file_name} from {sender}")
            
            # Show success message
            messagebox.showinfo("File Received", f"File '{file_name}' received from {sender} and saved to {received_dir}/ directory.")
            
            if file_hash:
                computed_hash = hashlib.sha256(file_data_decoded).hexdigest()
                self.log(f"[DEBUG] Received hash: {file_hash}, Computed hash: {computed_hash}")
                if computed_hash != file_hash:
                    self.log(f"[SECURITY] File hash mismatch for {file_name} from {sender}! Possible corruption or tampering.")
                    messagebox.showerror("Security Alert", f"File hash mismatch for {file_name} from {sender}! Possible corruption or tampering.")
            
        except Exception as e:
            self.log(f"[ERROR] Failed to save received file: {e}")
            messagebox.showerror("Error", f"Failed to save received file: {e}")

    def log(self, msg):
        self.logs_text.insert(tk.END, msg + '\n')
        self.logs_text.see(tk.END)
        logging.info(msg)

    def activity_log(self, msg):
        self.activity_text.insert(tk.END, msg + '\n')
        self.activity_text.see(tk.END)

    def update_statistics(self):
        # Update success rate
        total = self.stats['sent_transfers']
        allowed = self.stats['allowed_transfers']
        if total > 0:
            success_rate = (allowed / total) * 100
        else:
            success_rate = 0
        
        self.stats_vars["Sent Transfers"].set(str(self.stats['sent_transfers']))
        self.stats_vars["Allowed Transfers"].set(str(self.stats['allowed_transfers']))
        self.stats_vars["Denied Transfers"].set(str(self.stats['denied_transfers']))
        self.stats_vars["Success Rate"].set(f"{success_rate:.1f}%")

    def run(self):
        # Start statistics update thread
        def update_stats_loop():
            while True:
                self.update_statistics()
                time.sleep(2)
        
        threading.Thread(target=update_stats_loop, daemon=True).start()
        self.root.mainloop()

    def clear_received_files(self):
        """Clear received files display"""
        self.received_files_tree.delete(*self.received_files_tree.get_children())
        messagebox.showinfo("Received Files", "Received files display cleared.")

    def export_received_files(self):
        """Export received files list to file"""
        received_files = []
        for item in self.received_files_tree.get_children():
            values = self.received_files_tree.item(item)['values']
            received_files.append({
                'time': values[0],
                'type': values[1],
                'from': values[2],
                'size': values[3],
                'status': values[4],
                'details': values[5]
            })
        
        if not received_files:
            messagebox.showinfo("Export", "No received files to export.")
            return
        
        fname = f"vlan10_received_files_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(fname, 'w', encoding='utf-8') as f:
            f.write("VLAN10 (HR) - Received Files\n")
            f.write("=" * 50 + "\n\n")
            for file_info in received_files:
                f.write(f"Time: {file_info['time']}\n")
                f.write(f"Type: {file_info['type']}\n")
                f.write(f"From: {file_info['from']}\n")
                f.write(f"Size: {file_info['size']}\n")
                f.write(f"Status: {file_info['status']}\n")
                f.write(f"Details: {file_info['details']}\n")
                f.write("-" * 30 + "\n")
        
        messagebox.showinfo("Export", f"Received files list exported to {fname}")

if __name__ == "__main__":
    app = EnhancedVLAN10Agent()
    app.run() 
