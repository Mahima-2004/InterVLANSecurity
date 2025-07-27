#!/usr/bin/env python3
"""
router_monitor.py - Enhanced Central Controller for Distributed Inter-VLAN Monitoring
- Listens for agent connections (VLAN10, VLAN20)
- Receives file transfer requests and enforces permissions
- Provides enhanced GUI with real-time monitoring
- Handles text messages and image transfers
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import socket
import queue
import time
import datetime
import json
import logging
import os
import base64
from collections import defaultdict, deque
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
import random # Added for simulated packet loss

# --- CONFIGURATION ---
ROUTER_IP = '0.0.0.0'  # Listen on all interfaces
ROUTER_PORT = 50050
# AGENT_TIMEOUT = 10  # seconds - DISABLED for now

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('router_monitor.log'),
        logging.StreamHandler()
    ]
)

SHARED_SECRET = 'SHARED_SECRET'  # Shared authentication token

class EnhancedRouterMonitor:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Enhanced Router Monitor - Inter-VLAN Controller")
        self.root.geometry("1400x900")
        self.root.configure(bg='#2b2b2b')

        # Agent state
        self.agent_status = {
            'VLAN10': {'ip': None, 'last_seen': None, 'status': 'Disconnected', 'dept': 'HR'},
            'VLAN20': {'ip': None, 'last_seen': None, 'status': 'Disconnected', 'dept': 'Finance'}
        }
        self.permission_matrix = {
            ('VLAN10', 'VLAN20'): True,
            ('VLAN20', 'VLAN10'): True
        }
        self.event_queue = queue.Queue()
        self.gui_update_queue = queue.Queue()  # Queue for GUI updates
        self.running = False
        self.server_thread = None
        self.gui_update_thread = None
        self.connections = {}
        self.traffic_log = []
        self.transfer_history = []
        self.stats = {
            'total_transfers': 0,
            'allowed_transfers': 0,
            'denied_transfers': 0,
            'vlan10_transfers': 0,
            'vlan20_transfers': 0
        }

        # Data structures for charts
        self.transfer_times = deque(maxlen=100)
        self.transfer_sizes = deque(maxlen=100)
        self.permission_decisions = deque(maxlen=100)

        self.qos_latencies = []  # List of all latencies (seconds)
        self.qos_throughputs = []  # List of all throughputs (bytes/sec)
        self.qos_last_latency = None
        self.qos_last_throughput = None
        self.qos_lock = threading.Lock()

        # Add new data tracking for bandwidth and packet loss
        self.bandwidth_history = deque(maxlen=100)  # (timestamp, Mbps)
        self.latency_history = deque(maxlen=100)    # (timestamp, latency)
        self.jitter_history = deque(maxlen=100)     # (timestamp, jitter)
        self.packet_loss_history = deque(maxlen=100) # (timestamp, loss%)
        self.last_transfer_time = None
        self.last_transfer_count = 0
        self.last_latency = None
        self.simulated_total_packets = 0
        self.simulated_lost_packets = 0

        self.setup_gui()

    def setup_gui(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Title
        title = tk.Label(main_frame, text="Enhanced Router Monitor - Inter-VLAN Controller", 
                        font=("Arial", 16, "bold"), bg='#2b2b2b', fg='white')
        title.pack(pady=(0, 10))

        # Create notebook for tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)

        # Dashboard tab
        self.create_dashboard_tab(notebook)
        
        # Transfer Monitor tab
        self.create_transfer_monitor_tab(notebook)
        
        # Permission Control tab
        self.create_permission_control_tab(notebook)
        
        # Traffic Analysis tab
        self.create_traffic_analysis_tab(notebook)
        
        # Logs tab
        self.create_logs_tab(notebook)
        self.create_qos_tab(notebook)  # <-- Add new QoS tab
        # Control buttons
        self.create_control_buttons(main_frame)

    def create_dashboard_tab(self, notebook):
        dashboard_frame = ttk.Frame(notebook)
        notebook.add(dashboard_frame, text="Dashboard")

        # Agent status
        status_frame = ttk.LabelFrame(dashboard_frame, text="Agent Status", padding=10)
        status_frame.pack(fill=tk.X, padx=10, pady=5)

        self.agent_vars = {}
        for vlan in ['VLAN10', 'VLAN20']:
            frame = ttk.Frame(status_frame)
            frame.pack(side=tk.LEFT, padx=20)
            ttk.Label(frame, text=f"{vlan} ({self.agent_status[vlan]['dept']})").pack()
            var = tk.StringVar(value="Disconnected")
            self.agent_vars[vlan] = var
            status_label = tk.Label(frame, textvariable=var, fg='red', font=("Arial", 10, "bold"))
            status_label.pack()

        # Statistics
        stats_frame = ttk.LabelFrame(dashboard_frame, text="Transfer Statistics", padding=10)
        stats_frame.pack(fill=tk.X, padx=10, pady=5)

        self.stats_vars = {}
        stats_items = [
            ("Total Transfers", "0"),
            ("Allowed Transfers", "0"),
            ("Denied Transfers", "0"),
            ("VLAN10 → VLAN20", "0"),
            ("VLAN20 → VLAN10", "0"),
            ("Active Connections", "0")
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

    def create_transfer_monitor_tab(self, notebook):
        transfer_frame = ttk.Frame(notebook)
        notebook.add(transfer_frame, text="Transfer Monitor")

        # Transfer history
        history_frame = ttk.LabelFrame(transfer_frame, text="Transfer History", padding=10)
        history_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Create treeview for transfer history
        columns = ('Time', 'From', 'To', 'Type', 'Size', 'Status', 'Details')
        self.transfer_tree = ttk.Treeview(history_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.transfer_tree.heading(col, text=col)
            self.transfer_tree.column(col, width=120)

        self.transfer_tree.pack(fill=tk.BOTH, expand=True)

        # Transfer controls
        controls_frame = ttk.Frame(transfer_frame)
        controls_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(controls_frame, text="Clear History", command=self.clear_transfer_history).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Export History", command=self.export_transfer_history).pack(side=tk.LEFT, padx=5)

    def create_permission_control_tab(self, notebook):
        perm_frame = ttk.Frame(notebook)
        notebook.add(perm_frame, text="Permission Control")

        # Permission matrix
        perm_matrix_frame = ttk.LabelFrame(perm_frame, text="Inter-VLAN Permissions", padding=10)
        perm_matrix_frame.pack(fill=tk.X, padx=10, pady=5)

        self.perm_vars = {}
        for src, dst in [('VLAN10 (HR)', 'VLAN20 (Finance)'), ('VLAN20 (Finance)', 'VLAN10 (HR)')]:
            var = tk.BooleanVar(value=self.permission_matrix[(src.split()[0], dst.split()[0])])
            self.perm_vars[(src.split()[0], dst.split()[0])] = var
            cb = ttk.Checkbutton(perm_matrix_frame, text=f"Allow {src} → {dst}", 
                               variable=var, command=self.update_permissions)
            cb.pack(side=tk.LEFT, padx=10, pady=5)

        # Quick actions
        actions_frame = ttk.LabelFrame(perm_frame, text="Quick Actions", padding=10)
        actions_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(actions_frame, text="Allow All", command=self.allow_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Deny All", command=self.deny_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="HR Only", command=self.hr_only).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Finance Only", command=self.finance_only).pack(side=tk.LEFT, padx=5)

        # Permission log
        perm_log_frame = ttk.LabelFrame(perm_frame, text="Permission Changes Log", padding=10)
        perm_log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.perm_log_text = scrolledtext.ScrolledText(
            perm_log_frame, height=15, font=("Consolas", 9), 
            bg='#1e1e1e', fg='#4ecdc4'
        )
        self.perm_log_text.pack(fill=tk.BOTH, expand=True)

    def create_traffic_analysis_tab(self, notebook):
        analysis_frame = ttk.Frame(notebook)
        notebook.add(analysis_frame, text="Traffic Analysis")

        # Add a description at the top
        desc = (
            "Traffic Analysis Overview:\n"
            "1. Transfer Volume Over Time: Number of file transfers per minute.\n"
            "2. Bandwidth Utilization: Network usage in Mbps over time.\n"
            "3. Latency and Jitter: Transfer delay and its variation.\n"
            "4. File Size vs. Transfer Time: Each dot is a file transfer (time vs. size)."
        )
        desc_label = ttk.Label(analysis_frame, text=desc, font=("Arial", 11, "italic"), anchor="w", justify="left")
        desc_label.pack(fill=tk.X, padx=10, pady=(10, 0))

        # Create matplotlib figure for charts (2x2 grid)
        self.fig, ((self.ax1, self.ax2), (self.ax3, self.ax4)) = plt.subplots(2, 2, figsize=(16, 10))
        self.fig.patch.set_facecolor('#23272e')
        self.fig.subplots_adjust(hspace=0.35, wspace=0.25)

        # ax1: Transfer volume
        self.ax1.set_title('Transfer Volume Over Time', color='#1f77b4', fontsize=15, fontweight='bold', pad=12)
        self.ax1.set_ylabel('Transfers/min', color='#1f77b4', fontsize=12, fontweight='bold', labelpad=8)
        self.ax1.set_xlabel('Time (seconds since start)', color='#1f77b4', fontsize=12, fontweight='bold', labelpad=8)
        self.ax1.set_facecolor('#181c20')
        self.ax1.grid(True, alpha=0.25, color='#aaa', linestyle='--')
        self.ax1.tick_params(colors='#1f77b4', labelsize=10)

        # ax2: Bandwidth
        self.ax2.set_title('Bandwidth Utilization (Mbps)', color='#2ca02c', fontsize=15, fontweight='bold', pad=12)
        self.ax2.set_ylabel('Mbps', color='#2ca02c', fontsize=12, fontweight='bold', labelpad=8)
        self.ax2.set_xlabel('Time (seconds since start)', color='#2ca02c', fontsize=12, fontweight='bold', labelpad=8)
        self.ax2.set_facecolor('#181c20')
        self.ax2.grid(True, alpha=0.25, color='#aaa', linestyle='--')
        self.ax2.tick_params(colors='#2ca02c', labelsize=10)

        # ax3: Latency/Jitter
        self.ax3.set_title('Latency and Jitter Over Time', color='#d62728', fontsize=15, fontweight='bold', pad=12)
        self.ax3.set_ylabel('Seconds', color='#d62728', fontsize=12, fontweight='bold', labelpad=8)
        self.ax3.set_xlabel('Time (seconds since start)', color='#d62728', fontsize=12, fontweight='bold', labelpad=8)
        self.ax3.set_facecolor('#181c20')
        self.ax3.grid(True, alpha=0.25, color='#aaa', linestyle='--')
        self.ax3.tick_params(colors='#d62728', labelsize=10)

        # ax4: File size vs. time
        self.ax4.set_title('File Size vs. Transfer Time', color='#9467bd', fontsize=15, fontweight='bold', pad=12)
        self.ax4.set_xlabel('Time (seconds since start)', color='#9467bd', fontsize=12, fontweight='bold', labelpad=8)
        self.ax4.set_ylabel('File Size (bytes)', color='#9467bd', fontsize=12, fontweight='bold', labelpad=8)
        self.ax4.set_facecolor('#181c20')
        self.ax4.grid(True, alpha=0.25, color='#aaa', linestyle='--')
        self.ax4.tick_params(colors='#9467bd', labelsize=10)

        # Embed chart in tkinter
        self.canvas = FigureCanvasTkAgg(self.fig, analysis_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        # Chart controls
        chart_controls_frame = ttk.Frame(analysis_frame)
        chart_controls_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Button(chart_controls_frame, text="Refresh Charts", command=self.update_charts).pack(side=tk.LEFT, padx=5)
        ttk.Button(chart_controls_frame, text="Clear Chart Data", command=self.clear_chart_data).pack(side=tk.LEFT, padx=5)
        ttk.Button(chart_controls_frame, text="Export Charts", command=self.export_charts).pack(side=tk.LEFT, padx=5)

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

    def create_qos_tab(self, notebook):
        qos_frame = ttk.Frame(notebook)
        notebook.add(qos_frame, text="QoS Report")
        self.qos_latency_var = tk.StringVar(value="-")
        self.qos_throughput_var = tk.StringVar(value="-")
        self.qos_jitter_var = tk.StringVar(value="-")
        self.qos_count_var = tk.StringVar(value="0")
        self.qos_packet_count_var = tk.StringVar(value="0")  # New: for packet count
        self.qos_chunk_count_var = tk.StringVar(value="0")   # New: for chunk count
        # Layout
        ttk.Label(qos_frame, text="Quality of Service (QoS) Metrics", font=("Arial", 14, "bold")).pack(pady=10)
        stats_frame = ttk.Frame(qos_frame)
        stats_frame.pack(pady=10)
        ttk.Label(stats_frame, text="Latency (s):", font=("Arial", 11)).grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        ttk.Label(stats_frame, textvariable=self.qos_latency_var, font=("Arial", 11, "bold")).grid(row=0, column=1, sticky=tk.W, padx=10, pady=5)
        ttk.Label(stats_frame, text="Throughput (bytes/sec):", font=("Arial", 11)).grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        ttk.Label(stats_frame, textvariable=self.qos_throughput_var, font=("Arial", 11, "bold")).grid(row=1, column=1, sticky=tk.W, padx=10, pady=5)
        ttk.Label(stats_frame, text="Jitter (s):", font=("Arial", 11)).grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
        ttk.Label(stats_frame, textvariable=self.qos_jitter_var, font=("Arial", 11, "bold")).grid(row=2, column=1, sticky=tk.W, padx=10, pady=5)
        ttk.Label(stats_frame, text="Total Transfers Measured:", font=("Arial", 11)).grid(row=3, column=0, sticky=tk.W, padx=10, pady=5)
        ttk.Label(stats_frame, textvariable=self.qos_count_var, font=("Arial", 11, "bold")).grid(row=3, column=1, sticky=tk.W, padx=10, pady=5)
        # New: Add packet and chunk count to QoS tab
        ttk.Label(stats_frame, text="Packets Sent (last transfer):", font=("Arial", 11)).grid(row=4, column=0, sticky=tk.W, padx=10, pady=5)
        ttk.Label(stats_frame, textvariable=self.qos_packet_count_var, font=("Arial", 11, "bold")).grid(row=4, column=1, sticky=tk.W, padx=10, pady=5)
        ttk.Label(stats_frame, text="Chunks Sent (last transfer):", font=("Arial", 11)).grid(row=5, column=0, sticky=tk.W, padx=10, pady=5)
        ttk.Label(stats_frame, textvariable=self.qos_chunk_count_var, font=("Arial", 11, "bold")).grid(row=5, column=1, sticky=tk.W, padx=10, pady=5)
        ttk.Button(qos_frame, text="Refresh QoS Report", command=self.update_qos_report).pack(pady=10)

    def create_control_buttons(self, parent):
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=tk.X, pady=10)

        ttk.Button(button_frame, text="Start Server", command=self.start_server).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Stop Server", command=self.stop_server).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Refresh Charts", command=self.update_charts).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Exit", command=self.root.quit).pack(side=tk.RIGHT, padx=5)

    def start_server(self):
        if not self.running:
            self.running = True
            self.server_thread = threading.Thread(target=self.server_loop, daemon=True)
            self.server_thread.start()
            self.gui_update_thread = threading.Thread(target=self.gui_update_loop, daemon=True)
            self.gui_update_thread.start()
            self.log("[INFO] Enhanced server started. Waiting for agent connections...")
            messagebox.showinfo("Server", "Enhanced router server started!")

    def stop_server(self):
        self.running = False
        for conn in self.connections.values():
            try:
                conn.close()
            except:
                pass
        self.connections.clear()
        self.log("[INFO] Server stopped.")
        messagebox.showinfo("Server", "Router server stopped!")

    def server_loop(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((ROUTER_IP, ROUTER_PORT))
            s.listen(5)
            # s.settimeout(1)  # Removed timeout
            while self.running:
                try:
                    conn, addr = s.accept()
                    threading.Thread(target=self.handle_agent, args=(conn, addr), daemon=True).start()
                except Exception as e:
                    self.log(f"[ERROR] Server error: {e}")

    def handle_agent(self, conn, addr):
        try:
            # First message should be agent info
            data = conn.recv(1024)
            agent_info = json.loads(data.decode())
            vlan = agent_info.get('vlan')
            if vlan not in self.agent_status:
                self.log(f"[WARN] Unknown agent VLAN: {vlan} from {addr}")
                conn.close()
                return
            self.agent_status[vlan]['ip'] = addr[0]
            self.agent_status[vlan]['last_seen'] = time.time()
            self.agent_status[vlan]['status'] = 'Connected'
            self.connections[vlan] = conn
            self.log(f"[INFO] {vlan} agent connected from {addr[0]}")
            self.safe_gui_update(lambda v=vlan: self.agent_vars[v].set("Connected"))
            
            # Listen for events
            while self.running:
                try:
                    # Read data in chunks to handle large messages
                    data = b''
                    while True:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                        
                        # Try to parse JSON, if it fails, continue reading
                        try:
                            event = json.loads(data.decode())
                            break  # Successfully parsed JSON
                        except json.JSONDecodeError:
                            # Check if we have a complete JSON object
                            if data.count(b'{') == data.count(b'}'):
                                try:
                                    event = json.loads(data.decode())
                                    break
                                except json.JSONDecodeError:
                                    # Still incomplete, continue reading
                                    continue
                            # Continue reading more data
                            continue
                    
                    if not data:
                        break
                        
                    # Parse the complete JSON data
                    try:
                        event = json.loads(data.decode())
                        self.agent_status[vlan]['last_seen'] = time.time()
                        self.process_event(vlan, event)
                    except json.JSONDecodeError as e:
                        self.log(f"[ERROR] Invalid JSON from {vlan}: {e}")
                        continue
                        
                except Exception as e:
                    self.log(f"[ERROR] Error receiving data from {vlan}: {e}")
                    break
        except Exception as e:
            self.log(f"[ERROR] Agent handler error: {e}")
        finally:
            if vlan in self.agent_status:
                self.agent_status[vlan]['status'] = 'Disconnected'
                self.safe_gui_update(lambda v=vlan: self.agent_vars[v].set("Disconnected"))
            try:
                conn.close()
            except:
                pass
            if vlan in self.connections:
                del self.connections[vlan]
            self.log(f"[INFO] {vlan} agent disconnected.")

    def process_event(self, vlan, event):
        event_type = event.get('type')
        
        if event_type == 'file_transfer_request':
            self.handle_file_transfer_request(vlan, event)
        elif event_type == 'message_transfer_request':
            self.handle_message_transfer_request(vlan, event)
        else:
            self.log(f"[INFO] Unknown event type: {event_type}")

    def handle_file_transfer_request(self, vlan, event):
        src = vlan
        dst = event.get('dst_vlan')
        file_name = event.get('file_name', 'Unknown')
        file_size = event.get('file_size', 0)
        file_data = event.get('file_data', '')
        auth_token = event.get('auth_token', None)
        send_time = event.get('timestamp', None)
        recv_time = time.time()
        # Authentication check
        if auth_token != SHARED_SECRET:
            allowed = False
            self.log(f"[SECURITY] Authentication failed for file transfer from {src} to {dst} ({file_name}). Provided token: {auth_token}")
            # Respond to agent immediately and return
            response = {
                'type': 'file_transfer_response',
                'allowed': False,
                'message': 'File transfer denied: authentication failed (invalid shared secret)'
            }
            try:
                self.connections[src].send(json.dumps(response).encode())
            except:
                pass
            return
        allowed = self.permission_matrix.get((src, dst), False)
        # Update statistics (only for allowed/denied counts, not for charts)
        self.stats['total_transfers'] += 1
        if allowed:
            self.stats['allowed_transfers'] += 1
        else:
            self.stats['denied_transfers'] += 1
        if src == 'VLAN10':
            self.stats['vlan10_transfers'] += 1
        else:
            self.stats['vlan20_transfers'] += 1
        # Log the transfer (for history, not for charts)
        timestamp = datetime.datetime.now()
        transfer_info = {
            'timestamp': timestamp,
            'src': src,
            'dst': dst,
            'type': 'File',
            'name': file_name,
            'size': file_size,
            'allowed': allowed
        }
        self.transfer_history.append(transfer_info)
        # Add to treeview
        self.safe_gui_update(lambda: self.transfer_tree.insert('', 0, values=(
            timestamp.strftime('%H:%M:%S'),
            src,
            dst,
            'File',
            f"{file_size} bytes",
            'Allowed' if allowed else 'Denied',
            file_name
        )))
        # Update activity log
        activity_msg = f"[{timestamp.strftime('%H:%M:%S')}] {src} -> {dst} | File: {file_name} | {'ALLOWED' if allowed else 'DENIED'}"
        self.safe_gui_update(lambda: self.activity_text.insert(tk.END, activity_msg + '\n'))
        self.safe_gui_update(lambda: self.activity_text.see(tk.END))
        # Respond to agent
        response = {
            'type': 'file_transfer_response',
            'allowed': allowed,
            'message': f"File transfer {'approved' if allowed else 'denied'} by router"
        }
        try:
            self.connections[src].send(json.dumps(response).encode())
        except:
            pass
        # Only update charts and QoS if transfer is allowed and forwarded
        if allowed and dst in self.connections:
            forward_file = {
                'type': 'file_received',
                'sender': src,
                'file_name': file_name,
                'file_size': file_size,
                'file_data': file_data,
                'file_hash': event.get('file_hash', None)  # Forward the hash
            }
            try:
                json_data = json.dumps(forward_file)
                data_bytes = json_data.encode('utf-8')
                chunk_size = 8192  # 8KB chunks
                total_sent = 0
                chunk_count = 0
                packet_sizes = []
                # --- Router-side timing start ---
                start_time = time.time()
                while total_sent < len(data_bytes):
                    chunk = data_bytes[total_sent:total_sent + chunk_size]
                    sent = self.connections[dst].send(chunk)
                    if sent == 0:
                        raise Exception("Connection broken")
                    total_sent += sent
                    chunk_count += 1
                    packet_sizes.append(len(chunk))
                    self.log(f"[PACKET] Chunk {chunk_count}: {len(chunk)} bytes sent")
                time.sleep(0.1)
                end_time = time.time()  # --- Router-side timing end ---
                self.log(f"[FORWARD] File forwarded from {src} to {dst} in {chunk_count} chunk(s)")
                self.safe_gui_update(lambda: self.qos_chunk_count_var.set(str(chunk_count)))
                self.safe_gui_update(lambda: self.qos_packet_count_var.set(str(chunk_count)))
                self.log(f"[PACKET SIZES] Last transfer packet sizes: {packet_sizes}")
                # --- QoS metrics using router-side timing ---
                latency = end_time - start_time
                if latency < 0:
                    self.log("[WARNING] Negative latency detected in router-side timing. Setting latency to 0.")
                    latency = 0.0
                if latency > 0:
                    throughput = file_size / latency
                else:
                    throughput = 0.0
                now = end_time
                # Only here: update chart data and QoS
                self.transfer_times.append(now)
                self.transfer_sizes.append(file_size)
                self.permission_decisions.append(1)
                # Bandwidth calculation (Mbps)
                if self.last_transfer_time is not None:
                    time_delta = now - self.last_transfer_time
                    if time_delta > 0:
                        bytes_delta = sum(list(self.transfer_sizes)[-2:])
                        mbps = (bytes_delta * 8) / (time_delta * 1_000_000)
                        self.bandwidth_history.append((now, mbps))
                self.last_transfer_time = now
                self.latency_history.append((now, latency))
                if self.last_latency is not None:
                    jitter = abs(latency - self.last_latency)
                    self.jitter_history.append((now, jitter))
                self.last_latency = latency
                with self.qos_lock:
                    self.qos_latencies.append(latency)
                    self.qos_throughputs.append(throughput)
                    self.qos_last_latency = latency
                    self.qos_last_throughput = throughput
                self.safe_gui_update(self.update_charts)
                self.safe_gui_update(self.update_qos_report)
            except Exception as e:
                self.log(f"[ERROR] Failed to forward file to {dst}: {e}")
                if dst in self.connections:
                    try:
                        self.connections[dst].close()
                    except:
                        pass
                    del self.connections[dst]
                    self.agent_status[dst]['status'] = 'Disconnected'
                    self.safe_gui_update(lambda v=dst: self.agent_vars[v].set("Disconnected"))
        else:
            # If not allowed, reset chunk/packet count and do NOT update charts/QoS
            self.safe_gui_update(lambda: self.qos_chunk_count_var.set("0"))
            self.safe_gui_update(lambda: self.qos_packet_count_var.set("0"))

        self.log(f"[TRANSFER] {src} -> {dst} | File: {file_name} | {'ALLOWED' if allowed else 'DENIED'}")

        # QoS measurement
        # with self.qos_lock: # This block is now redundant as latency/throughput are calculated in the forwarding loop
        #     if 'timestamp' in event and event['timestamp'] is not None:
        #         latency = recv_time - event['timestamp']
        #         if latency < 0:
        #             self.log("[WARNING] Negative latency detected. Possible clock skew between sender and router. Setting latency to 0.")
        #             latency = 0.0
        #     else:
        #         latency = 0.0
        #     self.qos_latencies.append(latency)
        #     if latency > 0:
        #         throughput = file_size / latency
        #     else:
        #         throughput = 0.0
        #     self.qos_throughputs.append(throughput)
        #     self.qos_last_latency = latency
        #     self.qos_last_throughput = throughput
        # self.safe_gui_update(self.update_qos_report)

    def handle_message_transfer_request(self, vlan, event):
        src = vlan
        dst = event.get('dst_vlan')
        message = event.get('message', '')
        message_type = event.get('message_type', 'text')
        auth_token = event.get('auth_token', None)
        send_time = event.get('timestamp', None)
        recv_time = time.time()
        # Authentication check
        if auth_token != SHARED_SECRET:
            allowed = False
            self.log(f"[SECURITY] Authentication failed for message transfer from {src} to {dst}. Provided token: {auth_token}")
            # Respond to agent immediately and return
            response = {
                'type': 'message_transfer_response',
                'allowed': False,
                'message': 'Message transfer denied: authentication failed (invalid shared secret)'
            }
            try:
                self.connections[src].send(json.dumps(response).encode())
            except:
                pass
            return
        allowed = self.permission_matrix.get((src, dst), False)
        
        # Update statistics
        self.stats['total_transfers'] += 1
        if allowed:
            self.stats['allowed_transfers'] += 1
        else:
            self.stats['denied_transfers'] += 1
            
        if src == 'VLAN10':
            self.stats['vlan10_transfers'] += 1
        else:
            self.stats['vlan20_transfers'] += 1

        # Log the transfer
        timestamp = datetime.datetime.now()
        transfer_info = {
            'timestamp': timestamp,
            'src': src,
            'dst': dst,
            'type': message_type.capitalize(),
            'name': f"{message_type} message",
            'size': len(message),
            'allowed': allowed
        }
        self.transfer_history.append(transfer_info)
        
        # Add to treeview
        self.safe_gui_update(lambda: self.transfer_tree.insert('', 0, values=(
            timestamp.strftime('%H:%M:%S'),
            src,
            dst,
            message_type.capitalize(),
            f"{len(message)} chars",
            'Allowed' if allowed else 'Denied',
            message[:50] + '...' if len(message) > 50 else message
        )))

        # Update activity log
        activity_msg = f"[{timestamp.strftime('%H:%M:%S')}] {src} -> {dst} | {message_type.capitalize()}: {message[:30]}... | {'ALLOWED' if allowed else 'DENIED'}"
        self.safe_gui_update(lambda: self.activity_text.insert(tk.END, activity_msg + '\n'))
        self.safe_gui_update(lambda: self.activity_text.see(tk.END))

        # Store data for charts
        self.transfer_times.append(time.time())
        self.transfer_sizes.append(len(message))
        self.permission_decisions.append(1 if allowed else 0)

        # Update charts immediately
        self.safe_gui_update(self.update_charts)

        # Respond to sender
        response = {
            'type': 'message_transfer_response',
            'allowed': allowed,
            'message': f"Message transfer {'approved' if allowed else 'denied'} by router"
        }
        try:
            self.connections[src].send(json.dumps(response).encode())
        except:
            pass

        # Forward message to destination if allowed
        if allowed and dst in self.connections:
            forward_message = {
                'type': 'message_received',
                'sender': src,
                'message_type': message_type,
                'content': message
            }
            try:
                self.connections[dst].send(json.dumps(forward_message).encode())
                self.log(f"[FORWARD] Message forwarded from {src} to {dst}")
            except Exception as e:
                self.log(f"[ERROR] Failed to forward message to {dst}: {e}")

        self.log(f"[TRANSFER] {src} -> {dst} | {message_type.capitalize()}: {message[:30]}... | {'ALLOWED' if allowed else 'DENIED'}")

        # QoS measurement
        # with self.qos_lock: # This block is now redundant as latency/throughput are calculated in the forwarding loop
        #     if 'timestamp' in event and event['timestamp'] is not None:
        #         latency = recv_time - event['timestamp']
        #     else:
        #         latency = 0.0
        #     self.qos_latencies.append(latency)
        #     if latency > 0:
        #         throughput = len(message.encode()) / latency
        #     else:
        #         throughput = 0.0
        #     self.qos_throughputs.append(throughput)
        #     self.qos_last_latency = latency
        #     self.qos_last_throughput = throughput
        # self.safe_gui_update(self.update_qos_report)

    def update_permissions(self):
        for (src, dst), var in self.perm_vars.items():
            self.permission_matrix[(src, dst)] = var.get()
        
        perm_msg = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Permission matrix updated"
        self.safe_gui_update(lambda: self.perm_log_text.insert(tk.END, perm_msg + '\n'))
        self.safe_gui_update(lambda: self.perm_log_text.see(tk.END))
        self.log("[INFO] Permission matrix updated.")

    def allow_all(self):
        for var in self.perm_vars.values():
            var.set(True)
        self.update_permissions()

    def deny_all(self):
        for var in self.perm_vars.values():
            var.set(False)
        self.update_permissions()

    def hr_only(self):
        self.perm_vars[('VLAN10', 'VLAN20')].set(True)
        self.perm_vars[('VLAN20', 'VLAN10')].set(False)
        self.update_permissions()

    def finance_only(self):
        self.perm_vars[('VLAN10', 'VLAN20')].set(False)
        self.perm_vars[('VLAN20', 'VLAN10')].set(True)
        self.update_permissions()

    def gui_update_loop(self):
        while self.running:
            # Update statistics (no timeout checks)
            self.safe_gui_update(lambda: self.stats_vars["Total Transfers"].set(str(self.stats['total_transfers'])))
            self.safe_gui_update(lambda: self.stats_vars["Allowed Transfers"].set(str(self.stats['allowed_transfers'])))
            self.safe_gui_update(lambda: self.stats_vars["Denied Transfers"].set(str(self.stats['denied_transfers'])))
            self.safe_gui_update(lambda: self.stats_vars["VLAN10 → VLAN20"].set(str(self.stats['vlan10_transfers'])))
            self.safe_gui_update(lambda: self.stats_vars["VLAN20 → VLAN10"].set(str(self.stats['vlan20_transfers'])))
            self.safe_gui_update(lambda: self.stats_vars["Active Connections"].set(str(len(self.connections))))

            # Update charts every 5 seconds
            self.safe_gui_update(self.update_charts)

            time.sleep(2)

    def update_charts(self):
        try:
            # Clear all axes
            for ax in [self.ax1, self.ax2, self.ax3, self.ax4]:
                ax.clear()
            # --- ax1: Traffic volume over time ---
            self.ax1.set_title('Transfer Volume Over Time', color='#1f77b4', fontsize=15, fontweight='bold', pad=12)
            self.ax1.set_ylabel('Transfers/min', color='#1f77b4', fontsize=12, fontweight='bold', labelpad=8)
            self.ax1.set_xlabel('Time (seconds since start)', color='#1f77b4', fontsize=12, fontweight='bold', labelpad=8)
            self.ax1.set_facecolor('#181c20')
            self.ax1.grid(True, alpha=0.25, color='#aaa', linestyle='--')
            self.ax1.tick_params(colors='#1f77b4', labelsize=10)
            if self.transfer_times:
                times = np.array(self.transfer_times)
                t0 = times.min()
                rel_times = times - t0
                if len(times) > 1:
                    min_time = rel_times.min()
                    max_time = rel_times.max()
                    bins = np.arange(min_time, max_time + 60, 60)
                    counts, edges = np.histogram(rel_times, bins=bins)
                    self.ax1.plot(edges[:-1], counts, color='#1f77b4', linewidth=2, marker='o', label='Transfers/min')
                    self.ax1.legend()
                else:
                    self.ax1.plot([rel_times[0]], [1], 'o', color='#1f77b4', label='Single Transfer')
                    self.ax1.legend()
            else:
                self.ax1.text(0.5, 0.5, 'No transfers yet', ha='center', va='center', transform=self.ax1.transAxes, color='#1f77b4', fontsize=12)
            # --- ax2: Bandwidth utilization ---
            self.ax2.set_title('Bandwidth Utilization (Mbps)', color='#2ca02c', fontsize=15, fontweight='bold', pad=12)
            self.ax2.set_ylabel('Mbps', color='#2ca02c', fontsize=12, fontweight='bold', labelpad=8)
            self.ax2.set_xlabel('Time (seconds since start)', color='#2ca02c', fontsize=12, fontweight='bold', labelpad=8)
            self.ax2.set_facecolor('#181c20')
            self.ax2.grid(True, alpha=0.25, color='#aaa', linestyle='--')
            self.ax2.tick_params(colors='#2ca02c', labelsize=10)
            if self.bandwidth_history:
                times, mbps = zip(*self.bandwidth_history)
                t0 = min(times)
                rel_times = np.array(times) - t0
                self.ax2.plot(rel_times, mbps, color='#2ca02c', linewidth=2, marker='o', label='Mbps')
                self.ax2.legend()
            else:
                self.ax2.text(0.5, 0.5, 'No bandwidth data', ha='center', va='center', transform=self.ax2.transAxes, color='#2ca02c', fontsize=12)
            # --- ax3: Latency and Jitter ---
            self.ax3.set_title('Latency and Jitter Over Time', color='#d62728', fontsize=15, fontweight='bold', pad=12)
            self.ax3.set_ylabel('Seconds', color='#d62728', fontsize=12, fontweight='bold', labelpad=8)
            self.ax3.set_xlabel('Time (seconds since start)', color='#d62728', fontsize=12, fontweight='bold', labelpad=8)
            self.ax3.set_facecolor('#181c20')
            self.ax3.grid(True, alpha=0.25, color='#aaa', linestyle='--')
            self.ax3.tick_params(colors='#d62728', labelsize=10)
            if self.latency_history:
                t_lat, lat = zip(*self.latency_history)
                t0 = min(t_lat)
                rel_t_lat = np.array(t_lat) - t0
                self.ax3.plot(rel_t_lat, lat, color='#d62728', linewidth=2, marker='o', label='Latency')
            if self.jitter_history:
                t_jit, jit = zip(*self.jitter_history)
                t0 = min(t_jit)
                rel_t_jit = np.array(t_jit) - t0
                self.ax3.plot(rel_t_jit, jit, color='#ff7f0e', linewidth=2, marker='x', label='Jitter')
            if self.latency_history or self.jitter_history:
                self.ax3.legend()
            else:
                self.ax3.text(0.5, 0.5, 'No latency/jitter data', ha='center', va='center', transform=self.ax3.transAxes, color='#d62728', fontsize=12)
            # --- ax4: File size vs. transfer time ---
            self.ax4.set_title('File Size vs. Transfer Time', color='#9467bd', fontsize=15, fontweight='bold', pad=12)
            self.ax4.set_xlabel('Time (seconds since start)', color='#9467bd', fontsize=12, fontweight='bold', labelpad=8)
            self.ax4.set_ylabel('File Size (bytes)', color='#9467bd', fontsize=12, fontweight='bold', labelpad=8)
            self.ax4.set_facecolor('#181c20')
            self.ax4.grid(True, alpha=0.25, color='#aaa', linestyle='--')
            self.ax4.tick_params(colors='#9467bd', labelsize=10)
            if self.transfer_times and self.transfer_sizes:
                times = np.array(self.transfer_times)
                t0 = times.min()
                rel_times = times - t0
                sizes = np.array(self.transfer_sizes)
                self.ax4.scatter(rel_times, sizes, c='#00bfff', edgecolors='k', label='File Transfers', s=80)
                self.ax4.legend()
            else:
                self.ax4.text(0.5, 0.5, 'No file transfer data', ha='center', va='center', transform=self.ax4.transAxes, color='#9467bd', fontsize=12)
            self.fig.tight_layout(pad=2.0)
            # Redraw canvas
            self.canvas.draw()
        except Exception as e:
            self.log(f"[ERROR] Chart update error: {e}")

    def clear_transfer_history(self):
        self.transfer_tree.delete(*self.transfer_tree.get_children())
        self.transfer_history.clear()
        self.stats = {
            'total_transfers': 0,
            'allowed_transfers': 0,
            'denied_transfers': 0,
            'vlan10_transfers': 0,
            'vlan20_transfers': 0
        }

    def export_transfer_history(self):
        fname = f"transfer_history_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(fname, 'w') as f:
            f.write("Transfer History Export\n")
            f.write("=" * 50 + "\n\n")
            for transfer in self.transfer_history:
                f.write(f"Time: {transfer['timestamp']}\n")
                f.write(f"From: {transfer['src']} To: {transfer['dst']}\n")
                f.write(f"Type: {transfer['type']}\n")
                f.write(f"Name: {transfer['name']}\n")
                f.write(f"Size: {transfer['size']}\n")
                f.write(f"Status: {'Allowed' if transfer['allowed'] else 'Denied'}\n")
                f.write("-" * 30 + "\n")
        messagebox.showinfo("Export", f"Transfer history exported to {fname}")

    def clear_logs(self):
        self.logs_text.delete(1.0, tk.END)

    def export_logs(self):
        fname = f"router_logs_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(fname, 'w') as f:
            f.write(self.logs_text.get(1.0, tk.END))
        messagebox.showinfo("Export", f"Logs exported to {fname}")
    
    def clear_chart_data(self):
        """Clear all chart data"""
        self.transfer_times.clear()
        self.transfer_sizes.clear()
        self.permission_decisions.clear()
        self.bandwidth_history.clear()
        self.latency_history.clear()
        self.jitter_history.clear()
        self.packet_loss_history.clear()
        self.update_charts()
        messagebox.showinfo("Charts", "Chart data cleared!")
    
    def export_charts(self):
        """Export charts as image"""
        try:
            fname = f"traffic_analysis_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            self.fig.savefig(fname, dpi=300, bbox_inches='tight', facecolor='#2b2b2b')
            messagebox.showinfo("Export", f"Charts exported to {fname}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export charts: {e}")

    def update_qos_report(self):
        with self.qos_lock:
            if self.qos_latencies:
                avg_latency = sum(self.qos_latencies) / len(self.qos_latencies)
                min_latency = min(self.qos_latencies)
                max_latency = max(self.qos_latencies)
                latency_str = f"avg={avg_latency:.4f}, min={min_latency:.4f}, max={max_latency:.4f}"
            else:
                latency_str = "No data"
            if self.qos_throughputs:
                avg_throughput = sum(self.qos_throughputs) / len(self.qos_throughputs)
                min_throughput = min(self.qos_throughputs)
                max_throughput = max(self.qos_throughputs)
                throughput_str = f"avg={avg_throughput:.2f}, min={min_throughput:.2f}, max={max_throughput:.2f}"
            else:
                throughput_str = "No data"
            if len(self.qos_latencies) > 1:
                jitters = [abs(self.qos_latencies[i] - self.qos_latencies[i-1]) for i in range(1, len(self.qos_latencies))]
                avg_jitter = sum(jitters) / len(jitters)
                jitter_str = f"avg={avg_jitter:.6f}"
            else:
                jitter_str = "Not enough data"
            self.qos_latency_var.set(latency_str)
            self.qos_throughput_var.set(throughput_str)
            self.qos_jitter_var.set(jitter_str)
            self.qos_count_var.set(str(len(self.qos_latencies)))
            # New: Do not update chunk/packet count here, it's per-transfer

    def log(self, msg):
        self.safe_gui_update(lambda: self.logs_text.insert(tk.END, msg + '\n'))
        self.safe_gui_update(lambda: self.logs_text.see(tk.END))
        logging.info(msg)

    def run(self):
        # Start the server automatically when GUI starts
        self.start_server()
        
        # Start GUI update scheduler
        self.schedule_gui_updates()
        
        self.root.mainloop()
    
    def schedule_gui_updates(self):
        """Schedule GUI updates from the main thread"""
        try:
            # Process any pending GUI updates
            while not self.gui_update_queue.empty():
                update_func = self.gui_update_queue.get_nowait()
                update_func()
        except queue.Empty:
            pass
        
        # Schedule next update
        self.root.after(100, self.schedule_gui_updates)
    
    def safe_gui_update(self, update_func):
        """Safely update GUI from any thread"""
        self.gui_update_queue.put(update_func)

if __name__ == "__main__":
    app = EnhancedRouterMonitor()
    app.run() 
