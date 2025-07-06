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

        # Create matplotlib figure for charts
        self.fig, ((self.ax1, self.ax2), (self.ax3, self.ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        self.fig.patch.set_facecolor('#2b2b2b')

        # Transfer volume chart
        self.ax1.set_title('Transfer Volume Over Time', color='white')
        self.ax1.set_ylabel('Transfers', color='white')
        self.ax1.set_facecolor('#1e1e1e')
        self.ax1.grid(True, alpha=0.3)
        self.ax1.tick_params(colors='white')

        # Permission decisions chart
        self.ax2.set_title('Permission Decisions', color='white')
        self.ax2.set_ylabel('Count', color='white')
        self.ax2.set_facecolor('#1e1e1e')
        self.ax2.tick_params(colors='white')

        # Transfer sizes chart
        self.ax3.set_title('Transfer Sizes Distribution', color='white')
        self.ax3.set_ylabel('Size (KB)', color='white')
        self.ax3.set_facecolor('#1e1e1e')
        self.ax3.grid(True, alpha=0.3)
        self.ax3.tick_params(colors='white')

        # Department activity chart
        self.ax4.set_title('Department Activity', color='white')
        self.ax4.set_ylabel('Transfers', color='white')
        self.ax4.set_facecolor('#1e1e1e')
        self.ax4.tick_params(colors='white')

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

        # Store data for charts
        self.transfer_times.append(time.time())
        self.transfer_sizes.append(file_size)
        self.permission_decisions.append(1 if allowed else 0)

        # Update charts immediately
        self.safe_gui_update(self.update_charts)

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

        # Forward file to destination if allowed
        if allowed and dst in self.connections:
            forward_file = {
                'type': 'file_received',
                'sender': src,
                'file_name': file_name,
                'file_size': file_size,
                'file_data': file_data
            }
            try:
                # Send file data in chunks if it's large
                json_data = json.dumps(forward_file)
                data_bytes = json_data.encode('utf-8')
                
                # Send in chunks if necessary
                chunk_size = 8192  # 8KB chunks
                total_sent = 0
                
                while total_sent < len(data_bytes):
                    chunk = data_bytes[total_sent:total_sent + chunk_size]
                    sent = self.connections[dst].send(chunk)
                    if sent == 0:
                        raise Exception("Connection broken")
                    total_sent += sent
                
                # Add a small delay to ensure all data is sent
                time.sleep(0.1)
                
                self.log(f"[FORWARD] File forwarded from {src} to {dst}")
            except Exception as e:
                self.log(f"[ERROR] Failed to forward file to {dst}: {e}")
                # Mark the destination as disconnected
                if dst in self.connections:
                    try:
                        self.connections[dst].close()
                    except:
                        pass
                    del self.connections[dst]
                    self.agent_status[dst]['status'] = 'Disconnected'
                    self.safe_gui_update(lambda v=dst: self.agent_vars[v].set("Disconnected"))

        self.log(f"[TRANSFER] {src} -> {dst} | File: {file_name} | {'ALLOWED' if allowed else 'DENIED'}")

    def handle_message_transfer_request(self, vlan, event):
        src = vlan
        dst = event.get('dst_vlan')
        message = event.get('message', '')
        message_type = event.get('message_type', 'text')
        
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

            # Transfer volume over time
            self.ax1.set_title('Transfer Volume Over Time', color='white')
            self.ax1.set_ylabel('Transfers', color='white')
            self.ax1.set_facecolor('#1e1e1e')
            self.ax1.grid(True, alpha=0.3)
            self.ax1.tick_params(colors='white')
            
            if self.transfer_times:
                # Group transfers by minute
                times = list(self.transfer_times)
                if len(times) > 1:
                    time_bins = np.linspace(min(times), max(times), min(10, len(times)))
                    counts, _ = np.histogram(times, bins=time_bins)
                    self.ax1.plot(time_bins[:-1], counts, 'g-', linewidth=2, marker='o')
                else:
                    # Single transfer
                    self.ax1.bar([0], [1], color='green', alpha=0.7)
            else:
                # No data yet
                self.ax1.text(0.5, 0.5, 'No transfers yet', ha='center', va='center', 
                             transform=self.ax1.transAxes, color='white', fontsize=12)

            # Permission decisions
            self.ax2.set_title('Permission Decisions', color='white')
            self.ax2.set_ylabel('Count', color='white')
            self.ax2.set_facecolor('#1e1e1e')
            self.ax2.tick_params(colors='white')
            
            if self.permission_decisions:
                allowed = sum(self.permission_decisions)
                denied = len(self.permission_decisions) - allowed
                self.ax2.bar(['Allowed', 'Denied'], [allowed, denied], color=['green', 'red'])
            else:
                # No data yet
                self.ax2.text(0.5, 0.5, 'No decisions yet', ha='center', va='center', 
                             transform=self.ax2.transAxes, color='white', fontsize=12)

            # Transfer sizes
            self.ax3.set_title('Transfer Sizes Distribution', color='white')
            self.ax3.set_ylabel('Size (bytes)', color='white')
            self.ax3.set_facecolor('#1e1e1e')
            self.ax3.grid(True, alpha=0.3)
            self.ax3.tick_params(colors='white')
            
            if self.transfer_sizes:
                sizes = list(self.transfer_sizes)
                self.ax3.hist(sizes, bins=min(10, len(sizes)), color='blue', alpha=0.7)
            else:
                # No data yet
                self.ax3.text(0.5, 0.5, 'No transfers yet', ha='center', va='center', 
                             transform=self.ax3.transAxes, color='white', fontsize=12)

            # Department activity
            self.ax4.set_title('Department Activity', color='white')
            self.ax4.set_ylabel('Transfers', color='white')
            self.ax4.set_facecolor('#1e1e1e')
            self.ax4.tick_params(colors='white')
            
            self.ax4.bar(['HR (VLAN10)', 'Finance (VLAN20)'], 
                        [self.stats['vlan10_transfers'], self.stats['vlan20_transfers']], 
                        color=['orange', 'purple'])

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