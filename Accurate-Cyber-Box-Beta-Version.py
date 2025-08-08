import sys
import socket
import threading
import time
from datetime import datetime
import json
import os
import subprocess
import platform
import requests
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP, UDP
import dpkt
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QLabel, QLineEdit, QPushButton, QTextEdit, QTabWidget, 
                            QTableWidget, QTableWidgetItem, QMenuBar, QMenu, QAction,
                            QStatusBar, QToolBar, QSystemTrayIcon, QMessageBox, QComboBox)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QIcon, QFont, QColor, QPalette

class CyberDrillTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Accurate Cyber Box Beta Version")
        self.setGeometry(100, 100, 1200, 800)
        
        # Configure theme
        self.set_theme()
        
        # Initialize core components
        self.monitored_ips = []
        self.attack_history = []
        self.command_history = []
        self.config = self.load_config()
        
        # Setup UI
        self.init_ui()
        
        # Start background monitoring thread
        self.monitoring_active = False
        self.monitoring_thread = None
        
    def set_theme(self):
        """Configure the green/black theme"""
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(0, 20, 10))
        palette.setColor(QPalette.WindowText, Qt.green)
        palette.setColor(QPalette.Base, QColor(0, 10, 5))
        palette.setColor(QPalette.AlternateBase, QColor(0, 30, 15))
        palette.setColor(QPalette.ToolTipBase, Qt.black)
        palette.setColor(QPalette.ToolTipText, Qt.green)
        palette.setColor(QPalette.Text, Qt.green)
        palette.setColor(QPalette.Button, QColor(0, 40, 20))
        palette.setColor(QPalette.ButtonText, Qt.green)
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Highlight, QColor(0, 100, 50))
        palette.setColor(QPalette.HighlightedText, Qt.black)
        
        self.setPalette(palette)
        
        # Custom font
        font = QFont("Consolas", 10)
        QApplication.setFont(font)
        
    def init_ui(self):
        """Initialize the user interface"""
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QHBoxLayout()
        central_widget.setLayout(main_layout)
        
        # Left panel (command interface)
        left_panel = QVBoxLayout()
        main_layout.addLayout(left_panel, 30)
        
        # Command input
        self.cmd_input = QLineEdit()
        self.cmd_input.setPlaceholderText("Enter command (type 'help' for options)")
        self.cmd_input.returnPressed.connect(self.execute_command)
        left_panel.addWidget(self.cmd_input)
        
        # Command output
        self.cmd_output = QTextEdit()
        self.cmd_output.setReadOnly(True)
        left_panel.addWidget(self.cmd_output)
        
        # Right panel (dashboard)
        right_panel = QVBoxLayout()
        main_layout.addLayout(right_panel, 70)
        
        # Create tabs
        self.tabs = QTabWidget()
        right_panel.addWidget(self.tabs)
        
        # Dashboard tab
        self.dashboard_tab = QWidget()
        self.tabs.addTab(self.dashboard_tab, "Dashboard")
        self.init_dashboard()
        
        # Monitoring tab
        self.monitoring_tab = QWidget()
        self.tabs.addTab(self.monitoring_tab, "Monitoring")
        self.init_monitoring_tab()
        
        # Attacks tab
        self.attacks_tab = QWidget()
        self.tabs.addTab(self.attacks_tab, "Attack History")
        self.init_attacks_tab()
        
        # Forensic tab
        self.forensic_tab = QWidget()
        self.tabs.addTab(self.forensic_tab, "Forensic Tools")
        self.init_forensic_tab()
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Create toolbar
        self.create_toolbar()
        
        # System tray icon
        self.create_system_tray()
        
    def init_dashboard(self):
        """Initialize dashboard tab"""
        layout = QVBoxLayout()
        self.dashboard_tab.setLayout(layout)
        
        # Stats overview
        stats_group = QHBoxLayout()
        layout.addLayout(stats_group)
        
        # Add stats widgets
        self.ip_count_label = QLabel("Monitored IPs: 0")
        stats_group.addWidget(self.ip_count_label)
        
        self.attack_count_label = QLabel("Detected Attacks: 0")
        stats_group.addWidget(self.attack_count_label)
        
        self.threat_level_label = QLabel("Threat Level: Low")
        stats_group.addWidget(self.threat_level_label)
        
        # Network graph
        self.figure = plt.figure(facecolor='#001405')
        self.canvas = FigureCanvas(self.figure)
        layout.addWidget(self.canvas)
        
        # Update dashboard
        self.update_dashboard()
        
    def init_monitoring_tab(self):
        """Initialize monitoring tab"""
        layout = QVBoxLayout()
        self.monitoring_tab.setLayout(layout)
        
        # IP list
        self.ip_table = QTableWidget()
        self.ip_table.setColumnCount(4)
        self.ip_table.setHorizontalHeaderLabels(["IP Address", "Status", "Last Seen", "Threats"])
        layout.addWidget(self.ip_table)
        
        # Monitoring controls
        control_layout = QHBoxLayout()
        layout.addLayout(control_layout)
        
        self.start_monitoring_btn = QPushButton("Start Monitoring")
        self.start_monitoring_btn.clicked.connect(self.start_monitoring)
        control_layout.addWidget(self.start_monitoring_btn)
        
        self.stop_monitoring_btn = QPushButton("Stop Monitoring")
        self.stop_monitoring_btn.clicked.connect(self.stop_monitoring)
        control_layout.addWidget(self.stop_monitoring_btn)
        
        # Update monitoring list
        self.update_monitoring_list()
        
    def init_attacks_tab(self):
        """Initialize attack history tab"""
        layout = QVBoxLayout()
        self.attacks_tab.setLayout(layout)
        
        self.attack_table = QTableWidget()
        self.attack_table.setColumnCount(5)
        self.attack_table.setHorizontalHeaderLabels(["Timestamp", "IP Address", "Attack Type", "Severity", "Details"])
        layout.addWidget(self.attack_table)
        
        # Update attack list
        self.update_attack_list()
        
    def init_forensic_tab(self):
        """Initialize forensic tools tab"""
        layout = QVBoxLayout()
        self.forensic_tab.setLayout(layout)
        
        # Forensic tools
        forensic_tools = QHBoxLayout()
        layout.addLayout(forensic_tools)
        
        self.pcap_analyzer_btn = QPushButton("PCAP Analyzer")
        self.pcap_analyzer_btn.clicked.connect(self.open_pcap_analyzer)
        forensic_tools.addWidget(self.pcap_analyzer_btn)
        
        self.memory_analyzer_btn = QPushButton("Memory Analyzer")
        self.memory_analyzer_btn.clicked.connect(self.open_memory_analyzer)
        forensic_tools.addWidget(self.memory_analyzer_btn)
        
        # Results area
        self.forensic_output = QTextEdit()
        self.forensic_output.setReadOnly(True)
        layout.addWidget(self.forensic_output)
        
    def create_menu_bar(self):
        """Create the menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        new_action = QAction("New Session", self)
        file_menu.addAction(new_action)
        
        load_action = QAction("Load Config", self)
        file_menu.addAction(load_action)
        
        save_action = QAction("Save Config", self)
        file_menu.addAction(save_action)
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("Tools")
        
        ping_action = QAction("Ping Tool", self)
        tools_menu.addAction(ping_action)
        
        traceroute_action = QAction("Traceroute Tool", self)
        tools_menu.addAction(traceroute_action)
        
        portscan_action = QAction("Port Scanner", self)
        tools_menu.addAction(portscan_action)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        about_action = QAction("About", self)
        help_menu.addAction(about_action)
        
        docs_action = QAction("Documentation", self)
        help_menu.addAction(docs_action)
        
    def create_toolbar(self):
        """Create the toolbar"""
        toolbar = QToolBar("Main Toolbar")
        self.addToolBar(toolbar)
        
        # Add toolbar actions
        start_monitor_action = QAction(QIcon("icons/start.png"), "Start Monitoring", self)
        start_monitor_action.triggered.connect(self.start_monitoring)
        toolbar.addAction(start_monitor_action)
        
        stop_monitor_action = QAction(QIcon("icons/stop.png"), "Stop Monitoring", self)
        stop_monitor_action.triggered.connect(self.stop_monitoring)
        toolbar.addAction(stop_monitor_action)
        
        toolbar.addSeparator()
        
        ping_action = QAction(QIcon("icons/ping.png"), "Ping", self)
        ping_action.triggered.connect(self.show_ping_dialog)
        toolbar.addAction(ping_action)
        
        scan_action = QAction(QIcon("icons/scan.png"), "Scan", self)
        scan_action.triggered.connect(self.show_scan_dialog)
        toolbar.addAction(scan_action)
        
    def create_system_tray(self):
        """Create system tray icon"""
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
            
        tray_icon = QSystemTrayIcon(self)
        tray_icon.setIcon(QIcon("icons/cyberdrill.png"))
        
        tray_menu = QMenu()
        
        show_action = QAction("Show", self)
        show_action.triggered.connect(self.show)
        tray_menu.addAction(show_action)
        
        hide_action = QAction("Hide", self)
        hide_action.triggered.connect(self.hide)
        tray_menu.addAction(hide_action)
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        tray_menu.addAction(exit_action)
        
        tray_icon.setContextMenu(tray_menu)
        tray_icon.show()
        
    def execute_command(self):
        """Execute command from input"""
        cmd = self.cmd_input.text().strip()
        self.command_history.append(cmd)
        self.cmd_input.clear()
        
        self.cmd_output.append(f"> {cmd}")
        
        # Process command
        parts = cmd.split()
        if not parts:
            return
            
        command = parts[0].lower()
        args = parts[1:]
        
        if command == "help":
            self.show_help()
        elif command == "ping":
            self.ping_ip(args[0] if args else "")
        elif command == "scan":
            self.scan_ip(args[0] if args else "")
        elif command == "start":
            if "monitoring" in cmd.lower():
                self.start_monitoring()
            else:
                self.cmd_output.append("Unknown command. Type 'help' for options.")
        elif command == "stop":
            self.stop_monitoring()
        elif command == "add":
            if args and args[0] == "ip":
                self.add_ip(args[1] if len(args) > 1 else "")
        elif command == "remove":
            if args and args[0] == "ip":
                self.remove_ip(args[1] if len(args) > 1 else "")
        elif command == "view":
            self.view_data()
        elif command == "clear":
            self.cmd_output.clear()
        elif command == "history":
            self.show_command_history()
        elif command == "traceroute":
            self.traceroute_ip(args[0] if args else "")
        elif command == "udptraceroute":
            self.udp_traceroute_ip(args[0] if args else "")
        elif command == "tcptraceroute":
            self.tcp_traceroute_ip(args[0] if args else "")
        elif command == "config":
            if len(args) >= 3 and args[0] == "telegram" and args[1] == "token":
                self.config_telegram_token(" ".join(args[2:]))
            elif len(args) >= 3 and args[0] == "telegram" and args[1] == "chat_id":
                self.config_telegram_chat_id(" ".join(args[2:]))
        elif command == "test" and args and args[0] == "telegram":
            self.test_telegram()
        elif command == "exit":
            self.close()
        else:
            self.cmd_output.append("Unknown command. Type 'help' for options.")
    
    def show_help(self):
        """Display help information"""
        help_text = """
CyberDrill Advanced Security Tool - Command Reference:

Basic Commands:
  help                     - Show this help message
  clear                    - Clear the command output
  exit                     - Exit the application
  history                  - Show command history

IP Management:
  add ip <IP>              - Add an IP to monitor
  remove ip <IP>           - Remove an IP from monitoring
  view                     - View monitored IPs and attack history

Network Tools:
  ping <IP>                - Ping an IP address
  scan <IP>                - Scan an IP address for open ports
  traceroute <IP>          - Perform ICMP traceroute
  udptraceroute <IP>       - Perform UDP traceroute
  tcptraceroute <IP>       - Perform TCP traceroute

Monitoring:
  start monitoring <IP>    - Start monitoring an IP
  stop monitoring          - Stop all monitoring

Telegram Integration:
  config telegram token <TOKEN> - Set Telegram bot token
  config telegram chat_id <ID>  - Set Telegram chat ID
  test telegram            - Test Telegram notifications
"""
        self.cmd_output.append(help_text)
    
    def ping_ip(self, ip):
        """Ping an IP address"""
        if not self.validate_ip(ip):
            self.cmd_output.append(f"Invalid IP address: {ip}")
            return
            
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '4', ip]
            output = subprocess.check_output(command).decode('utf-8')
            self.cmd_output.append(output)
        except subprocess.CalledProcessError as e:
            self.cmd_output.append(f"Ping failed: {e}")
    
    def scan_ip(self, ip):
        """Scan an IP address for open ports"""
        if not self.validate_ip(ip):
            self.cmd_output.append(f"Invalid IP address: {ip}")
            return
            
        self.cmd_output.append(f"Scanning {ip}...")
        
        # Common ports to scan
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389]
        
        try:
            open_ports = []
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
                
            if open_ports:
                self.cmd_output.append(f"Open ports on {ip}: {', '.join(map(str, open_ports))}")
            else:
                self.cmd_output.append(f"No open ports found on {ip} (scanned common ports)")
        except Exception as e:
            self.cmd_output.append(f"Scan failed: {e}")
    
    def start_monitoring(self):
        """Start monitoring all added IPs"""
        if not self.monitored_ips:
            self.cmd_output.append("No IPs to monitor. Add IPs first with 'add ip <IP>'")
            return
            
        if self.monitoring_active:
            self.cmd_output.append("Monitoring is already active")
            return
            
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=self.monitor_ips, daemon=True)
        self.monitoring_thread.start()
        self.cmd_output.append(f"Started monitoring {len(self.monitored_ips)} IP(s)")
        
    def stop_monitoring(self):
        """Stop monitoring"""
        if not self.monitoring_active:
            self.cmd_output.append("Monitoring is not active")
            return
            
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join()
        self.cmd_output.append("Monitoring stopped")
    
    def monitor_ips(self):
        """Background thread for monitoring IPs"""
        while self.monitoring_active:
            for ip in self.monitored_ips:
                self.check_ip(ip)
            time.sleep(10)  # Check every 10 seconds
    
    def check_ip(self, ip):
        """Check an IP for potential threats"""
        try:
            # Check for ping of death
            if self.detect_ping_of_death(ip):
                self.log_attack(ip, "Ping of Death", "High")
                
            # Check for port scanning
            if self.detect_port_scan(ip):
                self.log_attack(ip, "Port Scanning", "Medium")
                
            # Check for UDP flood
            if self.detect_udp_flood(ip):
                self.log_attack(ip, "UDP Flood", "High")
                
            # Check for HTTPS flood
            if self.detect_https_flood(ip):
                self.log_attack(ip, "HTTPS Flood", "High")
                
            # Update dashboard
            self.update_dashboard()
            self.update_monitoring_list()
            self.update_attack_list()
            
        except Exception as e:
            self.cmd_output.append(f"Error monitoring {ip}: {e}")
    
    def detect_ping_of_death(self, ip):
        """Detect ping of death attack"""
        # Simulated detection - in real implementation would analyze actual traffic
        return random.random() < 0.01  # 1% chance for demo
    
    def detect_port_scan(self, ip):
        """Detect port scanning activity"""
        # Simulated detection
        return random.random() < 0.02  # 2% chance for demo
    
    def detect_udp_flood(self, ip):
        """Detect UDP flood attack"""
        # Simulated detection
        return random.random() < 0.01  # 1% chance for demo
    
    def detect_https_flood(self, ip):
        """Detect HTTPS flood attack"""
        # Simulated detection
        return random.random() < 0.015  # 1.5% chance for demo
    
    def log_attack(self, ip, attack_type, severity):
        """Log a detected attack"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        attack = {
            "timestamp": timestamp,
            "ip": ip,
            "type": attack_type,
            "severity": severity,
            "details": f"{attack_type} detected from {ip}"
        }
        self.attack_history.append(attack)
        
        # Send Telegram notification if configured
        if "telegram_token" in self.config and "telegram_chat_id" in self.config:
            self.send_telegram_notification(attack)
    
    def send_telegram_notification(self, attack):
        """Send attack notification via Telegram"""
        message = (f"🚨 CyberDrill Alert 🚨\n"
                  f"Type: {attack['type']}\n"
                  f"IP: {attack['ip']}\n"
                  f"Severity: {attack['severity']}\n"
                  f"Time: {attack['timestamp']}")
                  
        try:
            url = f"https://api.telegram.org/bot{self.config['telegram_token']}/sendMessage"
            params = {
                "chat_id": self.config["telegram_chat_id"],
                "text": message
            }
            requests.post(url, params=params)
        except Exception as e:
            self.cmd_output.append(f"Failed to send Telegram notification: {e}")
    
    def add_ip(self, ip):
        """Add an IP to monitor"""
        if not self.validate_ip(ip):
            self.cmd_output.append(f"Invalid IP address: {ip}")
            return
            
        if ip in self.monitored_ips:
            self.cmd_output.append(f"IP {ip} is already being monitored")
            return
            
        self.monitored_ips.append(ip)
        self.cmd_output.append(f"Added {ip} to monitoring list")
        self.update_monitoring_list()
    
    def remove_ip(self, ip):
        """Remove an IP from monitoring"""
        if ip in self.monitored_ips:
            self.monitored_ips.remove(ip)
            self.cmd_output.append(f"Removed {ip} from monitoring list")
            self.update_monitoring_list()
        else:
            self.cmd_output.append(f"IP {ip} is not in monitoring list")
    
    def view_data(self):
        """View monitoring data"""
        self.cmd_output.append("\nMonitored IPs:")
        for ip in self.monitored_ips:
            self.cmd_output.append(f" - {ip}")
            
        self.cmd_output.append("\nRecent Attacks:")
        for attack in self.attack_history[-5:]:  # Show last 5 attacks
            self.cmd_output.append(f" - {attack['timestamp']} {attack['ip']}: {attack['type']} ({attack['severity']})")
    
    def show_command_history(self):
        """Show command history"""
        self.cmd_output.append("\nCommand History:")
        for i, cmd in enumerate(self.command_history[-10:], 1):  # Show last 10 commands
            self.cmd_output.append(f"{i}. {cmd}")
    
    def traceroute_ip(self, ip):
        """Perform ICMP traceroute to an IP"""
        if not self.validate_ip(ip):
            self.cmd_output.append(f"Invalid IP address: {ip}")
            return
            
        self.cmd_output.append(f"Traceroute to {ip} (ICMP)...")
        
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(["tracert", ip], capture_output=True, text=True)
            else:
                result = subprocess.run(["traceroute", ip], capture_output=True, text=True)
                
            self.cmd_output.append(result.stdout)
        except Exception as e:
            self.cmd_output.append(f"Traceroute failed: {e}")
    
    def udp_traceroute_ip(self, ip):
        """Perform UDP traceroute to an IP"""
        if not self.validate_ip(ip):
            self.cmd_output.append(f"Invalid IP address: {ip}")
            return
            
        self.cmd_output.append(f"Traceroute to {ip} (UDP)...")
        
        try:
            if platform.system().lower() == "windows":
                self.cmd_output.append("UDP traceroute not natively supported on Windows")
            else:
                result = subprocess.run(["traceroute", "-U", ip], capture_output=True, text=True)
                self.cmd_output.append(result.stdout)
        except Exception as e:
            self.cmd_output.append(f"UDP traceroute failed: {e}")
    
    def tcp_traceroute_ip(self, ip):
        """Perform TCP traceroute to an IP"""
        if not self.validate_ip(ip):
            self.cmd_output.append(f"Invalid IP address: {ip}")
            return
            
        self.cmd_output.append(f"Traceroute to {ip} (TCP)...")
        
        try:
            if platform.system().lower() == "windows":
                self.cmd_output.append("TCP traceroute not natively supported on Windows")
            else:
                result = subprocess.run(["traceroute", "-T", ip], capture_output=True, text=True)
                self.cmd_output.append(result.stdout)
        except Exception as e:
            self.cmd_output.append(f"TCP traceroute failed: {e}")
    
    def config_telegram_token(self, token):
        """Configure Telegram bot token"""
        self.config["telegram_token"] = token
        self.save_config()
        self.cmd_output.append("Telegram token configured")
    
    def config_telegram_chat_id(self, chat_id):
        """Configure Telegram chat ID"""
        self.config["telegram_chat_id"] = chat_id
        self.save_config()
        self.cmd_output.append("Telegram chat ID configured")
    
    def test_telegram(self):
        """Test Telegram notification"""
        if "telegram_token" not in self.config or "telegram_chat_id" not in self.config:
            self.cmd_output.append("Telegram not configured. Set token and chat ID first.")
            return
            
        test_attack = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": "192.168.1.1",
            "type": "Test Notification",
            "severity": "Low",
            "details": "This is a test notification from CyberDrill"
        }
        
        self.send_telegram_notification(test_attack)
        self.cmd_output.append("Sent test Telegram notification")
    
    def validate_ip(self, ip):
        """Validate an IP address"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    def load_config(self):
        """Load configuration from file"""
        config_path = "cyberdrill_config.json"
        if os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    return json.load(f)
            except Exception as e:
                self.cmd_output.append(f"Error loading config: {e}")
        return {}
    
    def save_config(self):
        """Save configuration to file"""
        config_path = "cyberdrill_config.json"
        try:
            with open(config_path, "w") as f:
                json.dump(self.config, f)
        except Exception as e:
            self.cmd_output.append(f"Error saving config: {e}")
    
    def update_dashboard(self):
        """Update dashboard display"""
        self.ip_count_label.setText(f"Monitored IPs: {len(self.monitored_ips)}")
        self.attack_count_label.setText(f"Detected Attacks: {len(self.attack_history)}")
        
        # Update threat level
        if len(self.attack_history) > 10:
            self.threat_level_label.setText("Threat Level: Critical")
        elif len(self.attack_history) > 5:
            self.threat_level_label.setText("Threat Level: High")
        elif len(self.attack_history) > 2:
            self.threat_level_label.setText("Threat Level: Medium")
        else:
            self.threat_level_label.setText("Threat Level: Low")
        
        # Update network graph
        self.update_network_graph()
    
    def update_network_graph(self):
        """Update the network activity graph"""
        self.figure.clear()
        ax = self.figure.add_subplot(111)
        
        # Sample data for demo
        ips = self.monitored_ips[:5] or ["192.168.1.1", "10.0.0.1", "172.16.0.1"]
        activity = [random.randint(1, 100) for _ in ips]
        colors = ['#00ff00', '#00cc00', '#009900', '#006600', '#003300']
        
        ax.bar(ips, activity, color=colors)
        ax.set_title('Network Activity', color='#00ff00')
        ax.set_ylabel('Activity Level', color='#00ff00')
        ax.tick_params(axis='x', colors='#00ff00')
        ax.tick_params(axis='y', colors='#00ff00')
        
        # Set background color
        ax.set_facecolor('#000a05')
        self.figure.patch.set_facecolor('#001405')
        
        self.canvas.draw()
    
    def update_monitoring_list(self):
        """Update the monitoring IP table"""
        self.ip_table.setRowCount(len(self.monitored_ips))
        
        for row, ip in enumerate(self.monitored_ips):
            self.ip_table.setItem(row, 0, QTableWidgetItem(ip))
            self.ip_table.setItem(row, 1, QTableWidgetItem("Active"))
            self.ip_table.setItem(row, 2, QTableWidgetItem(datetime.now().strftime("%H:%M:%S")))
            
            # Count attacks for this IP
            attack_count = sum(1 for attack in self.attack_history if attack["ip"] == ip)
            self.ip_table.setItem(row, 3, QTableWidgetItem(str(attack_count)))
    
    def update_attack_list(self):
        """Update the attack history table"""
        self.attack_table.setRowCount(len(self.attack_history))
        
        for row, attack in enumerate(self.attack_history):
            self.attack_table.setItem(row, 0, QTableWidgetItem(attack["timestamp"]))
            self.attack_table.setItem(row, 1, QTableWidgetItem(attack["ip"]))
            self.attack_table.setItem(row, 2, QTableWidgetItem(attack["type"]))
            self.attack_table.setItem(row, 3, QTableWidgetItem(attack["severity"]))
            self.attack_table.setItem(row, 4, QTableWidgetItem(attack["details"]))
    
    def open_pcap_analyzer(self):
        """Open PCAP file analyzer"""
        self.forensic_output.append("PCAP Analyzer: Not implemented in this demo")
    
    def open_memory_analyzer(self):
        """Open memory analyzer"""
        self.forensic_output.append("Memory Analyzer: Not implemented in this demo")
    
    def show_ping_dialog(self):
        """Show ping dialog"""
        self.cmd_input.setText("ping ")
        self.cmd_input.setFocus()
    
    def show_scan_dialog(self):
        """Show scan dialog"""
        self.cmd_input.setText("scan ")
        self.cmd_input.setFocus()
    
    def closeEvent(self, event):
        """Handle application close"""
        if self.monitoring_active:
            reply = QMessageBox.question(
                self, 'Confirm Exit',
                'Monitoring is active. Are you sure you want to exit?',
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                
            if reply == QMessageBox.No:
                event.ignore()
                return
                
        self.stop_monitoring()
        event.accept()

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    # Set application icon
    if os.path.exists("icons/cyberdrill.png"):
        app.setWindowIcon(QIcon("icons/cyberdrill.png"))
    
    window = CyberDrillTool()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()