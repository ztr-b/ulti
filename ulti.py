import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
import subprocess
import os
import webbrowser
import asyncio
import threading
import json
from PIL import Image, ImageTk
import requests
import platform
import socket

class PentestPro:
    def __init__(self, master):
        self.master = master
        self.master.title("PENTEST PRO v3.0")
        self.master.geometry("1200x800")
        
        # Initialize core components
        self.set_theme()
        self.create_menu()
        self.setup_toolbar()
        self.setup_main_interface()
        self.setup_status_bar()
        self.create_side_panel()
        self.setup_console()
        
        # Initialize managers
        self.session_manager = SessionManager()
        self.plugin_manager = PluginManager(self)
        
        # Load default settings
        self.load_settings()

    # ---------------------------
    # Core GUI Setup
    # ---------------------------
    def set_theme(self, theme_name='dark'):
        """Set light or dark theme"""
        self.style = ttk.Style()
        
        if theme_name == 'dark':
            bg = '#2d2d2d'
            fg = '#ffffff'
            highlight = '#347083'
        else:
            bg = '#ffffff'
            fg = '#000000'
            highlight = '#4a90d9'
            
        self.style.configure('.', background=bg, foreground=fg)
        self.style.configure('TNotebook', background=bg)
        self.style.configure('TNotebook.Tab', background=bg, foreground=fg)
        self.style.map('TNotebook.Tab', background=[('selected', highlight)])
        self.style.configure('TFrame', background=bg)
        self.style.configure('TButton', background=highlight, foreground=fg)
        self.style.map('TButton', background=[('active', highlight)])
        
    def create_menu(self):
        """Create the main menu bar"""
        menubar = tk.Menu(self.master)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Project", command=self.new_project)
        file_menu.add_command(label="Open Session", command=self.load_session)
        file_menu.add_command(label="Save Session", command=self.save_session)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.master.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Tool Manager", command=self.show_tool_manager)
        tools_menu.add_command(label="Plugin Center", command=self.open_plugin_center)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Dark Theme", command=lambda: self.set_theme('dark'))
        view_menu.add_command(label="Light Theme", command=lambda: self.set_theme('light'))
        view_menu.add_separator()
        view_menu.add_command(label="Reset Layout", command=self.reset_layout)
        menubar.add_cascade(label="View", menu=view_menu)
        
        self.master.config(menu=menubar)
    
    def setup_toolbar(self):
        """Create the toolbar with quick actions"""
        toolbar = ttk.Frame(self.master)
        
        # Toolbar buttons
        icons = {
            'scan': self.load_icon('scan.png'),
            'report': self.load_icon('report.png'),
            'metasploit': self.load_icon('metasploit.png'),
            'burp': self.load_icon('burp.png'),
            'chat': self.load_icon('chat.png')
        }
        
        ttk.Button(toolbar, image=icons['scan'], command=self.quick_scan).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, image=icons['report'], command=self.generate_report).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, image=icons['metasploit'], command=self.toggle_metasploit).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, image=icons['burp'], command=self.toggle_burp).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, image=icons['chat'], command=self.toggle_chat).pack(side=tk.LEFT, padx=2)
        
        toolbar.pack(side=tk.TOP, fill=tk.X)
    
    def setup_main_interface(self):
        """Setup the main notebook interface"""
        self.notebook = ttk.Notebook(self.master)
        
        # Create tabs
        self.android_tab = self.create_android_tab()
        self.ios_tab = self.create_ios_tab()
        self.network_tab = self.create_network_tab()
        self.web_tab = self.create_web_tab()
        self.forensics_tab = self.create_forensics_tab()
        self.password_tab = self.create_password_tab()
        self.automation_tab = self.create_automation_tab()
        
        # Add tabs to notebook
        self.notebook.add(self.android_tab, text="Android")
        self.notebook.add(self.ios_tab, text="iOS")
        self.notebook.add(self.network_tab, text="Network")
        self.notebook.add(self.web_tab, text="Web")
        self.notebook.add(self.forensics_tab, text="Forensics")
        self.notebook.add(self.password_tab, text="Password")
        self.notebook.add(self.automation_tab, text="Automation")
        
        self.notebook.pack(expand=True, fill=tk.BOTH)
    
    def create_side_panel(self):
        """Create the right-side panel"""
        self.side_panel = ttk.PanedWindow(self.master, orient=tk.VERTICAL)
        
        # Target manager
        self.target_tree = ttk.Treeview(self.side_panel)
        self.target_tree['columns'] = ('OS', 'Status')
        self.target_tree.heading('#0', text='Target')
        self.target_tree.heading('OS', text='OS')
        self.target_tree.heading('Status', text='Status')
        
        # Vulnerability list
        self.vuln_tree = ttk.Treeview(self.side_panel)
        self.vuln_tree['columns'] = ('Severity', 'Product')
        self.vuln_tree.heading('#0', text='CVE ID')
        self.vuln_tree.heading('Severity', text='Severity')
        self.vuln_tree.heading('Product', text='Product')
        
        # Mini chat
        self.mini_chat = tk.Text(self.side_panel, height=10)
        self.mini_chat_entry = ttk.Entry(self.side_panel)
        self.mini_chat_entry.bind('<Return>', self.send_chat_message)
        
        # Add components to side panel
        self.side_panel.add(self.target_tree)
        self.side_panel.add(self.vuln_tree)
        self.side_panel.add(self.mini_chat)
        self.side_panel.add(self.mini_chat_entry)
        
        self.side_panel.pack(side=tk.RIGHT, fill=tk.Y)
    
    def setup_console(self):
        """Setup the console output area"""
        console_frame = ttk.Frame(self.master)
        
        self.console = scrolledtext.ScrolledText(console_frame, height=10)
        self.console.pack(expand=True, fill=tk.BOTH)
        
        # Console tags for coloring
        self.console.tag_config('error', foreground='red')
        self.console.tag_config('warning', foreground='orange')
        self.console.tag_config('success', foreground='green')
        self.console.tag_config('info', foreground='blue')
        
        console_frame.pack(side=tk.BOTTOM, fill=tk.BOTH)
    
    def setup_status_bar(self):
        """Create the status bar"""
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        
        self.cpu_var = tk.StringVar()
        self.cpu_var.set("CPU: 0%")
        
        self.mem_var = tk.StringVar()
        self.mem_var.set("Mem: 0MB/0MB")
        
        self.net_var = tk.StringVar()
        self.net_var.set("Net: 0Kbps")
        
        status_bar = ttk.Frame(self.master)
        
        ttk.Label(status_bar, textvariable=self.status_var).pack(side=tk.LEFT, padx=5)
        ttk.Label(status_bar, textvariable=self.cpu_var).pack(side=tk.LEFT, padx=5)
        ttk.Label(status_bar, textvariable=self.mem_var).pack(side=tk.LEFT, padx=5)
        ttk.Label(status_bar, textvariable=self.net_var).pack(side=tk.LEFT, padx=5)
        
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Start status updater
        self.update_status_indicators()
    
    # ---------------------------
    # Tab Creation Methods
    # ---------------------------
    def create_android_tab(self):
        """Create Android pentesting tab"""
        frame = ttk.Frame(self.notebook)
        
        # APK Analysis section
        apk_frame = ttk.LabelFrame(frame, text="APK Analysis")
        ttk.Button(apk_frame, text="Analyze APK", command=self.analyze_apk).pack(pady=5)
        ttk.Button(apk_frame, text="Decompile APK", command=self.decompile_apk).pack(pady=5)
        ttk.Button(apk_frame, text="Run MobSF", command=self.run_mobsf).pack(pady=5)
        apk_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # ADB Tools section
        adb_frame = ttk.LabelFrame(frame, text="ADB Tools")
        ttk.Button(adb_frame, text="List Devices", command=self.list_adb_devices).pack(pady=5)
        ttk.Button(adb_frame, text="Shell", command=self.adb_shell).pack(pady=5)
        ttk.Button(adb_frame, text="Install APK", command=self.install_apk).pack(pady=5)
        adb_frame.pack(fill=tk.X, padx=5, pady=5)
        
        return frame
    
    def create_ios_tab(self):
        """Create iOS pentesting tab"""
        frame = ttk.Frame(self.notebook)
        
        # IPA Analysis section
        ipa_frame = ttk.LabelFrame(frame, text="IPA Analysis")
        ttk.Button(ipa_frame, text="Analyze IPA", command=self.analyze_ipa).pack(pady=5)
        ttk.Button(ipa_frame, text="Extract Info", command=self.extract_ipa_info).pack(pady=5)
        ipa_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Jailbreak Tools section
        jb_frame = ttk.LabelFrame(frame, text="Jailbreak Tools")
        ttk.Button(jb_frame, text="Checkra1n", command=self.run_checkra1n).pack(pady=5)
        ttk.Button(jb_frame, text="Objection", command=self.run_objection).pack(pady=5)
        jb_frame.pack(fill=tk.X, padx=5, pady=5)
        
        return frame
    
    def create_network_tab(self):
        """Create network pentesting tab"""
        frame = ttk.Frame(self.notebook)
        
        # Scanning section
        scan_frame = ttk.LabelFrame(frame, text="Scanning")
        ttk.Button(scan_frame, text="Quick Scan", command=self.quick_scan).pack(pady=5)
        ttk.Button(scan_frame, text="Full Scan", command=self.full_scan).pack(pady=5)
        scan_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Exploitation section
        exploit_frame = ttk.LabelFrame(frame, text="Exploitation")
        ttk.Button(exploit_frame, text="Metasploit", command=self.run_metasploit).pack(pady=5)
        ttk.Button(exploit_frame, text="CrackMapExec", command=self.run_crackmapexec).pack(pady=5)
        exploit_frame.pack(fill=tk.X, padx=5, pady=5)
        
        return frame
    
    def create_web_tab(self):
        """Create web pentesting tab"""
        frame = ttk.Frame(self.notebook)
        
        # Scanning section
        scan_frame = ttk.LabelFrame(frame, text="Web Scanning")
        ttk.Button(scan_frame, text="Nikto", command=self.run_nikto).pack(pady=5)
        ttk.Button(scan_frame, text="OWASP ZAP", command=self.run_owasp_zap).pack(pady=5)
        scan_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Exploitation section
        exploit_frame = ttk.LabelFrame(frame, text="Web Exploitation")
        ttk.Button(exploit_frame, text="SQLmap", command=self.run_sqlmap).pack(pady=5)
        ttk.Button(exploit_frame, text="XSStrike", command=self.run_xsstrike).pack(pady=5)
        exploit_frame.pack(fill=tk.X, padx=5, pady=5)
        
        return frame
    
    def create_forensics_tab(self):
        """Create forensics tab"""
        frame = ttk.Frame(self.notebook)
        
        # Memory analysis
        mem_frame = ttk.LabelFrame(frame, text="Memory Analysis")
        ttk.Button(mem_frame, text="Volatility", command=self.run_volatility).pack(pady=5)
        mem_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Disk analysis
        disk_frame = ttk.LabelFrame(frame, text="Disk Analysis")
        ttk.Button(disk_frame, text="Autopsy", command=self.run_autopsy).pack(pady=5)
        disk_frame.pack(fill=tk.X, padx=5, pady=5)
        
        return frame
    
    def create_password_tab(self):
        """Create password cracking tab"""
        frame = ttk.Frame(self.notebook)
        
        # Hash cracking
        hash_frame = ttk.LabelFrame(frame, text="Hash Cracking")
        ttk.Button(hash_frame, text="Hashcat", command=self.run_hashcat).pack(pady=5)
        ttk.Button(hash_frame, text="John", command=self.run_john).pack(pady=5)
        hash_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Wordlist tools
        wordlist_frame = ttk.LabelFrame(frame, text="Wordlist Tools")
        ttk.Button(wordlist_frame, text="Generate Wordlist", command=self.generate_wordlist).pack(pady=5)
        wordlist_frame.pack(fill=tk.X, padx=5, pady=5)
        
        return frame
    
    def create_automation_tab(self):
        """Create automation workflow tab"""
        frame = ttk.Frame(self.notebook)
        
        # Workflow canvas
        self.workflow_canvas = tk.Canvas(frame, bg='white')
        self.workflow_canvas.pack(expand=True, fill=tk.BOTH)
        
        # Toolbox
        toolbox = ttk.LabelFrame(frame, text="Tools")
        tools = ['Nmap', 'SQLmap', 'Hydra', 'Metasploit']
        for tool in tools:
            ttk.Button(toolbox, text=tool, command=lambda t=tool: self.add_to_workflow(t)).pack(pady=2)
        toolbox.pack(side=tk.RIGHT, fill=tk.Y)
        
        return frame
    
    # ---------------------------
    # Core Functionality
    # ---------------------------
    def execute_command(self, command):
        """Execute a system command"""
        self.log_output(f"> {command}\n", 'info')
        
        def run():
            try:
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=True,
                    universal_newlines=True
                )
                
                for line in process.stdout:
                    self.log_output(line, 'info')
                
                for line in process.stderr:
                    self.log_output(line, 'error')
                
                if process.returncode == 0:
                    self.log_output("[+] Command completed successfully\n", 'success')
                else:
                    self.log_output(f"[-] Command failed with code {process.returncode}\n", 'error')
            
            except Exception as e:
                self.log_output(f"[-] Error: {str(e)}\n", 'error')
        
        # Run in separate thread to prevent GUI freeze
        threading.Thread(target=run, daemon=True).start()
    
    def log_output(self, text, tag=None):
        """Log output to console"""
        self.console.insert(tk.END, text, tag)
        self.console.see(tk.END)
    
    def update_status_indicators(self):
        """Update CPU, memory, and network indicators"""
        # This would be replaced with actual system monitoring
        self.cpu_var.set(f"CPU: {os.cpu_percent()}%")
        
        mem = os.virtual_memory()
        self.mem_var.set(f"Mem: {mem.used//1024//1024}MB/{mem.total//1024//1024}MB")
        
        # Network monitoring would go here
        self.net_var.set("Net: 0Kbps")
        
        # Update every second
        self.master.after(1000, self.update_status_indicators)
    
    # ---------------------------
    # Tool Methods
    # ---------------------------
    def analyze_apk(self):
        """Analyze an APK file"""
        apk_path = filedialog.askopenfilename(filetypes=[("APK files", "*.apk")])
        if apk_path:
            self.execute_command(f"apktool d {apk_path}")
    
    def run_metasploit(self):
        """Launch Metasploit"""
        self.execute_command("msfconsole")
    
    def quick_scan(self):
        """Run a quick network scan"""
        target = simpledialog.askstring("Quick Scan", "Enter target IP or range:")
        if target:
            self.execute_command(f"nmap -T4 -F {target}")
    
    # [Additional tool methods would be implemented here...]
    
    # ---------------------------
    # Helper Methods
    # ---------------------------
    def load_icon(self, filename):
        """Load an icon image"""
        try:
            img = Image.open(f"icons/{filename}")
            return ImageTk.PhotoImage(img)
        except:
            # Return blank image if icon not found
            return tk.PhotoImage()
    
    def load_settings(self):
        """Load application settings"""
        try:
            with open('settings.json') as f:
                self.settings = json.load(f)
        except:
            self.settings = {
                'theme': 'dark',
                'recent_projects': []
            }
    
    def save_settings(self):
        """Save application settings"""
        with open('settings.json', 'w') as f:
            json.dump(self.settings, f)
    
    # ---------------------------
    # Session Management
    # ---------------------------
    def new_project(self):
        """Create a new project"""
        name = simpledialog.askstring("New Project", "Enter project name:")
        if name:
            self.session_manager.new_session(name)
            self.update_status(f"Created new project: {name}")
    
    def save_session(self):
        """Save current session"""
        self.session_manager.save()
        self.update_status("Session saved")
    
    def load_session(self):
        """Load a saved session"""
        filename = filedialog.askopenfilename(filetypes=[("Session files", "*.json")])
        if filename:
            self.session_manager.load(filename)
            self.update_status(f"Loaded session: {filename}")
    
    # ---------------------------
    # Main Execution
    # ---------------------------
    def run(self):
        """Run the application"""
        self.master.mainloop()


class SessionManager:
    """Manage pentesting sessions"""
    def __init__(self):
        self.current_session = None
        self.sessions = {}
    
    def new_session(self, name):
        """Create new session"""
        self.current_session = {
            'name': name,
            'targets': [],
            'notes': '',
            'timestamp': str(datetime.now())
        }
    
    def save(self):
        """Save current session"""
        if self.current_session:
            filename = f"sessions/{self.current_session['name']}.json"
            with open(filename, 'w') as f:
                json.dump(self.current_session, f)
    
    def load(self, filename):
        """Load session from file"""
        with open(filename) as f:
            self.current_session = json.load(f)


class PluginManager:
    """Manage application plugins"""
    def __init__(self, app):
        self.app = app
        self.plugins = {}
        self.load_plugins()
    
    def load_plugins(self):
        """Load all plugins from plugins directory"""
        plugin_dir = 'plugins'
        if not os.path.exists(plugin_dir):
            os.makedirs(plugin_dir)
        
        for filename in os.listdir(plugin_dir):
            if filename.endswith('.py'):
                try:
                    module_name = filename[:-3]
                    spec = importlib.util.spec_from_file_location(
                        module_name, f"{plugin_dir}/{filename}")
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    if hasattr(module, 'register'):
                        module.register(self.app)
                        self.plugins[module_name] = module
                except Exception as e:
                    self.app.log_output(f"Failed to load plugin {filename}: {str(e)}\n", 'error')


if __name__ == "__main__":
    root = tk.Tk()
    app = PentestPro(root)
    app.run()
