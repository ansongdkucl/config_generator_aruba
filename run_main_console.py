import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import json
import ipaddress
import os
import csv
import threading
import time
from datetime import datetime
from pathlib import Path

# Optional/External modules
try:
    import paramiko
except Exception:
    paramiko = None

try:
    import serial
    import serial.tools.list_ports
except Exception:
    serial = None

# -----------------------------
# Configuration defaults
# -----------------------------
DEFAULT_HOSTNAME = "default_host"
DEFAULT_VLAN_ID = "0"
DEFAULT_VLAN_NAME = "default_vlan"
DEFAULT_LOCATION = "default_location"

# -----------------------------
# Helpers
# -----------------------------

def safe_mac_filename(mac: str) -> str:
    """Return a safe filename for a MAC-based config (e.g., 1a2b3c4d5e6f.cfg)."""
    only_hex = "".join(ch for ch in mac if ch.isalnum()).lower()
    return f"{only_hex}.cfg" if only_hex else "config.cfg"


# -----------------------------
# Template manager
# -----------------------------
class TemplateManager:
    def __init__(self, template_dir="templates"):
        self.template_dir = Path(template_dir)
        self.template_dir.mkdir(exist_ok=True)

    def load_template(self, template_name):
        template_file = self.template_dir / f"{template_name}.j2"
        if template_file.exists():
            with open(template_file, "r") as f:
                return f.read()
        raise FileNotFoundError(f"Template {template_name} not found at {template_file}")

    def get_available_templates(self):
        return sorted([p.stem for p in self.template_dir.glob("*.j2")])


# -----------------------------
# Network config model
# -----------------------------
class NetworkConfig:
    def __init__(self, config_dir="config"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        self.config_file = self.config_dir / "network_config.json"
        self.load_config()

    def load_config(self):
        if self.config_file.exists():
            try:
                with open(self.config_file, "r") as f:
                    self.config = json.load(f)
                return
            except json.JSONDecodeError as e:
                messagebox.showerror("Config Error", f"Invalid JSON in config file: {e}")
        self._create_default_config()

    def _create_default_config(self):
        self.config = {
            "aruba-sw": {
                "network_address": "172.22.27.0",
                "subnet_mask": "255.255.255.0",
                "gateway": "172.22.27.254",
                "hosts_range": ["172.22.27.1", "172.22.27.253"],
                "data_vlan": {"id": "100", "name": "Data_VLAN"},
                "profiles": {"av": {}, "standard": {}}
            }
        }
        self.save_config()

    def save_config(self):
        with open(self.config_file, "w") as f:
            json.dump(self.config, f, indent=4)

    def get_network_names(self):
        return list(self.config.keys())

    def calculate_gateway(self, management_ip):
        try:
            ip = ipaddress.IPv4Address(management_ip)
            for network_name, cfg in self.config.items():
                try:
                    network = ipaddress.IPv4Network(
                        f"{cfg['network_address']}/{cfg['subnet_mask']}", strict=False
                    )
                    if ip in network:
                        return cfg["gateway"]
                except Exception:
                    continue
            # default: .254 in /24
            network = ipaddress.IPv4Network(f"{management_ip}/24", strict=False)
            return str(network.network_address + 254)
        except Exception:
            return "0.0.0.0"

    def get_profile_vlans(self, management_ip, profile_type):
        try:
            ip = ipaddress.IPv4Address(management_ip)
            for network_name, cfg in self.config.items():
                try:
                    network = ipaddress.IPv4Network(
                        f"{cfg['network_address']}/{cfg['subnet_mask']}", strict=False
                    )
                    if ip in network:
                        return cfg.get("profiles", {}).get(profile_type, {})
                except Exception:
                    continue
            return {}
        except Exception:
            return {}

    def get_data_vlan_info(self, management_ip):
        try:
            ip = ipaddress.IPv4Address(management_ip)
            for network_name, cfg in self.config.items():
                try:
                    network = ipaddress.IPv4Network(
                        f"{cfg['network_address']}/{cfg['subnet_mask']}", strict=False
                    )
                    if ip in network:
                        if "data_vlan" in cfg:
                            return cfg["data_vlan"].get("id", DEFAULT_VLAN_ID), cfg["data_vlan"].get("name", DEFAULT_VLAN_NAME)
                        return DEFAULT_VLAN_ID, DEFAULT_VLAN_NAME
                except Exception:
                    continue
            return DEFAULT_VLAN_ID, DEFAULT_VLAN_NAME
        except Exception:
            return DEFAULT_VLAN_ID, DEFAULT_VLAN_NAME

    def generate_hostname(self, management_ip, template_type, profile_type="standard"):
        try:
            octets = str(ipaddress.IPv4Address(management_ip)).split(".")
            if profile_type == "standard":
                prefix = "ae6000m"
            else:
                prefix = "ae4100i"
            return f"{prefix}-{octets[1]}-{octets[2]}-{octets[3]}"
        except Exception:
            return DEFAULT_HOSTNAME


# -----------------------------
# SFTP uploader (Paramiko)
# -----------------------------
class SFTPUploader:
    def __init__(self):
        self.authenticated = False
        self.ftp_server_ip = None
        self.ftp_username = None
        self.ftp_password = None

    def authenticate(self, server_ip, username, password):
        self.ftp_server_ip = server_ip
        self.ftp_username = username
        self.ftp_password = password
        self.authenticated = True

    def upload_with_sftp(self, local_file: str, remote_file: str) -> bool:
        if not self.authenticated or not paramiko:
            return False
        try:
            transport = paramiko.Transport((self.ftp_server_ip, 22))
            transport.connect(username=self.ftp_username, password=self.ftp_password)
            sftp = paramiko.SFTPClient.from_transport(transport)
            remote_directory = "ztp"
            try:
                sftp.mkdir(remote_directory)
            except IOError:
                pass
            remote_path = f"{remote_directory}/{remote_file}"
            sftp.put(local_file, remote_path)
            sftp.close()
            transport.close()
            return True
        except Exception:
            return False


# -----------------------------
# Serial console wrapper (pyserial)
# -----------------------------
class SerialConsole:
    def __init__(self):
        self.serial_connection = None
        self.is_connected = False
        self.read_thread = None
        self.stop_reading = False

    def get_available_ports(self):
        if not serial:
            return []
        ports = serial.tools.list_ports.comports()
        return [p.device for p in ports]

    def connect(self, port, baudrate=115200, timeout=1):
        if not serial:
            return False
        try:
            self.serial_connection = serial.Serial(
                port=port,
                baudrate=baudrate,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=timeout
            )
            self.is_connected = True
            return True
        except Exception:
            return False

    def disconnect(self):
        self.stop_reading = True
        if self.serial_connection and self.serial_connection.is_open:
            try:
                self.serial_connection.close()
            except Exception:
                pass
        self.is_connected = False

    def send_command(self, command):
        if self.serial_connection and self.is_connected:
            try:
                self.serial_connection.write((command + "\r\n").encode("utf-8"))
                return True
            except Exception:
                return False
        return False

    def start_reading(self, callback):
        def read_serial():
            while self.serial_connection and self.is_connected and not self.stop_reading:
                try:
                    if self.serial_connection.in_waiting > 0:
                        data = self.serial_connection.readline().decode("utf-8", errors="ignore")
                        if data:
                            callback(data)
                    time.sleep(0.05)
                except Exception:
                    break
        self.stop_reading = False
        self.read_thread = threading.Thread(target=read_serial, daemon=True)
        self.read_thread.start()

    def stop_reading_thread(self):
        self.stop_reading = True
        if self.read_thread and self.read_thread.is_alive():
            try:
                self.read_thread.join(timeout=1.0)
            except Exception:
                pass


# -----------------------------
# Dialog for SFTP creds
# -----------------------------
class SFTPLoginDialog(simpledialog.Dialog):
    def __init__(self, parent, title="SFTP Login"):
        self.server_ip = None
        self.username = None
        self.password = None
        super().__init__(parent, title)

    def body(self, master):
        ttk.Label(master, text="SFTP Server:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.server_entry = ttk.Entry(master, width=30)
        self.server_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)

        ttk.Label(master, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.user_entry = ttk.Entry(master, width=30)
        self.user_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)

        ttk.Label(master, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.pass_entry = ttk.Entry(master, width=30, show="*")
        self.pass_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)

        self.server_entry.focus_set()
        return self.server_entry

    def apply(self):
        self.server_ip = self.server_entry.get().strip()
        self.username = self.user_entry.get().strip()
        self.password = self.pass_entry.get().strip()


# -----------------------------
# Main GUI
# -----------------------------
class SwitchConfigGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("Aruba Switch Configuration Generator")
        self.root.geometry("820x980")

        # managers
        self.template_manager = TemplateManager()
        self.network_config = NetworkConfig()
        self.sftp_uploader = SFTPUploader()
        self.serial_console = SerialConsole()

        self.output_dir = Path("generated_configs")
        self.output_dir.mkdir(exist_ok=True)

        self.com_port_combo = None

        self.create_widgets()
        self.refresh_com_ports()

    # -------- UI ---------
    def create_widgets(self):
        main = ttk.Frame(self.root, padding="10")
        main.grid(row=0, column=0, sticky="nsew")

        title = ttk.Label(main, text="Aruba Switch Configuration Generator", font=("Arial", 16, "bold"))
        title.grid(row=0, column=0, columnspan=3, pady=(0, 20))

        # Template
        ttk.Label(main, text="Switch Template:").grid(row=1, column=0, sticky=tk.W)
        self.template_var = tk.StringVar()
        templates = self.template_manager.get_available_templates() or ["aruba-4100", "aruba-6300"]
        template_combo = ttk.Combobox(main, textvariable=self.template_var, values=templates, state="readonly")
        template_combo.grid(row=1, column=1, sticky="ew", pady=5)
        self.template_var.set(templates[0])

        # Profile (Radiobuttons to avoid dual-check issue)
        ttk.Label(main, text="Profile:").grid(row=2, column=0, sticky=tk.W)
        self.profile_var = tk.StringVar(value="standard")
        pr_frame = ttk.Frame(main)
        pr_frame.grid(row=2, column=1, sticky=tk.W, pady=5)
        ttk.Radiobutton(pr_frame, text="Standard", variable=self.profile_var, value="standard").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Radiobutton(pr_frame, text="AV", variable=self.profile_var, value="av").pack(side=tk.LEFT)

        # Management IP (required)
        ttk.Label(main, text="Management IP *:").grid(row=3, column=0, sticky=tk.W)
        self.management_ip_var = tk.StringVar()
        mgmt_entry = ttk.Entry(main, textvariable=self.management_ip_var)
        mgmt_entry.grid(row=3, column=1, sticky="ew", pady=5)
        mgmt_entry.bind("<FocusOut>", self.auto_fill_fields)

        # Hostname
        ttk.Label(main, text="Hostname:").grid(row=4, column=0, sticky=tk.W)
        self.hostname_var = tk.StringVar()
        ttk.Entry(main, textvariable=self.hostname_var).grid(row=4, column=1, sticky="ew", pady=5)

        # Location
        ttk.Label(main, text="Location:").grid(row=5, column=0, sticky=tk.W)
        self.location_var = tk.StringVar(value=DEFAULT_LOCATION)
        ttk.Entry(main, textvariable=self.location_var).grid(row=5, column=1, sticky="ew", pady=5)

        # Data VLAN ID/Name
        ttk.Label(main, text="Data VLAN ID:").grid(row=6, column=0, sticky=tk.W)
        self.data_vlan_id_var = tk.StringVar()
        ttk.Entry(main, textvariable=self.data_vlan_id_var).grid(row=6, column=1, sticky="ew", pady=5)

        ttk.Label(main, text="Data VLAN Name:").grid(row=7, column=0, sticky=tk.W)
        self.data_vlan_name_var = tk.StringVar()
        ttk.Entry(main, textvariable=self.data_vlan_name_var).grid(row=7, column=1, sticky="ew", pady=5)

        # MAC & Serial (required)
        ttk.Label(main, text="MAC Address *:").grid(row=8, column=0, sticky=tk.W)
        self.mac_address_var = tk.StringVar()
        ttk.Entry(main, textvariable=self.mac_address_var).grid(row=8, column=1, sticky="ew", pady=5)

        ttk.Label(main, text="Serial Number *:").grid(row=9, column=0, sticky=tk.W)
        self.serial_number_var = tk.StringVar()
        ttk.Entry(main, textvariable=self.serial_number_var).grid(row=9, column=1, sticky="ew", pady=5)

        # Upload toggle
        self.upload_var = tk.BooleanVar()
        ttk.Checkbutton(main, text="Upload to SFTP server", variable=self.upload_var, command=self.on_upload_toggle).grid(row=10, column=0, columnspan=2, pady=8, sticky=tk.W)

        # Buttons
        btns = ttk.Frame(main)
        btns.grid(row=11, column=0, columnspan=3, pady=10)
        ttk.Button(btns, text="Generate Configuration", command=self.generate_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(btns, text="Clear All", command=self.clear_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(btns, text="Exit", command=self.root.quit).pack(side=tk.LEFT, padx=5)

        # Required note
        ttk.Label(main, text="* Required fields", font=("Arial", 9, "italic"), foreground="red").grid(row=12, column=0, columnspan=2, pady=(5, 0), sticky=tk.W)

        # Output box
        ttk.Label(main, text="Output:").grid(row=13, column=0, sticky=tk.W, pady=(18, 5))
        self.output_text = tk.Text(main, height=12, width=90)
        self.output_text.grid(row=14, column=0, columnspan=3, sticky="nsew")
        out_scroll = ttk.Scrollbar(main, orient=tk.VERTICAL, command=self.output_text.yview)
        out_scroll.grid(row=14, column=3, sticky="ns")
        self.output_text.configure(yscrollcommand=out_scroll.set)

        # Console section (under output)
        console = ttk.LabelFrame(main, text="Console Connection", padding=5)
        console.grid(row=15, column=0, columnspan=3, sticky="nsew", pady=(18, 5))

        ttk.Label(console, text="COM Port:").grid(row=0, column=0, sticky=tk.W)
        self.com_port_var = tk.StringVar()
        self.com_port_combo = ttk.Combobox(console, textvariable=self.com_port_var, width=14, state="readonly")
        self.com_port_combo.grid(row=0, column=1, sticky=tk.W, padx=(4, 6))

        ttk.Button(console, text="Refresh Ports", command=self.refresh_com_ports).grid(row=0, column=2, sticky=tk.W)
        self.connect_button = ttk.Button(console, text="Connect", command=self.connect_console)
        self.connect_button.grid(row=0, column=3, padx=4)
        self.disconnect_button = ttk.Button(console, text="Disconnect", command=self.disconnect_console, state=tk.DISABLED)
        self.disconnect_button.grid(row=0, column=4, padx=4)
        self.write_config_button = ttk.Button(console, text="Write Config to Console", command=self.write_config_to_console, state=tk.DISABLED)
        self.write_config_button.grid(row=0, column=5, padx=4)

        self.console_text = tk.Text(console, height=10, width=90, bg="black", fg="white")
        self.console_text.grid(row=1, column=0, columnspan=6, sticky="nsew", pady=(6, 6))
        con_scroll = ttk.Scrollbar(console, orient=tk.VERTICAL, command=self.console_text.yview)
        con_scroll.grid(row=1, column=6, sticky="ns")
        self.console_text.configure(yscrollcommand=con_scroll.set)

        self.console_input_var = tk.StringVar()
        con_entry = ttk.Entry(console, textvariable=self.console_input_var)
        con_entry.grid(row=2, column=0, columnspan=5, sticky="ew", pady=(0, 6))
        con_entry.bind("<Return>", self.send_console_command)
        ttk.Button(console, text="Send", command=self.send_console_command).grid(row=2, column=5, sticky=tk.W, pady=(0, 6))

        # Progress bar (below Send button)
        progress_frame = ttk.Frame(console)
        progress_frame.grid(row=3, column=0, columnspan=6, sticky="ew", pady=(4, 4))
        ttk.Label(progress_frame, text="Transfer Progress:").pack(side=tk.LEFT, padx=(2, 8))
        self.progress = ttk.Progressbar(progress_frame, length=300, mode='determinate', maximum=100)
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True)




        # Status
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(main, textvariable=self.status_var, relief=tk.SUNKEN).grid(row=16, column=0, columnspan=3, sticky="ew")

        # Grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main.columnconfigure(1, weight=1)
        main.rowconfigure(14, weight=1)
        console.columnconfigure(0, weight=1)
        console.rowconfigure(1, weight=1)

    # -------- Console logic ---------
    def refresh_com_ports(self):
        ports = self.serial_console.get_available_ports()
        if self.com_port_combo is not None:
            self.com_port_combo["values"] = ports
            if ports:
                # Auto-select first port if none selected
                cur = self.com_port_var.get()
                if not cur or cur not in ports:
                    self.com_port_var.set(ports[0])
            else:
                self.com_port_var.set("")

    def connect_console(self):
        port = self.com_port_var.get()
        if not port:
            messagebox.showerror("Error", "Please select a COM port")
            return
        ok = self.serial_console.connect(port, baudrate=115200)
        if ok:
            self.connect_button.config(state=tk.DISABLED)
            self.disconnect_button.config(state=tk.NORMAL)
            self.write_config_button.config(state=tk.NORMAL)
            self.status_var.set(f"Connected to {port}")
            self.serial_console.start_reading(self.console_output_callback)
        else:
            messagebox.showerror("Error", f"Failed to connect to {port}. Is the device attached?")

    def disconnect_console(self):
        self.serial_console.stop_reading_thread()
        self.serial_console.disconnect()
        self.connect_button.config(state=tk.NORMAL)
        self.disconnect_button.config(state=tk.DISABLED)
        self.write_config_button.config(state=tk.DISABLED)
        self.status_var.set("Disconnected from console")

    def console_output_callback(self, data):
        def update():
            self.console_text.insert(tk.END, data)
            self.console_text.see(tk.END)
        self.root.after(0, update)

    def send_console_command(self, event=None):
        cmd = self.console_input_var.get()
        if cmd and self.serial_console.is_connected:
            self.serial_console.send_command(cmd)
            self.console_input_var.set("")

    def write_config_to_console(self):
        """Send configuration to an Aruba CX console.
        Always sends 'admin' login first, handles blank password setup,
        enters config mode, and pushes the config with progress bar."""
        if not self.serial_console.is_connected:
            messagebox.showerror("Error", "Not connected to console")
            return

        hostname = self.hostname_var.get().strip()
        if not hostname:
            messagebox.showerror("Error", "No hostname found. Please generate configuration first.")
            return

        cfg_path = self.output_dir / f"{hostname}.cfg"
        if not cfg_path.exists():
            messagebox.showerror("Error", f"Configuration file not found: {cfg_path}")
            return

        ser = self.serial_console.serial_connection
        if not ser:
            messagebox.showerror("Error", "Serial connection unavailable.")
            return

        def read_console(timeout=1.0):
            end = time.time() + timeout
            buf = ""
            while time.time() < end:
                if ser.in_waiting:
                    buf += ser.read(ser.in_waiting).decode("utf-8", errors="ignore")
                time.sleep(0.1)
            return buf.lower()

        try:
            self.progress["value"] = 0
            self.status_var.set("Starting console login…")
            self.root.update_idletasks()

            # --- Stage 1: Force login sequence ---
            # Always send 'admin' first, assume prompt is ready
            self.serial_console.send_command("admin")
            time.sleep(2.0)

            # Handle password prompts and setup
            for _ in range(40):
                buf = read_console(0.8)
                if not buf:
                    continue
                if "password:" in buf and "configure the 'admin'" not in buf:
                    self.serial_console.send_command("")
                    time.sleep(1.0)
                elif "please configure the 'admin' user account password" in buf:
                    self.serial_console.send_command("")
                    time.sleep(1.0)
                elif "enter new password" in buf:
                    self.serial_console.send_command("")
                    time.sleep(1.0)
                elif "confirm new password" in buf:
                    self.serial_console.send_command("")
                    time.sleep(1.0)
                elif "#" in buf:
                    break
                time.sleep(0.3)

            # --- Stage 2: enter configuration mode ---
            self.status_var.set("Entering configuration mode…")
            self.serial_console.send_command("configure terminal")
            time.sleep(1.5)

            # --- Stage 3: send configuration lines ---
            with open(cfg_path, "r") as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith("!")]

            total = len(lines)
            self.progress["value"] = 0
            self.progress["maximum"] = total
            self.status_var.set(f"Sending configuration ({total} lines)…")
            self.root.update_idletasks()

            for i, line in enumerate(lines, start=1):
                self.serial_console.send_command(line)
                time.sleep(0.1)

                incoming = read_console(0.3)
                if any(x in incoming for x in ["[y/n]", "(y/n)", "do you want", "confirm", "overwrite existing"]):
                    self.serial_console.send_command("y")
                    time.sleep(0.4)

                self.progress["value"] = i
                if i % 5 == 0 or i == total:
                    self.status_var.set(f"Sending line {i}/{total}…")
                    self.root.update_idletasks()

            # --- Stage 4: save ---
            self.serial_console.send_command("end")
            time.sleep(0.5)
            self.serial_console.send_command("write memory")
            time.sleep(1.0)

            self.progress["value"] = total
            self.status_var.set("Configuration complete.")
            self.root.update_idletasks()
            messagebox.showinfo("Success", f"Configuration '{hostname}.cfg' sent successfully!")

        except Exception as err:
            self.status_var.set("Error during config send.")
            messagebox.showerror("Error", f"Failed to send configuration:\n{err}")




    # -------- SFTP ---------
    def on_upload_toggle(self):
        if self.upload_var.get() and not self.sftp_uploader.authenticated:
            self.configure_sftp()

    def configure_sftp(self):
        dlg = SFTPLoginDialog(self.root)
        if dlg.server_ip and dlg.username and dlg.password:
            self.sftp_uploader.authenticate(dlg.server_ip, dlg.username, dlg.password)
            messagebox.showinfo("SFTP", "SFTP credentials configured")
        else:
            self.upload_var.set(False)
            messagebox.showwarning("SFTP", "SFTP configuration cancelled")

    # -------- Generation helpers ---------
    def auto_fill_fields(self, event=None):
    
        mgmt_ip = self.management_ip_var.get().strip()
        if not mgmt_ip:
            return

        try:
            ipaddress.IPv4Address(mgmt_ip)
        except ipaddress.AddressValueError:
            return

        try:
            template_type = self.template_var.get()
            profile_type = self.profile_var.get()

            # Auto-generate hostname based on both IP + profile type
            hostname = self.network_config.generate_hostname(mgmt_ip, template_type, profile_type)
            self.hostname_var.set(hostname)

            # Auto-fill data VLAN info from network config
            vid, vname = self.network_config.get_data_vlan_info(mgmt_ip)
            self.data_vlan_id_var.set(vid)
            self.data_vlan_name_var.set(vname)
        except Exception:
            pass


    def generate_profile_vlan_config(self, management_ip, profile_type):
        vlans = self.network_config.get_profile_vlans(management_ip, profile_type)
        out = []
        for vlan_id, vlan_name in vlans.items():
            out.append(f"vlan {vlan_id}")
            out.append(f"   name {vlan_name}")
            out.append("!")
        return "\n".join(out) + ("\n" if out else "")

    def get_all_vlan_ids(self, data_vlan_id, management_ip, profile_type):
        """Return a complete list of all VLAN IDs: data VLAN, profile VLANs, and defaults."""
        vlan_ids = set()  # use a set to avoid duplicates

        # Always include data VLAN
        if data_vlan_id:
            vlan_ids.add(str(data_vlan_id).strip())

        # Include known defaults
        vlan_ids.update(["885", "1001"])

        # Include profile VLANs from config
        profile_vlans = self.network_config.get_profile_vlans(management_ip, profile_type)
        for vid in profile_vlans.keys():
            vlan_ids.add(str(vid).strip())

        # Return as sorted list of strings (numeric order)
        try:
            return sorted(vlan_ids, key=lambda x: int(x))
        except Exception:
            return sorted(vlan_ids)
        

    def generate_trunk_allowed_vlans(self, data_vlan_id, management_ip, profile_type):
        """Return VLAN trunk list formatted as comma-separated values (no spaces)."""
        vlan_ids = self.get_all_vlan_ids(data_vlan_id, management_ip, profile_type)
        # Join with commas only — no spaces
        return ",".join(vlan_ids)



    def generate_aruba_central_json(self, hostname, management_ip, data_vlan_id, data_vlan_name, location, gateway, mac_address, serial_number, profile_type):
        central = {
            serial_number: {
                "_sys_data_vlan_id": data_vlan_id,
                "_sys_data_vlan_name": data_vlan_name,
                "_sys_gateway": gateway,
                "_sys_hostname": hostname,
                "_sys_lan_mac": mac_address,
                "_sys_location": location,
                "_sys_mgnt_ip": management_ip,
                "_sys_serial": serial_number,
            }
        }
        vlans = self.network_config.get_profile_vlans(management_ip, profile_type)
        for vid, vname in vlans.items():
            central[serial_number][f"_sys_{vid}_vlan_name"] = vname
        return central

    def save_csv_file(self, central_json, output_path):
        try:
            with open(output_path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["Variable", "Value"])
                for serial_number, data in central_json.items():
                    for k, v in data.items():
                        w.writerow([k, v])
        except Exception as e:
            print(f"CSV save error: {e}")

    # -------- Generate config ---------
    def generate_config(self):
        # required fields
        if not self.management_ip_var.get().strip() or not self.mac_address_var.get().strip() or not self.serial_number_var.get().strip():
            messagebox.showerror("Error", "Please fill in all required fields (*)")
            return
        try:
            ipaddress.IPv4Address(self.management_ip_var.get().strip())
        except ipaddress.AddressValueError:
            messagebox.showerror("Error", "Invalid Management IP address")
            return
        if not self.profile_var.get():
            messagebox.showerror("Error", "Please select a profile (Standard or AV)")
            return

        # Ensure SFTP cred if requested
        if self.upload_var.get() and not self.sftp_uploader.authenticated:
            if messagebox.askyesno("SFTP Not Configured", "SFTP is not configured. Configure now?"):
                self.configure_sftp()
            if not self.sftp_uploader.authenticated:
                self.upload_var.set(False)
                messagebox.showwarning("SFTP", "Upload cancelled. Will save locally only.")

        self.status_var.set("Loading template...")
        self.root.update_idletasks()
        template_content = self.template_manager.load_template(self.template_var.get())

        self.status_var.set("Calculating gateway...")
        self.root.update_idletasks()
        gateway = self.network_config.calculate_gateway(self.management_ip_var.get().strip())

        self.status_var.set("Generating configuration...")
        self.root.update_idletasks()

        # Inputs w/ defaults
        hostname = self.hostname_var.get().strip() or DEFAULT_HOSTNAME
        data_vlan_id = self.data_vlan_id_var.get().strip() or DEFAULT_VLAN_ID
        data_vlan_name = self.data_vlan_name_var.get().strip() or DEFAULT_VLAN_NAME
        location = self.location_var.get().strip() or DEFAULT_LOCATION
        mac_address = self.mac_address_var.get().strip()
        serial_number = self.serial_number_var.get().strip()
        management_ip = self.management_ip_var.get().strip()
        profile_type = self.profile_var.get()

        # Profile VLAN block & trunk list
        profile_vlan_cfg = self.generate_profile_vlan_config(management_ip, profile_type)
        trunk_allowed = self.generate_trunk_allowed_vlans(data_vlan_id, management_ip, profile_type)

        # Substitute template variables
        config = template_content
        replacements = {
            "{{hostname}}": hostname,
            "{{management_ip}}": management_ip,
            "{{data_vlan_id}}": data_vlan_id,
            "{{data_vlan_name}}": data_vlan_name,
            "{{snmp_location}}": location,
            "{{gateway}}": gateway,
            "{{trunk_allowed_vlans}}": trunk_allowed,
        }
        for k, v in replacements.items():
            config = config.replace(k, v)

        if "{{profile_vlans}}" in config:
            config = config.replace("{{profile_vlans}}", profile_vlan_cfg)
        else:
            # If template lacks placeholder, append VLANs after data VLAN block or at end
            if profile_vlan_cfg:
                marker = f"vlan {data_vlan_id}"
                idx = config.find(marker)
                if idx != -1:
                    # find end of that block by next '!' after marker
                    end_idx = config.find("\n!", idx)
                    if end_idx == -1:
                        end_idx = idx + len(marker)
                    insert_pos = end_idx + 2 if end_idx + 2 <= len(config) else len(config)
                    config = config[:insert_pos] + "\n" + profile_vlan_cfg + config[insert_pos:]
                else:
                    config += "\n" + profile_vlan_cfg

        # Save outputs
        cfg_filename = f"{hostname}.cfg"
        json_filename = f"{hostname}.json"
        csv_filename = f"{hostname}.csv"

        cfg_path = self.output_dir / cfg_filename
        with open(cfg_path, "w") as f:
            f.write(config)

        # Central JSON + CSV
        central = self.generate_aruba_central_json(
        hostname, management_ip, data_vlan_id, data_vlan_name, location, gateway, mac_address, serial_number, profile_type
        )
        json_path = self.output_dir / json_filename
        with open(json_path, "w") as jf:
            json.dump(central, jf, indent=2)
        csv_path = self.output_dir / csv_filename
        self.save_csv_file(central, csv_path)

        # Optional upload
        upload_msg = ""
        if self.upload_var.get():
            remote_name = safe_mac_filename(mac_address)
            ok = self.sftp_uploader.upload_with_sftp(str(cfg_path), remote_name)
            upload_msg = f"\nUploaded to SFTP as ztp/{remote_name}" if ok else "\nSFTP upload failed."

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Show in GUI
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, f"Generated at {timestamp}\n")
        self.output_text.insert(tk.END, f"Saved config: {cfg_path}\n")
        self.output_text.insert(tk.END, f"Saved Central JSON: {json_path}\n")
        self.output_text.insert(tk.END, f"Saved Central CSV: {csv_path}{upload_msg}\n\n")
        self.output_text.insert(tk.END, config)
        self.output_text.see(tk.END)
        self.status_var.set("Generated configuration.")

    # -------- misc ---------
    def clear_all(self):
        self.hostname_var.set("")
        self.management_ip_var.set("")
        self.location_var.set(DEFAULT_LOCATION)
        self.data_vlan_id_var.set("")
        self.data_vlan_name_var.set("")
        self.mac_address_var.set("")
        self.serial_number_var.set("")
        self.profile_var.set("standard")
        self.output_text.delete("1.0", tk.END)
        self.console_text.delete("1.0", tk.END)
        self.status_var.set("Ready")


if __name__ == "__main__":
    root = tk.Tk()
    app = SwitchConfigGenerator(root)
    root.mainloop()
