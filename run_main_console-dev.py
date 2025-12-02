#!/usr/bin/env python3
"""
Aruba Switch Configuration Tool (clean modular version)

Features:
- Generate full switch config from Jinja-style templates (.j2) + network_config.json
- Auto-fill hostname + Data VLAN from Management IP
- Save .cfg, .json, .csv, api-*.json
- Send full config to switch via serial console (pyserial)
- Load Excel (port / vlan / description) and push per-port config via SSH (Netmiko, aruba_aoscx)
"""

import os
import json
import csv
import ipaddress
import time
import threading
from datetime import datetime
from pathlib import Path

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# Optional extras
try:
    import serial
    import serial.tools.list_ports
except Exception:
    serial = None

try:
    import pandas as pd
except Exception:
    pd = None

try:
    from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
except Exception:
    ConnectHandler = None


# =============================================================================
# Configuration constants
# =============================================================================

DEFAULT_HOSTNAME = "default_host"
DEFAULT_VLAN_ID = "0"
DEFAULT_VLAN_NAME = "default_vlan"
DEFAULT_LOCATION = "default_location"

TEMPLATE_DIR = Path("templates")
CONFIG_DIR = Path("config")
OUTPUT_DIR = Path("generated_configs")

TEMPLATE_DIR.mkdir(exist_ok=True)
CONFIG_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)


# =============================================================================
# Helpers / Models
# =============================================================================

class TemplateManager:
    """Loads Jinja-style templates stored in templates/*.j2."""

    def __init__(self, template_dir: Path = TEMPLATE_DIR):
        self.template_dir = template_dir

    def load_template(self, template_name: str) -> str:
        # template_name is the label from combobox – map to stem
        mapping = {
            "4100i - Standard": "4100i_standard",
            "4100i - Audio Visual": "4100i_av",
            "6300m - Standard": "6300m_standard",
            "6300m - Audio Visual": "6300m_av",
        }
        stem = mapping.get(template_name, template_name)
        path = self.template_dir / f"{stem}.j2"
        if not path.exists():
            raise FileNotFoundError(f"Template not found: {path}")
        return path.read_text(encoding="utf-8")


class NetworkConfig:
    """
    Reads config/network_config.json and provides helpers:
    - auto gateway from IP
    - data/voice VLAN info
    - profile VLANs (standard/av)
    - generated hostname & trunk allowed VLANs
    """

    def __init__(self, config_dir: Path = CONFIG_DIR):
        self.config_path = config_dir / "network_config.json"
        self.config_dir = config_dir
        self.config_dir.mkdir(exist_ok=True)
        self.config = {}
        self._load_or_create_default()

    # ------------ core load/save ------------

    def _load_or_create_default(self):
        if self.config_path.exists():
            try:
                self.config = json.loads(self.config_path.read_text(encoding="utf-8"))
                return
            except Exception:
                pass  # fall through to default

        # default minimal config
        self.config = {
            "aruba-sw": {
                "network_address": "172.22.27.0",
                "subnet_mask": "255.255.255.0",
                "gateway": "172.22.27.254",
                "hosts_range": ["172.22.27.1", "172.22.27.253"],
                "data_vlan": {"id": "100", "name": "Data_VLAN"},
                # voice_vlan is optional
                "profiles": {
                    "standard": {},
                    "av": {}
                }
            }
        }
        self.save()

    def save(self):
        self.config_path.write_text(json.dumps(self.config, indent=4), encoding="utf-8")

    # ------------ internal helpers ------------

    def _find_network_cfg_for_ip(self, management_ip: str):
        try:
            ip = ipaddress.IPv4Address(management_ip)
        except Exception:
            return None

        for cfg in self.config.values():
            try:
                net = ipaddress.IPv4Network(
                    f"{cfg['network_address']}/{cfg['subnet_mask']}",
                    strict=False
                )
                if ip in net:
                    return cfg
            except Exception:
                continue
        return None

    # ------------ public helpers ------------

    def calculate_gateway(self, management_ip: str) -> str:
        cfg = self._find_network_cfg_for_ip(management_ip)
        if cfg and "gateway" in cfg:
            return cfg["gateway"]
        try:
            net = ipaddress.IPv4Network(f"{management_ip}/24", strict=False)
            return str(net.network_address + 254)
        except Exception:
            return "0.0.0.0"

    def get_data_vlan_info(self, management_ip: str):
        cfg = self._find_network_cfg_for_ip(management_ip)
        if cfg and "data_vlan" in cfg:
            d = cfg["data_vlan"]
            return d.get("id", DEFAULT_VLAN_ID), d.get("name", DEFAULT_VLAN_NAME)
        return DEFAULT_VLAN_ID, DEFAULT_VLAN_NAME

    def get_voice_vlan_info(self, management_ip: str):
        cfg = self._find_network_cfg_for_ip(management_ip)
        if cfg and "voice_vlan" in cfg:
            v = cfg["voice_vlan"]
            return v.get("id", ""), v.get("name", "")
        return "", ""

    def get_profile_vlans(self, management_ip: str, profile_type: str):
        cfg = self._find_network_cfg_for_ip(management_ip)
        if not cfg:
            return {}
        return cfg.get("profiles", {}).get(profile_type, {})

    def generate_hostname(self, management_ip: str, template_label: str) -> str:
        try:
            octets = str(ipaddress.IPv4Address(management_ip)).split(".")
        except Exception:
            return DEFAULT_HOSTNAME

        label = template_label.lower()
        if "6300" in label:
            prefix = "ae6000m"
        else:
            prefix = "ae4100i"
        return f"{prefix}-{octets[1]}-{octets[2]}-{octets[3]}"

    @staticmethod
    def detect_profile_type(template_label: str) -> str:
        t = template_label.lower()
        if "audio" in t or "av" in t or "visual" in t:
            return "av"
        return "standard"

    # VLAN collections for trunks
    def list_all_vlan_ids(self, data_vlan_id: str, management_ip: str, profile_type: str):
        s = set()
        if data_vlan_id:
            s.add(str(data_vlan_id).strip())

        voice_id, _ = self.get_voice_vlan_info(management_ip)
        if voice_id:
            s.add(str(voice_id).strip())

        # fixed defaults
        s.update(["885", "1001"])

        # profile VLANs
        for vid in self.get_profile_vlans(management_ip, profile_type).keys():
            s.add(str(vid).strip())

        try:
            return sorted(s, key=lambda x: int(x))
        except Exception:
            return sorted(s)

    def generate_trunk_allowed_list(self, data_vlan_id: str, management_ip: str, profile_type: str):
        return ",".join(self.list_all_vlan_ids(data_vlan_id, management_ip, profile_type))


# =============================================================================
# Serial console wrapper
# =============================================================================

class SerialConsole:
    """Thin wrapper around pyserial for reading/writing console output."""

    def __init__(self):
        self.serial_connection = None
        self.is_connected = False
        self.read_thread = None
        self._stop_flag = False

    # ---------- discovery ----------

    def list_ports(self):
        if not serial:
            return []
        return [p.device for p in serial.tools.list_ports.comports()]

    # ---------- lifecycle ----------

    def connect(self, port: str, baudrate: int = 115200, timeout: float = 1.0) -> bool:
        if not serial:
            return False
        try:
            self.serial_connection = serial.Serial(
                port=port,
                baudrate=baudrate,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=timeout,
            )
            self.is_connected = True
            return True
        except Exception:
            return False

    def disconnect(self):
        self._stop_flag = True
        if self.read_thread and self.read_thread.is_alive():
            try:
                self.read_thread.join(timeout=1.0)
            except Exception:
                pass
        if self.serial_connection:
            try:
                self.serial_connection.close()
            except Exception:
                pass
        self.is_connected = False

    # ---------- IO ----------

    def send(self, line: str):
        if self.serial_connection and self.is_connected:
            try:
                self.serial_connection.write((line + "\r\n").encode("utf-8"))
            except Exception:
                pass

    def start_reader(self, callback):
        """Start background read loop; callback(text) for each line."""

        if not self.serial_connection or not self.is_connected:
            return

        def loop():
            while self.is_connected and not self._stop_flag:
                try:
                    if self.serial_connection.in_waiting:
                        data = self.serial_connection.readline().decode(
                            "utf-8", errors="ignore"
                        )
                        if data:
                            callback(data)
                    time.sleep(0.05)
                except Exception:
                    break

        self._stop_flag = False
        self.read_thread = threading.Thread(target=loop, daemon=True)
        self.read_thread.start()


# =============================================================================
# Excel → Netmiko service
# =============================================================================

class ExcelPortApplier:
    """Loads Excel and pushes port configs to Aruba CX via Netmiko."""

    @staticmethod
    def load_excel(path: str):
        if not pd:
            raise RuntimeError("pandas is required to load Excel files")
        df = pd.read_excel(path)
        required = {"port", "vlan", "description"}
        if not required.issubset(df.columns):
            raise ValueError("Excel must contain columns: port, vlan, description")
        return df

    @staticmethod
    def apply_to_device(ip: str, df, console_log):
        if not ConnectHandler:
            console_log("Netmiko is not installed.")
            return

        username = os.environ.get("username")
        password = os.environ.get("passwordAD")

        if not username or not password:
            console_log("Missing env vars 'username' or 'passwordAD'.")
            return

        dev = {
            "device_type": "aruba_aoscx",
            "host": ip,
            "username": username,
            "password": password,
            "timeout": 20,
            "conn_timeout": 15,
            "fast_cli": False,
            "session_log": "netmiko_session.log",
        }

        try:
            console_log(f"Connecting to {ip} via SSH …")
            conn = ConnectHandler(**dev)

            # Learn the *actual* prompt
            prompt = conn.find_prompt()
            console_log(f"Connected. Prompt detected: {prompt}")

            conn.config_mode()
            console_log("Entered config mode.")

        except Exception as e:
            console_log(f"SSH error: {e}")
            return

        # --- APPLY PORT CONFIGS ---
        for idx, row in df.iterrows():
            port = str(row["port"]).strip()
            vlan = str(row["vlan"]).strip()
            desc = str(row["description"]).strip()

            console_log(f"\n--- Row {idx+1} ---")
            console_log(f"Interface {port}  VLAN {vlan}  Description '{desc}'")

            cmds = [
                f"interface {port}",
                f"vlan access {vlan}",
                f"description {desc}",
            ]

            try:
                output = conn.send_config_set(cmds, exit_config_mode=False)
                console_log(output)
            except Exception as e:
                console_log(f"Error: {e}")

        # --- SAVE ---
        try:
            console_log("\nSaving configuration (write memory)…")
            save_out = conn.send_command("write memory", expect_string=r"#")
            console_log(save_out)
        except Exception:
            console_log("Warning: failed to save config.")

        conn.disconnect()
        console_log("\n✔ Excel port configuration completed.")


# =============================================================================
# Main Tkinter Application
# =============================================================================

class SwitchConfigApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Aruba Switch Configuration Tool")

        self.template_mgr = TemplateManager()
        self.net_cfg = NetworkConfig()
        self.serial_console = SerialConsole()
        self.excel_df = None  # loaded port data

        self._build_ui()

    # ---------------- UI construction ----------------

    def _build_ui(self):
        self.root.geometry("880x980")
        main = ttk.Frame(self.root, padding=14)
        main.grid(row=0, column=0, sticky="nsew")

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=1)
        main.columnconfigure(2, weight=1)
        main.columnconfigure(3, weight=1)
        main.rowconfigure(9, weight=1)

        title = ttk.Label(main, text="Aruba Switch Configuration Tool",
                          font=("Segoe UI", 16, "bold"))
        title.grid(row=0, column=0, columnspan=4, pady=(0, 12))

        # --- template + serial ---
        ttk.Label(main, text="Switch Template:").grid(row=1, column=0, sticky="e", padx=4, pady=4)
        self.template_var = tk.StringVar()
        templates = [
            "4100i - Standard",
            "4100i - Audio Visual",
            "6300m - Standard",
            "6300m - Audio Visual",
        ]
        self.template_combo = ttk.Combobox(
            main, textvariable=self.template_var,
            values=templates, state="readonly", width=30
        )
        self.template_combo.grid(row=1, column=1, sticky="ew", padx=4, pady=4)
        self.template_var.set(templates[0])

        ttk.Label(main, text="Serial Number *:").grid(row=1, column=2, sticky="e", padx=4, pady=4)
        self.serial_var = tk.StringVar()
        ttk.Entry(main, textvariable=self.serial_var).grid(row=1, column=3, sticky="ew", padx=4, pady=4)

        # --- mgmt ip + hostname ---
        ttk.Label(main, text="Management IP *:").grid(row=2, column=0, sticky="e", padx=4, pady=4)
        self.mgmt_ip_var = tk.StringVar()
        mgmt_entry = ttk.Entry(main, textvariable=self.mgmt_ip_var)
        mgmt_entry.grid(row=2, column=1, sticky="ew", padx=4, pady=4)

        ttk.Label(main, text="Hostname:").grid(row=2, column=2, sticky="e", padx=4, pady=4)
        self.hostname_var = tk.StringVar()
        ttk.Entry(main, textvariable=self.hostname_var).grid(row=2, column=3, sticky="ew", padx=4, pady=4)

        # --- data vlan ---
        ttk.Label(main, text="Data VLAN ID:").grid(row=3, column=0, sticky="e", padx=4, pady=4)
        self.data_vlan_id_var = tk.StringVar()
        ttk.Entry(main, textvariable=self.data_vlan_id_var).grid(row=3, column=1, sticky="ew", padx=4, pady=4)

        ttk.Label(main, text="Data VLAN Name:").grid(row=3, column=2, sticky="e", padx=4, pady=4)
        self.data_vlan_name_var = tk.StringVar()
        ttk.Entry(main, textvariable=self.data_vlan_name_var).grid(row=3, column=3, sticky="ew", padx=4, pady=4)

        # --- location + MAC ---
        ttk.Label(main, text="Location:").grid(row=4, column=0, sticky="e", padx=4, pady=4)
        self.location_var = tk.StringVar(value=DEFAULT_LOCATION)
        ttk.Entry(main, textvariable=self.location_var).grid(row=4, column=1, sticky="ew", padx=4, pady=4)

        ttk.Label(main, text="MAC Address *:").grid(row=4, column=2, sticky="e", padx=4, pady=4)
        self.mac_var = tk.StringVar()
        ttk.Entry(main, textvariable=self.mac_var).grid(row=4, column=3, sticky="ew", padx=4, pady=4)

        # --- buttons row ---
        btn_frame = ttk.Frame(main)
        btn_frame.grid(row=5, column=0, columnspan=4, pady=6)

        ttk.Button(btn_frame, text="Generate Full Config", command=self.generate_config).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="Load Excel Ports", command=self.load_excel).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="Apply Excel Ports (SSH)", command=self.apply_excel_ports).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="Clear", command=self.clear_all).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="Exit", command=self.root.quit).pack(side=tk.LEFT, padx=4)

        ttk.Label(main, text="* Required fields", foreground="red",
                  font=("Segoe UI", 9, "italic")).grid(row=6, column=0, columnspan=4,
                                                      sticky="w", padx=4, pady=(0, 6))

        # --- output text (config) ---
        ttk.Label(main, text="Generated Config Output:").grid(row=7, column=0, columnspan=4,
                                                              sticky="w", padx=4, pady=(4, 2))
        self.output_text = tk.Text(main, height=10, width=100)
        self.output_text.grid(row=8, column=0, columnspan=4, sticky="nsew", padx=4)
        out_scroll = ttk.Scrollbar(main, orient="vertical", command=self.output_text.yview)
        out_scroll.grid(row=8, column=4, sticky="ns")
        self.output_text.configure(yscrollcommand=out_scroll.set)

        # --- console frame (serial + ssh log) ---
        console = ttk.LabelFrame(main, text="Console / Log", padding=8)
        console.grid(row=9, column=0, columnspan=4, sticky="nsew", pady=(10, 4))
        main.rowconfigure(9, weight=1)

        # serial controls
        ttk.Label(console, text="COM Port:").grid(row=0, column=0, sticky="w")
        self.com_var = tk.StringVar()
        self.com_combo = ttk.Combobox(console, textvariable=self.com_var, width=18, state="readonly")
        self.com_combo.grid(row=0, column=1, padx=4)

        ttk.Button(console, text="Refresh", command=self.refresh_ports).grid(row=0, column=2, padx=4)
        self.btn_connect = ttk.Button(console, text="Connect", command=self.connect_serial)
        self.btn_connect.grid(row=0, column=3, padx=4)
        self.btn_disconnect = ttk.Button(console, text="Disconnect", command=self.disconnect_serial,
                                         state=tk.DISABLED)
        self.btn_disconnect.grid(row=0, column=4, padx=4)
        self.btn_write_cfg = ttk.Button(console, text="Write Full Config over Console",
                                        command=self.write_config_over_console,
                                        state=tk.DISABLED)
        self.btn_write_cfg.grid(row=0, column=5, padx=4)

        # console text
        self.console_text = tk.Text(console, height=15, width=100, bg="black", fg="white")
        self.console_text.grid(row=1, column=0, columnspan=6, sticky="nsew", pady=(6, 4))
        console.rowconfigure(1, weight=1)
        console.columnconfigure(0, weight=1)
        c_scroll = ttk.Scrollbar(console, orient="vertical", command=self.console_text.yview)
        c_scroll.grid(row=1, column=6, sticky="ns")
        self.console_text.configure(yscrollcommand=c_scroll.set)

        # status bar
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(main, textvariable=self.status_var, relief="sunken").grid(
            row=10, column=0, columnspan=4, sticky="ew", pady=(4, 0)
        )

        # bindings
        mgmt_entry.bind("<FocusOut>", lambda e: self.auto_fill_from_ip())
        self.template_combo.bind("<<ComboboxSelected>>", lambda e: self.auto_fill_from_ip())

        # initial COM list
        self.refresh_ports()

    # ---------------- utility logging ----------------

    def log_console(self, text: str):
        self.console_text.insert(tk.END, text + "\n")
        self.console_text.see(tk.END)

    # ---------------- auto-fill hostname + VLAN ----------------

    def auto_fill_from_ip(self):
        ip = self.mgmt_ip_var.get().strip()
        if not ip:
            return
        try:
            ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            self.status_var.set("Invalid IP address")
            return

        try:
            template_label = self.template_var.get()
            hostname = self.net_cfg.generate_hostname(ip, template_label)
            self.hostname_var.set(hostname)

            vid, vname = self.net_cfg.get_data_vlan_info(ip)
            self.data_vlan_id_var.set(vid)
            self.data_vlan_name_var.set(vname)

            self.status_var.set(f"Auto-filled hostname {hostname} and VLAN {vid}.")
        except Exception as e:
            self.status_var.set(f"Auto-fill error: {e}")

    # ---------------- config generation ----------------

    def generate_config(self):
        # required fields
        if not self.mgmt_ip_var.get().strip() or not self.mac_var.get().strip() or not self.serial_var.get().strip():
            messagebox.showerror("Missing Fields", "Management IP, MAC Address and Serial Number are required.")
            return

        ip = self.mgmt_ip_var.get().strip()
        try:
            ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            messagebox.showerror("Invalid IP", "Management IP address is invalid.")
            return

        try:
            template_text = self.template_mgr.load_template(self.template_var.get())
        except Exception as e:
            messagebox.showerror("Template Error", str(e))
            return

        hostname = self.hostname_var.get().strip() or DEFAULT_HOSTNAME
        data_vlan_id = self.data_vlan_id_var.get().strip() or DEFAULT_VLAN_ID
        data_vlan_name = self.data_vlan_name_var.get().strip() or DEFAULT_VLAN_NAME
        location = self.location_var.get().strip() or DEFAULT_LOCATION
        mac = self.mac_var.get().strip()
        serial_no = self.serial_var.get().strip()

        gateway = self.net_cfg.calculate_gateway(ip)
        profile_type = self.net_cfg.detect_profile_type(self.template_var.get())
        profile_vlans = self.net_cfg.get_profile_vlans(ip, profile_type)
        trunk_allowed = self.net_cfg.generate_trunk_allowed_list(data_vlan_id, ip, profile_type)
        voice_id, voice_name = self.net_cfg.get_voice_vlan_info(ip)

        # build profile VLAN text
        profile_vlan_cfg = ""
        for vid, vname in profile_vlans.items():
            profile_vlan_cfg += f"vlan {vid}\n name {vname}\n!\n"

        cfg = template_text

        # replacements
        replace_map = {
            "{{hostname}}": hostname,
            "{{management_ip}}": ip,
            "{{data_vlan_id}}": data_vlan_id,
            "{{data_vlan_name}}": data_vlan_name,
            "{{voice_vlan_id}}": voice_id,
            "{{voice_vlan_name}}": voice_name,
            "{{snmp_location}}": location,
            "{{gateway}}": gateway,
            "{{trunk_allowed_vlans}}": trunk_allowed,
        }
        for k, v in replace_map.items():
            cfg = cfg.replace(k, str(v))

        # optional blocks
        if "{{voice_vlan_block}}" in cfg:
            if voice_id and voice_name:
                vblock = f"vlan {voice_id}\n name {voice_name}\n!\n"
            else:
                vblock = ""
            cfg = cfg.replace("{{voice_vlan_block}}", vblock)

        if "{{profile_vlans}}" in cfg:
            cfg = cfg.replace("{{profile_vlans}}", profile_vlan_cfg)

        # file paths
        cfg_path = OUTPUT_DIR / f"{hostname}.cfg"
        json_path = OUTPUT_DIR / f"{hostname}.json"
        csv_path = OUTPUT_DIR / f"{hostname}.csv"
        api_json_path = OUTPUT_DIR / f"api-{hostname}.json"

        # Central-style JSON
        central_json = {
            serial_no: {
                "_sys_data_vlan_id": data_vlan_id,
                "_sys_data_vlan_name": data_vlan_name,
                "_sys_voice_vlan_id": voice_id,
                "_sys_voice_vlan_name": voice_name,
                "_sys_gateway": gateway,
                "_sys_hostname": hostname,
                "_sys_lan_mac": mac,
                "_sys_location": location,
                "_sys_mgnt_ip": ip,
                "_sys_serial": serial_no,
            }
        }
        for vid, vname in profile_vlans.items():
            central_json[serial_no][f"_sys_{vid}_vlan_name"] = vname

        # write files
        cfg_path.write_text(cfg, encoding="utf-8")
        json_path.write_text(json.dumps(central_json, indent=2), encoding="utf-8")

        with csv_path.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Variable", "Value"])
            for k, v in central_json[serial_no].items():
                w.writerow([k, v])

        api_payload = {"total": len(central_json[serial_no]), "variables": central_json[serial_no]}
        api_json_path.write_text(json.dumps(api_payload, indent=2), encoding="utf-8")

        # show output
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, f"Generated at {ts}\n")
        self.output_text.insert(tk.END, f"Config: {cfg_path}\n")
        self.output_text.insert(tk.END, f"Central JSON: {json_path}\n")
        self.output_text.insert(tk.END, f"CSV: {csv_path}\n")
        self.output_text.insert(tk.END, f"API JSON: {api_json_path}\n\n")
        self.output_text.insert(tk.END, cfg)
        self.output_text.see(tk.END)

        self.status_var.set("Configuration generated.")

    # ---------------- serial console actions ----------------

    def refresh_ports(self):
        ports = self.serial_console.list_ports()
        self.com_combo["values"] = ports
        if ports:
            if self.com_var.get() not in ports:
                self.com_var.set(ports[0])
        else:
            self.com_var.set("")

    def connect_serial(self):
        port = self.com_var.get()
        if not port:
            messagebox.showerror("Serial Error", "Select a COM port.")
            return
        ok = self.serial_console.connect(port)
        if not ok:
            messagebox.showerror("Serial Error", "Failed to open serial port.")
            return
        self.btn_connect.config(state=tk.DISABLED)
        self.btn_disconnect.config(state=tk.NORMAL)
        self.btn_write_cfg.config(state=tk.NORMAL)
        self.status_var.set(f"Connected to {port}")
        self.serial_console.start_reader(lambda d: self.root.after(0, self._append_console, d))

    def _append_console(self, text):
        self.console_text.insert(tk.END, text)
        self.console_text.see(tk.END)

    def disconnect_serial(self):
        self.serial_console.disconnect()
        self.btn_connect.config(state=tk.NORMAL)
        self.btn_disconnect.config(state=tk.DISABLED)
        self.btn_write_cfg.config(state=tk.DISABLED)
        self.status_var.set("Serial disconnected")

    def write_config_over_console(self):
        if not self.serial_console.is_connected:
            messagebox.showerror("Serial Error", "Not connected to console.")
            return

        hostname = self.hostname_var.get().strip() or DEFAULT_HOSTNAME
        cfg_path = OUTPUT_DIR / f"{hostname}.cfg"
        if not cfg_path.exists():
            messagebox.showerror("Missing Config", f"{cfg_path} not found. Generate config first.")
            return

        ser = self.serial_console.serial_connection
        if not ser:
            messagebox.showerror("Serial Error", "Serial connection missing.")
            return

        def read_for(sec=1.0):
            end = time.time() + sec
            buf = ""
            while time.time() < end:
                if ser.in_waiting:
                    buf += ser.read(ser.in_waiting).decode("utf-8", errors="ignore")
                time.sleep(0.1)
            return buf.lower()

        try:
            self.status_var.set("Logging in over console…")
            self.serial_console.send("admin")
            time.sleep(2)

            # basic login loop with blank password + default admin
            for _ in range(30):
                buf = read_for(0.7)
                if "password:" in buf and "configure the 'admin'" not in buf:
                    self.serial_console.send("")  # blank password
                elif "enter new password" in buf or "confirm new password" in buf:
                    self.serial_console.send("")
                elif "#" in buf:
                    break
                time.sleep(0.2)

            # enter config mode
            self.serial_console.send("configure terminal")
            time.sleep(1)

            lines = []
            for line in cfg_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("!"):
                    lines.append(line)

            self.status_var.set(f"Sending {len(lines)} config lines…")
            for i, line in enumerate(lines, start=1):
                self.serial_console.send(line)
                time.sleep(0.1)
                incoming = read_for(0.3)
                if "[y/n]" in incoming or "(y/n)" in incoming:
                    self.serial_console.send("y")
                    time.sleep(0.3)

                if i % 10 == 0:
                    self.status_var.set(f"Sent {i}/{len(lines)} lines…")
                    self.root.update_idletasks()

            # save
            self.serial_console.send("end")
            time.sleep(0.5)
            self.serial_console.send("write memory")
            self.status_var.set("Config sent and saved.")
            messagebox.showinfo("Success", "Configuration sent over console.")
        except Exception as e:
            messagebox.showerror("Console Error", f"Failed to send config:\n{e}")

    # ---------------- Excel / SSH actions ----------------

    def load_excel(self):
        path = filedialog.askopenfilename(
            title="Select Excel Port File",
            filetypes=[("Excel Files", "*.xlsx *.xls")]
        )
        if not path:
            return
        try:
            self.excel_df = ExcelPortApplier.load_excel(path)
            messagebox.showinfo("Excel Loaded", f"Loaded {len(self.excel_df)} rows.")
        except Exception as e:
            messagebox.showerror("Excel Error", str(e))

    def apply_excel_ports(self):
        if self.excel_df is None:
            messagebox.showerror("No Excel", "Load an Excel port file first.")
            return
        ip = self.mgmt_ip_var.get().strip()
        if not ip:
            messagebox.showerror("Missing IP", "Enter Management IP first.")
            return
        try:
            ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            messagebox.showerror("Invalid IP", "Management IP is invalid.")
            return

        def worker():
            ExcelPortApplier.apply_to_device(ip, self.excel_df, self.log_console)
            self.status_var.set("Excel port configuration completed.")

        threading.Thread(target=worker, daemon=True).start()
        self.status_var.set("Applying Excel port configuration (SSH)…")

    # ---------------- misc ----------------

    def clear_all(self):
        self.hostname_var.set("")
        self.mgmt_ip_var.set("")
        self.data_vlan_id_var.set("")
        self.data_vlan_name_var.set("")
        self.location_var.set(DEFAULT_LOCATION)
        self.mac_var.set("")
        self.serial_var.set("")
        self.output_text.delete("1.0", tk.END)
        self.console_text.delete("1.0", tk.END)
        self.excel_df = None
        self.status_var.set("Cleared. Ready.")


# =============================================================================
# Entrypoint
# =============================================================================

if __name__ == "__main__":
    root = tk.Tk()
    app = SwitchConfigApp(root)
    root.mainloop()
