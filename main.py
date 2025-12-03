#!/usr/bin/env python3
"""
Main Tkinter App for Aruba Switch Configuration Tool
Modular Version (Production Ready)
"""

import os
import json
import csv
import ipaddress
import threading
import time
from datetime import datetime
from pathlib import Path

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# ==== Local module imports ====
from services.templates import TemplateManager
from services.network_config import NetworkConfig
from services.serial_console import SerialConsole
from services.excel_apply import ExcelPortApplier
from services.utils import safe_log


# ==== Directories ====

BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = BASE_DIR / "templates"
CONFIG_DIR = BASE_DIR / "config"
OUTPUT_DIR = BASE_DIR / "generated_configs"

TEMPLATE_DIR.mkdir(exist_ok=True)
CONFIG_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)


class SwitchConfigApp:

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Aruba Switch Configuration Tool")

        # core services
        self.template_mgr = TemplateManager(TEMPLATE_DIR)
        self.net_cfg = NetworkConfig(CONFIG_DIR / "network_config.json")
        self.serial_console = SerialConsole()

        # excel data
        self.excel_df = None

        # build UI
        self._build_ui()

    # ---------------------------------------------------------------------
    # UI Construction
    # ---------------------------------------------------------------------

    def _build_ui(self):
        self.root.geometry("900x1000")
        main = ttk.Frame(self.root, padding=15)
        main.grid(row=0, column=0, sticky="nsew")

        self.root.columnconfigure(0, weight=1)
        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=1)
        main.columnconfigure(2, weight=1)
        main.columnconfigure(3, weight=1)
        main.rowconfigure(9, weight=1)

        # Title
        ttk.Label(
            main, text="Aruba Switch Configuration Tool",
            font=("Segoe UI", 16, "bold")
        ).grid(row=0, column=0, columnspan=4, pady=(0, 15))

        # --- Template
        ttk.Label(main, text="Switch Template:").grid(row=1, column=0, sticky="e")
        self.template_var = tk.StringVar()
        templates = self.template_mgr.list_templates()
        self.template_combo = ttk.Combobox(
            main, textvariable=self.template_var,
            values=templates, state="readonly", width=28
        )
        self.template_combo.grid(row=1, column=1, sticky="ew", padx=4)
        self.template_combo.set(templates[0])

        # Serial number
        ttk.Label(main, text="Serial Number *:").grid(row=1, column=2, sticky="e")
        self.serial_var = tk.StringVar()
        ttk.Entry(main, textvariable=self.serial_var).grid(
            row=1, column=3, sticky="ew", padx=4
        )

        # --- Management IP + Hostname
        ttk.Label(main, text="Management IP *:").grid(row=2, column=0, sticky="e")
        self.mgmt_ip_var = tk.StringVar()
        mgmt_entry = ttk.Entry(main, textvariable=self.mgmt_ip_var)
        mgmt_entry.grid(row=2, column=1, sticky="ew", padx=4)

        ttk.Label(main, text="Hostname:").grid(row=2, column=2, sticky="e")
        self.hostname_var = tk.StringVar()
        ttk.Entry(main, textvariable=self.hostname_var).grid(
            row=2, column=3, sticky="ew", padx=4
        )

        # --- Data VLAN
        ttk.Label(main, text="Data VLAN ID:").grid(row=3, column=0, sticky="e")
        self.data_vlan_id_var = tk.StringVar()
        ttk.Entry(main, textvariable=self.data_vlan_id_var).grid(
            row=3, column=1, sticky="ew", padx=4
        )

        ttk.Label(main, text="Data VLAN Name:").grid(row=3, column=2, sticky="e")
        self.data_vlan_name_var = tk.StringVar()
        ttk.Entry(main, textvariable=self.data_vlan_name_var).grid(
            row=3, column=3, sticky="ew", padx=4
        )

        # --- Location + MAC
        ttk.Label(main, text="Location:").grid(row=4, column=0, sticky="e")
        self.location_var = tk.StringVar(value="default_location")
        ttk.Entry(main, textvariable=self.location_var).grid(
            row=4, column=1, sticky="ew", padx=4
        )

        ttk.Label(main, text="MAC Address *:").grid(row=4, column=2, sticky="e")
        self.mac_var = tk.StringVar()
        ttk.Entry(main, textvariable=self.mac_var).grid(
            row=4, column=3, sticky="ew", padx=4
        )

        # --- Buttons Row
        btnf = ttk.Frame(main)
        btnf.grid(row=5, column=0, columnspan=4, pady=10)

        ttk.Button(btnf, text="Generate Full Config", command=self.generate_config).pack(side="left", padx=6)
        ttk.Button(btnf, text="Load Excel Ports", command=self.load_excel).pack(side="left", padx=6)
        ttk.Button(btnf, text="Apply Excel Ports (SSH)", command=self.apply_excel_ports).pack(side="left", padx=6)
        ttk.Button(btnf, text="Clear", command=self.clear_all).pack(side="left", padx=6)
        ttk.Button(btnf, text="Exit", command=self.root.quit).pack(side="left", padx=6)

        # Required note
        ttk.Label(
            main,
            text="* Required fields",
            foreground="red",
            font=("Segoe UI", 9, "italic"),
        ).grid(row=6, column=0, columnspan=4, sticky="w")

        # --- Output (Config)
        ttk.Label(main, text="Generated Config Output:").grid(
            row=7, column=0, columnspan=4, sticky="w"
        )
        self.output_text = tk.Text(main, height=10, width=110)
        self.output_text.grid(row=8, column=0, columnspan=4, sticky="nsew")
        scroll = ttk.Scrollbar(main, orient="vertical", command=self.output_text.yview)
        scroll.grid(row=8, column=4, sticky="ns")
        self.output_text.config(yscrollcommand=scroll.set)

        # --- Console Frame
        console = ttk.LabelFrame(main, text="Console / Log", padding=10)
        console.grid(row=9, column=0, columnspan=4, sticky="nsew")
        main.rowconfigure(9, weight=1)

        ttk.Label(console, text="COM Port:").grid(row=0, column=0, sticky="w")
        self.com_var = tk.StringVar()
        self.com_combo = ttk.Combobox(console, textvariable=self.com_var, width=20, state="readonly")
        self.com_combo.grid(row=0, column=1, padx=4)

        ttk.Button(console, text="Refresh", command=self.refresh_ports).grid(row=0, column=2, padx=4)

        self.btn_connect = ttk.Button(console, text="Connect", command=self.connect_serial)
        self.btn_connect.grid(row=0, column=3, padx=4)

        self.btn_disconnect = ttk.Button(console, text="Disconnect", command=self.disconnect_serial, state="disabled")
        self.btn_disconnect.grid(row=0, column=4, padx=4)

        self.btn_write_cfg = ttk.Button(
            console, text="Write Config Over Console",
            command=self.write_config_over_console,
            state="disabled"
        )
        self.btn_write_cfg.grid(row=0, column=5, padx=4)

        # --- Console output widget
        self.console_text = tk.Text(console, height=16, width=110, bg="black", fg="white")
        self.console_text.grid(row=1, column=0, columnspan=6, sticky="nsew")
        console.rowconfigure(1, weight=1)
        cscroll = ttk.Scrollbar(console, orient="vertical", command=self.console_text.yview)
        cscroll.grid(row=1, column=6, sticky="ns")
        self.console_text.config(yscrollcommand=cscroll.set)

        # --- Status Bar
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(main, textvariable=self.status_var, relief="sunken").grid(
            row=10, column=0, columnspan=4, sticky="ew", pady=(6, 0)
        )

        # Bind auto-fill
        mgmt_entry.bind("<FocusOut>", lambda e: self.auto_fill_from_ip())
        self.template_combo.bind("<<ComboboxSelected>>", lambda e: self.auto_fill_from_ip())

        # Load initial COM list
        self.refresh_ports()

    # ---------------------------------------------------------------------
    # Auto Fill
    # ---------------------------------------------------------------------

    def auto_fill_from_ip(self):
        ip = self.mgmt_ip_var.get().strip()
        if not ip:
            return

        try:
            ipaddress.IPv4Address(ip)
        except Exception:
            self.status_var.set("Invalid IP address")
            return

        # hostname
        hostname = self.net_cfg.generate_hostname(ip, self.template_var.get())
        self.hostname_var.set(hostname)

        # data VLAN
        vid, vname = self.net_cfg.get_data_vlan(ip)
        self.data_vlan_id_var.set(vid)
        self.data_vlan_name_var.set(vname)

        self.status_var.set(f"Auto-filled hostname {hostname} & VLAN {vid}")

    # ---------------------------------------------------------------------
    # Generate Config
    # ---------------------------------------------------------------------

    def generate_config(self):

        # Required fields
        if not self.mgmt_ip_var.get().strip():
            messagebox.showerror("Missing", "Management IP is required.")
            return
        if not self.mac_var.get().strip():
            messagebox.showerror("Missing", "MAC Address is required.")
            return
        if not self.serial_var.get().strip():
            messagebox.showerror("Missing", "Serial Number is required.")
            return

        ip = self.mgmt_ip_var.get().strip()
        try:
            ipaddress.IPv4Address(ip)
        except Exception:
            messagebox.showerror("Invalid IP", "Management IP is invalid.")
            return

        # Load template
        try:
            template_text = self.template_mgr.load_template(self.template_var.get())
        except Exception as e:
            messagebox.showerror("Template Error", str(e))
            return

        # Values
        hostname = self.hostname_var.get().strip()
        data_vlan_id = self.data_vlan_id_var.get().strip()
        data_vlan_name = self.data_vlan_name_var.get().strip()
        location = self.location_var.get().strip()
        mac = self.mac_var.get().strip()
        serial_no = self.serial_var.get().strip()

        gateway = self.net_cfg.get_gateway(ip)
        profile_type = self.net_cfg.detect_profile(self.template_var.get())
        profile_vlans = self.net_cfg.get_profile_vlans(ip, profile_type)
        trunk_allowed = self.net_cfg.build_trunk_list(ip, data_vlan_id, profile_type)
        voice_id, voice_name = self.net_cfg.get_voice_vlan(ip)

        # Build profile VLAN config block
        profile_block = ""
        for vid, vname in profile_vlans.items():
            profile_block += f"vlan {vid}\n name {vname}\n!\n"

        # Perform replacements
        cfg = template_text

        rep = {
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
        for k, v in rep.items():
            cfg = cfg.replace(k, str(v))

        # Optional voice block
        if "{{voice_vlan_block}}" in cfg:
            if voice_id and voice_name:
                vblock = f"vlan {voice_id}\n name {voice_name}\n!\n"
            else:
                vblock = ""
            cfg = cfg.replace("{{voice_vlan_block}}", vblock)

        if "{{profile_vlans}}" in cfg:
            cfg = cfg.replace("{{profile_vlans}}", profile_block)

        # Paths
        cfg_path = OUTPUT_DIR / f"{hostname}.cfg"
        json_path = OUTPUT_DIR / f"{hostname}.json"
        csv_path = OUTPUT_DIR / f"{hostname}.csv"
        api_path = OUTPUT_DIR / f"api-{hostname}.json"

        # Build central-style JSON
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

        # Save files
        cfg_path.write_text(cfg, encoding="utf-8")
        json_path.write_text(json.dumps(central_json, indent=2), encoding="utf-8")

        # CSV
        with csv_path.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Variable", "Value"])
            for k, v in central_json[serial_no].items():
                w.writerow([k, v])

        # API JSON
        api_payload = {
            "total": len(central_json[serial_no]),
            "variables": central_json[serial_no]
        }
        api_path.write_text(json.dumps(api_payload, indent=2), encoding="utf-8")

        # Display
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(
            tk.END,
            f"Generated at {datetime.now()}\n"
            f"CFG: {cfg_path}\nJSON: {json_path}\nCSV: {csv_path}\nAPI JSON: {api_path}\n\n"
        )
        self.output_text.insert(tk.END, cfg)
        self.output_text.see(tk.END)

        self.status_var.set("Configuration generated.")

    # ---------------------------------------------------------------------
    # Serial Console Actions
    # ---------------------------------------------------------------------

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

        if not self.serial_console.connect(port):
            messagebox.showerror("Serial Error", "Failed to open COM port.")
            return

        self.btn_connect.config(state="disabled")
        self.btn_disconnect.config(state="normal")
        self.btn_write_cfg.config(state="normal")
        self.status_var.set(f"Connected to {port}")

        self.serial_console.start_reader(lambda data: safe_log(self.console_text, data))

    def disconnect_serial(self):
        self.serial_console.disconnect()
        self.btn_connect.config(state="normal")
        self.btn_disconnect.config(state="disabled")
        self.btn_write_cfg.config(state="disabled")
        self.status_var.set("Serial disconnected")

    # ---- SEND CONFIG OVER SERIAL ----

    def write_config_over_console(self):
        if not self.serial_console.is_connected:
            messagebox.showerror("Serial", "Not connected to console.")
            return

        hostname = self.hostname_var.get().strip()
        cfg_path = OUTPUT_DIR / f"{hostname}.cfg"
        if not cfg_path.exists():
            messagebox.showerror("Missing", "Generate config first.")
            return

        ser = self.serial_console.ser

        def read_buffer(sec=0.5):
            end = time.time() + sec
            buf = ""
            while time.time() < end:
                if ser.in_waiting:
                    buf += ser.read(ser.in_waiting).decode("utf-8", errors="ignore")
                time.sleep(0.05)
            return buf.lower()

        try:
            self.status_var.set("Logging in…")

            # Aruba default login
            self.serial_console.send("admin")
            time.sleep(1)

            # Login loop
            for _ in range(40):
                buf = read_buffer(0.5)
                if "password:" in buf and "configure the 'admin'" not in buf:
                    self.serial_console.send("")
                elif "enter new password" in buf:
                    self.serial_console.send("")
                elif "confirm new password" in buf:
                    self.serial_console.send("")
                elif "#" in buf:
                    break
                time.sleep(0.2)

            # config mode
            self.serial_console.send("configure terminal")
            time.sleep(1)

            # send lines
            lines = [
                ln.strip() for ln in cfg_path.read_text().splitlines()
                if ln.strip() and not ln.startswith("!")
            ]

            total = len(lines)
            for i, line in enumerate(lines, start=1):
                self.serial_console.send(line)
                time.sleep(0.08)

                buf = read_buffer(0.2)
                if "[y/n]" in buf or "(y/n)" in buf:
                    self.serial_console.send("y")

                if i % 12 == 0:
                    self.status_var.set(f"Sent {i}/{total} lines…")
                    self.root.update_idletasks()

            # save
            self.serial_console.send("end")
            time.sleep(0.4)
            self.serial_console.send("write memory")

            messagebox.showinfo("Success", "Configuration sent over console.")
            self.status_var.set("Config sent and saved.")

        except Exception as e:
            messagebox.showerror("Console Error", str(e))

    # ---------------------------------------------------------------------
    # Excel to SSH
    # ---------------------------------------------------------------------

    def load_excel(self):
        path = filedialog.askopenfilename(
            title="Select Excel File", filetypes=[("Excel Files", "*.xlsx *.xls")]
        )
        if not path:
            return

        try:
            self.excel_df = ExcelPortApplier.load_excel(path)
            messagebox.showinfo("Loaded", f"Loaded {len(self.excel_df)} rows.")
        except Exception as e:
            messagebox.showerror("Excel Error", str(e))

    def apply_excel_ports(self):
        if self.excel_df is None:
            messagebox.showerror("Excel Error", "Load Excel file first.")
            return

        ip = self.mgmt_ip_var.get().strip()
        if not ip:
            messagebox.showerror("Missing", "Enter Management IP.")
            return

        try:
            ipaddress.IPv4Address(ip)
        except:
            messagebox.showerror("Invalid IP", "Management IP is invalid.")
            return

        def worker():
            ExcelPortApplier.apply_to_device(ip, self.excel_df, self.console_text)
            self.status_var.set("Excel port configuration done.")

        threading.Thread(target=worker, daemon=True).start()
        self.status_var.set("Applying Excel config…")

    # ---------------------------------------------------------------------
    # Clear
    # ---------------------------------------------------------------------

    def clear_all(self):
        self.hostname_var.set("")
        self.mgmt_ip_var.set("")
        self.data_vlan_id_var.set("")
        self.data_vlan_name_var.set("")
        self.location_var.set("default_location")
        self.mac_var.set("")
        self.serial_var.set("")
        self.output_text.delete("1.0", tk.END)
        self.console_text.delete("1.0", tk.END)
        self.excel_df = None
        self.status_var.set("Cleared.")


# -------------------------------------------------------------------------
# Entrypoint
# -------------------------------------------------------------------------

if __name__ == "__main__":
    root = tk.Tk()
    app = SwitchConfigApp(root)
    root.mainloop()
