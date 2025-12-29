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
        
        # New variable for Excel Tab Status
        self.excel_status_var = tk.StringVar(value="No Excel file loaded.") 

        # build UI
        self._build_ui()

    # ---------------------------------------------------------------------
    # UI Construction Helpers
    # ---------------------------------------------------------------------

    def _create_input_field(self, parent_frame, row, label_text, var, callback=None):
        """Helper to create a label and entry pair."""
        ttk.Label(parent_frame, text=label_text).grid(row=row, column=0, sticky="w", padx=5, pady=2)
        entry = ttk.Entry(parent_frame, textvariable=var, width=35)
        entry.grid(row=row, column=1, sticky="ew", padx=5, pady=2)
        
        # Bind the callback function (e.g., for auto-filling)
        if callback:
            # Bind to key release to trigger the callback after typing
            entry.bind("<KeyRelease>", lambda event: callback())
        
        return entry

    # ---------------------------------------------------------------------
    # UI Construction
    # ---------------------------------------------------------------------

    def _build_ui(self):
        # --- Main Layout Frames ---
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky="nsew")
        
        # 1. Control Panel (Left Frame)
        self.control_frame = ttk.LabelFrame(self.main_frame, text="Configuration Input", padding="10")
        self.control_frame.grid(row=0, column=0, padx=10, pady=5, sticky="n")
        
        # 2. Notebook (Right Widget)
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.grid(row=0, column=1, padx=10, pady=5, sticky="nsew")

        # Configure weights for resizing
        self.main_frame.grid_columnconfigure(1, weight=1)
        self.main_frame.grid_rowconfigure(0, weight=1)

        # --- Tab Frames (for the Notebook) ---
        self.config_tab = ttk.Frame(self.notebook, padding="10")
        self.excel_tab = ttk.Frame(self.notebook, padding="10")
        self.log_tab = ttk.Frame(self.notebook, padding="10")

        self.notebook.add(self.config_tab, text="1. Configuration Output")
        self.notebook.add(self.excel_tab, text="2. Excel Port Applier")
        self.notebook.add(self.log_tab, text="3. Device Console / Log")

        self.config_tab.columnconfigure(0, weight=1)
        self.config_tab.rowconfigure(0, weight=1)
        self.log_tab.columnconfigure(0, weight=1)
        self.log_tab.rowconfigure(0, weight=1)
        self.excel_tab.columnconfigure(0, weight=1)
        
        # --- Variables ---
        self.hostname_var = tk.StringVar()
        self.mgmt_ip_var = tk.StringVar()
        self.data_vlan_id_var = tk.StringVar(value="12")
        self.data_vlan_name_var = tk.StringVar()
        self.location_var = tk.StringVar(value="default_location")
        self.mac_var = tk.StringVar()
        self.serial_var = tk.StringVar()
        self.template_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready.")

        # --- A. Control Panel (Inputs) ---
        
        # Hostname, IP, Serial, MAC, Location
        self._create_input_field(self.control_frame, 0, "Hostname:", self.hostname_var, self._auto_fill_data_vlan)
        self._create_input_field(self.control_frame, 1, "Mgmt IP:", self.mgmt_ip_var, self._auto_fill_data_vlan)
        self._create_input_field(self.control_frame, 2, "Serial No:", self.serial_var)
        self._create_input_field(self.control_frame, 3, "MAC:", self.mac_var)
        self._create_input_field(self.control_frame, 4, "Location:", self.location_var)

        # VLANs
        ttk.Separator(self.control_frame, orient='horizontal').grid(row=5, column=0, columnspan=2, sticky='ew', pady=10)
        ttk.Label(self.control_frame, text="Data VLAN ID:").grid(row=6, column=0, sticky="w", padx=5, pady=2)
        ttk.Entry(self.control_frame, textvariable=self.data_vlan_id_var, width=15).grid(row=6, column=1, sticky="ew", padx=5, pady=2)
        self._create_input_field(self.control_frame, 7, "Data VLAN Name:", self.data_vlan_name_var)
        
        # Template
        ttk.Separator(self.control_frame, orient='horizontal').grid(row=8, column=0, columnspan=2, sticky='ew', pady=10)
        ttk.Label(self.control_frame, text="Template:").grid(row=9, column=0, sticky="w", padx=5, pady=2)
        templates = self.template_mgr.list_templates()
        if templates:
            self.template_var.set(templates[0])
            ttk.Combobox(self.control_frame, textvariable=self.template_var, values=templates, state="readonly", width=30).grid(row=9, column=1, sticky="ew", padx=5, pady=2)
        
        # --- B. Action Buttons (Bottom of Control Panel) ---
        self.button_frame = ttk.Frame(self.control_frame)
        self.button_frame.grid(row=10, column=0, columnspan=2, pady=15)

        self.generate_button = ttk.Button(self.button_frame, text="Generate Config", command=self.generate_config)
        self.generate_button.grid(row=0, column=0, padx=5, pady=5)
        
        self.clear_button = ttk.Button(self.button_frame, text="Clear All", command=self.clear_all)
        self.clear_button.grid(row=0, column=1, padx=5, pady=5)
        
        # --- C. Status Bar ---
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor="w")
        self.status_bar.grid(row=1, column=0, columnspan=2, sticky="ew")

        # --- D. Tab 1: Configuration Output Widgets ---
        self.output_text = tk.Text(self.config_tab, wrap="none", height=30, width=80, font=('Consolas', 10))
        self.output_text.grid(row=0, column=0, sticky="nsew")
        
        self.output_scroll_y = ttk.Scrollbar(self.config_tab, orient=tk.VERTICAL, command=self.output_text.yview)
        self.output_scroll_y.grid(row=0, column=1, sticky="ns")
        self.output_text.config(yscrollcommand=self.output_scroll_y.set)

        self.output_scroll_x = ttk.Scrollbar(self.config_tab, orient=tk.HORIZONTAL, command=self.output_text.xview)
        self.output_scroll_x.grid(row=1, column=0, sticky="ew")
        self.output_text.config(xscrollcommand=self.output_scroll_x.set)

        # --- E. Tab 2: Excel Port Applier Widgets (UPDATED) ---
        self.excel_tab.grid_rowconfigure(5, weight=1) # Configure row for Treeview

        self.excel_action_frame = ttk.Frame(self.excel_tab, padding="10")
        self.excel_action_frame.grid(row=0, column=0, sticky="ew")
        self.excel_tab.grid_columnconfigure(0, weight=1)

        self.load_excel_button = ttk.Button(self.excel_action_frame, text="Load Excel File", command=self.load_excel)
        self.load_excel_button.pack(side=tk.LEFT, padx=10)

        self.apply_excel_button = ttk.Button(self.excel_action_frame, text="Apply Excel Config to Device", command=self.apply_excel_ports)
        self.apply_excel_button.pack(side=tk.LEFT, padx=10)
        
        ttk.Separator(self.excel_tab, orient='horizontal').grid(row=1, column=0, sticky='ew', pady=10)
        
        ttk.Label(self.excel_tab, text="Excel Data Status:").grid(row=2, column=0, sticky="w", padx=10, pady=5)
        ttk.Label(self.excel_tab, textvariable=self.excel_status_var, relief=tk.GROOVE, anchor="w", padding=5).grid(row=3, column=0, sticky="ew", padx=10, pady=5)
        
        ttk.Label(self.excel_tab, text="Excel Data Preview (First 50 Rows, 5 Columns):").grid(row=4, column=0, sticky="w", padx=10, pady=5)

        # Treeview for Data Preview
        self.excel_tree_frame = ttk.Frame(self.excel_tab)
        self.excel_tree_frame.grid(row=5, column=0, sticky="nsew", padx=10, pady=5)
        self.excel_tree_frame.grid_columnconfigure(0, weight=1)
        self.excel_tree_frame.grid_rowconfigure(0, weight=1)

        self.excel_tree = ttk.Treeview(self.excel_tree_frame, show="headings")
        self.excel_tree.grid(row=0, column=0, sticky="nsew")

        self.excel_tree_scroll_y = ttk.Scrollbar(self.excel_tree_frame, orient=tk.VERTICAL, command=self.excel_tree.yview)
        self.excel_tree_scroll_y.grid(row=0, column=1, sticky="ns")
        self.excel_tree.configure(yscrollcommand=self.excel_tree_scroll_y.set)

        self.excel_tree_scroll_x = ttk.Scrollbar(self.excel_tree_frame, orient=tk.HORIZONTAL, command=self.excel_tree.xview)
        self.excel_tree_scroll_x.grid(row=1, column=0, sticky="ew")
        self.excel_tree.configure(xscrollcommand=self.excel_tree_scroll_x.set)

        # --- F. Tab 3: Console Log Widgets ---
        self.console_text = tk.Text(self.log_tab, wrap="word", height=25, width=80, font=('Consolas', 10))
        self.console_text.grid(row=0, column=0, sticky="nsew")

        self.console_scroll = ttk.Scrollbar(self.log_tab, orient=tk.VERTICAL, command=self.console_text.yview)
        self.console_scroll.grid(row=0, column=1, sticky="ns")
        self.console_text.config(yscrollcommand=self.console_scroll.set)
        
        # Initial focus on the input IP field
        self.mgmt_ip_var.trace_add("write", lambda name, index, mode: self._auto_fill_hostname())
        self.mgmt_ip_var.trace_add("write", lambda name, index, mode: self._auto_fill_data_vlan())

    # ---------------------------------------------------------------------
    # Auto Fill (Unified Logic)
    # ---------------------------------------------------------------------

    def _auto_fill_from_ip_logic(self):
        ip = self.mgmt_ip_var.get().strip()
        if not ip:
            return

        try:
            ipaddress.IPv4Address(ip)
        except Exception:
            # self.status_var.set("Invalid IP address") # Removed to prevent flicker on every keystroke
            return

        # hostname
        hostname = self.net_cfg.generate_hostname(ip, self.template_var.get())
        self.hostname_var.set(hostname)

        # data VLAN
        vid, vname = self.net_cfg.get_data_vlan(ip)
        self.data_vlan_id_var.set(vid)
        self.data_vlan_name_var.set(vname)

        # self.status_var.set(f"Auto-filled hostname {hostname} & VLAN {vid}")

    def _auto_fill_hostname(self):
        self._auto_fill_from_ip_logic()

    def _auto_fill_data_vlan(self):
        self._auto_fill_from_ip_logic()

    # ---------------------------------------------------------------------
    # Excel Preview
    # ---------------------------------------------------------------------
    
    def _update_excel_preview(self, df):
        """Populates the Treeview widget with the first few rows of the DataFrame."""
        # Clear existing data
        self.excel_tree.delete(*self.excel_tree.get_children())
        
        # Determine columns to display (limit to first 5 for preview)
        columns = df.columns.tolist()
        display_columns = columns[:5]
        
        # Configure the Treeview
        self.excel_tree['columns'] = display_columns
        self.excel_tree.column("#0", width=0, stretch=tk.NO) # Hide first dummy column
        
        for col in display_columns:
            # Set heading and a minimum width
            self.excel_tree.heading(col, text=col.upper(), anchor=tk.CENTER)
            self.excel_tree.column(col, anchor=tk.W, width=120, minwidth=50)

        # Insert data rows (limit to 50 rows for performance/preview)
        for i, row in df.head(50).iterrows():
            values = [row[col] for col in display_columns]
            # Truncate strings for display
            display_values = [str(v)[:40] for v in values]
            self.excel_tree.insert("", tk.END, values=display_values)

        if len(df) > 50:
            self.excel_tree.insert("", tk.END, values=["...", "...", "...", "...", "..."])


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

        # ------------------------------
        # DISPLAY IN OUTPUT BOX
        # ------------------------------
        self.output_text.delete("1.0", tk.END)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # HEADER
        self.output_text.insert(tk.END, f"Generated at {ts}\n\n")

        # CFG BLOCK
        self.output_text.insert(tk.END, "=====================\n")
        self.output_text.insert(tk.END, "  FULL CONFIG (.cfg)\n")
        self.output_text.insert(tk.END, "=====================\n\n")
        self.output_text.insert(tk.END, cfg + "\n\n")

        # JSON BLOCK
        self.output_text.insert(tk.END, "=====================\n")
        self.output_text.insert(tk.END, "      JSON OUTPUT\n")
        self.output_text.insert(tk.END, "=====================\n\n")
        pretty_json = json.dumps(central_json, indent=4)
        self.output_text.insert(tk.END, pretty_json + "\n\n")

        # CSV TABLE BLOCK
        self.output_text.insert(tk.END, "=====================\n")
        self.output_text.insert(tk.END, "      CSV TABLE\n")
        self.output_text.insert(tk.END, "=====================\n\n")

        # *** MODIFIED SECTION FOR IMPROVED VISUAL ALIGNMENT ***
        table = "Variable".ljust(45) + "Value\n"
        table += "-" * 78 + "\n"

        for k, v in central_json[serial_no].items():
            table += k.ljust(45) + str(v) + "\n"

        self.output_text.insert(tk.END, table + "\n")
        # ********************************************************

        self.output_text.see(tk.END)
        self.status_var.set("Configuration generated.")

    # ---------------------------------------------------------------------
    # Serial Console Actions
    # ---------------------------------------------------------------------

    # ... (Serial console methods remain here) ...
    # Placeholder for missing methods, assuming they are complete in full file

    def refresh_ports(self):
        ports = self.serial_console.list_ports()
        # Assumes com_combo exists, not in provided code
        # self.com_combo["values"] = ports
        # if ports:
        #     if self.com_var.get() not in ports:
        #         self.com_var.set(ports[0])
        # else:
        #     self.com_var.set("")
        pass

    def connect_serial(self):
        # Assumes serial connection widgets exist, not in provided code
        pass

    def disconnect_serial(self):
        # Assumes serial connection widgets exist, not in provided code
        pass

    def write_config_over_console(self):
        # Assumes serial connection widgets exist, not in provided code
        pass


    # ---------------------------------------------------------------------
    # Excel to SSH
    # ---------------------------------------------------------------------

    def load_excel(self):
        # Open file dialog
        file_path = filedialog.askopenfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel files", "*.xlsx")],
            title="Select Port Configuration Excel File",
        )
        if not file_path:
            return

        try:
            # Load the data and store DataFrame.
            # load_excel in excel_apply.py now ensures the first two columns are named 'serial' and 'mgmt_ip'.
            self.excel_df = ExcelPortApplier.load_excel(file_path)
            
            # Update Treeview preview
            self._update_excel_preview(self.excel_df) 

            # --- MODIFIED LINE ---
            num_ports = len(self.excel_df)
            self.excel_status_var.set(f"Loaded {num_ports} rows from: {Path(file_path).name}. Preview loaded.")
            # ---------------------
            
            self.status_var.set("Excel port configuration loaded.")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to load Excel file: {e}")
            self.excel_df = None
            self.excel_status_var.set("Error loading file.") # Also update dedicated status
            # Clear preview on error
            self.excel_tree.delete(*self.excel_tree.get_children())


    def apply_excel_ports(self):
        if self.excel_df is None:
            messagebox.showerror("Excel Error", "Load Excel file first.")
            return

        ip = self.mgmt_ip_var.get().strip()
        serial_no = self.serial_var.get().strip() # Get Serial from UI

        if not ip:
            messagebox.showerror("Missing", "Enter Management IP.")
            return
        
        if not serial_no: # Safety: ensure serial is also entered in the UI
            messagebox.showerror("Missing", "Enter Serial Number.")
            return

        try:
            ipaddress.IPv4Address(ip)
        except:
            messagebox.showerror("Invalid IP", "Management IP is invalid.")
            return

        # ----------------------------------------------------
        # NEW: Safety Check - Ensure Serial and IP match ALL rows
        # ----------------------------------------------------
        df = self.excel_df
        
        # Check if required columns exist (forced in load_excel, but good to check)
        if 'serial' not in df.columns or 'mgmt_ip' not in df.columns:
             messagebox.showerror("Validation Error", "The Excel file is missing the 'serial' and/or 'mgmt_ip' columns (first two columns of the loaded sheet).")
             return

        # Check if all values in the 'serial' column match the UI serial number
        # Need to cast df['serial'] to string just in case
        mismatched_serial = df[df['serial'].astype(str) != serial_no]
        if not mismatched_serial.empty:
            messagebox.showerror("Validation Error", f"Serial Number mismatch in Excel data. Expected '{serial_no}'. Found {len(mismatched_serial)} mismatched entries. Check rows: {mismatched_serial.index.tolist()[:5]}")
            return

        # Check if all values in the 'mgmt_ip' column match the UI Mgmt IP
        # Need to cast df['mgmt_ip'] to string just in case
        mismatched_ip = df[df['mgmt_ip'].astype(str) != ip]
        if not mismatched_ip.empty:
            messagebox.showerror("Validation Error", f"Management IP mismatch in Excel data. Expected '{ip}'. Found {len(mismatched_ip)} mismatched entries. Check rows: {mismatched_ip.index.tolist()[:5]}")
            return
        # ----------------------------------------------------
        
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
        self.excel_status_var.set("No Excel file loaded.")
        self.excel_tree.delete(*self.excel_tree.get_children())
        self.status_var.set("Cleared.")


# -------------------------------------------------------------------------
# Entrypoint
# -------------------------------------------------------------------------

if __name__ == "__main__":
    root = tk.Tk()
    app = SwitchConfigApp(root)
    root.mainloop()