# services/excel_apply.py

import os
import pandas as pd
from .utils import safe_log, clean_excel_value

try:
    from netmiko import ConnectHandler
except Exception:
    ConnectHandler = None


class ExcelPortApplier:

    @staticmethod
    def load_excel(path: str):
        # Load file, treating the first row as the header (header=0)
        df = pd.read_excel(path, dtype=str, header=0)
        df = df.fillna("")  # remove NaN

        # --- NEW: Enforce column names for safety check ---
        # Rename the first two columns to 'serial' and 'mgmt_ip' for validation in main.py
        
        # Check if a sufficient number of columns exist before renaming
        current_columns = df.columns.tolist()
        
        # Dictionary for renaming: {old_name: new_name}
        rename_map = {}
        
        if len(current_columns) >= 1:
            rename_map[current_columns[0]] = 'serial'
        if len(current_columns) >= 2:
            rename_map[current_columns[1]] = 'mgmt_ip'
            
        df = df.rename(columns=rename_map)
        # --------------------------------------------------
        
        return df

    @staticmethod
    def apply_to_device(ip: str, df, console_widget):
        if not ConnectHandler:
            safe_log(console_widget, "Netmiko is not installed.")
            return

        username = os.environ.get("username")
        password = os.environ.get("passwordAD")

        if not username or not password:
            safe_log(console_widget, "Missing username or passwordAD environment vars.")
            return

        dev = {
            "device_type": "aruba_aoscx",
            "host": ip,
            "username": username,
            "password": password,
            "session_log": "netmiko_session.log",
            "timeout": 15,
            "conn_timeout": 10,
        }

        safe_log(console_widget, f"Connecting to {ip}…")

        try:
            safe_log(console_widget, f"Connecting to {ip}…")
            conn = ConnectHandler(**dev)
            safe_log(console_widget, f"Connected. Prompt = {conn.find_prompt()}")

            # 💥 ALWAYS enter support-mode
            try:
                conn.send_command("support-mode", expect_string=r"#")
                safe_log(console_widget, "Support-mode enabled.")
            except Exception:
                safe_log(console_widget, "Warning: Could not confirm support-mode.")

            conn.config_mode()
            safe_log(console_widget, "Entered configuration mode.")

        except Exception as e:
            safe_log(console_widget, f"SSH error: {e}")
            return
        # iterate rows
        for idx, row in df.iterrows():
            # The existing logic relies on the column names 'port', 'vlan', 'description'.
            # These columns must be present in the third column onwards (index 2, 3, 4)
            port = clean_excel_value(row.get("port"))
            vlan = clean_excel_value(row.get("vlan"))
            desc = clean_excel_value(row.get("description"))

            if not port or not vlan:
                continue

            safe_log(console_widget, f"\n[{idx+1}] {port}  VLAN {vlan}  DESC '{desc}'")

            cmds = [
                f"interface {port}",
                f"vlan access {vlan}",
                f"description {desc}" if desc else "",
            ]

            try:
                out = conn.send_config_set(cmds, exit_config_mode=False)
                safe_log(console_widget, out)
            except Exception as e:
                safe_log(console_widget, f"Error: {e}")

        try:
            safe_log(console_widget, "Saving config…")
            conn.send_command("write memory", expect_string=r"#")
        except:
            safe_log(console_widget, "Warning: save failed.")

        conn.disconnect()
        safe_log(console_widget, f"Disconnected from {ip}")