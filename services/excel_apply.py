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
        df = pd.read_excel(path, dtype=str)
        df = df.fillna("")  # remove NaN
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
            safe_log(console_widget, "Enabling Aruba Central support-mode…")
            try:
                conn.send_command("aruba-central support-mode", expect_string=r"#")
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
        safe_log(console_widget, "\n✔ Excel port configuration done.")
