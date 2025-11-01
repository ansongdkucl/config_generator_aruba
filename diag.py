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
import platform

# Optional/External modules
try:
    import paramiko
except Exception:
    paramiko = None

# Robust pyserial import
try:
    import serial  # from pyserial
    try:
        from serial.tools import list_ports as _list_ports
    except Exception:
        _list_ports = None
    SERIAL_AVAILABLE = True
except Exception:
    serial = None
    _list_ports = None
    SERIAL_AVAILABLE = False

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
    only_hex = "".join(ch for ch in mac if ch.isalnum()).lower()
    return f"{only_hex}.cfg" if only_hex else "config.cfg"

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
        if not SERIAL_AVAILABLE or _list_ports is None:
            return []
        return [p.device for p in _list_ports.comports()]

    def connect(self, port, baudrate=115200, timeout=1):
        if not SERIAL_AVAILABLE:
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
        except Exception as e:
            print(f"Serial connect error: {e}")
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
            except Exception as e:
                print(f"Send error: {e}")
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

# -------- Diagnostic helper ---------
def diagnose_serial_environment():
    info = []
    info.append(f"Platform: {platform.system()} {platform.release()}")
    info.append(f"pyserial available: {SERIAL_AVAILABLE}")
    if not SERIAL_AVAILABLE:
        info.append("Install with: pip install pyserial")
    else:
        try:
            ports = list(_list_ports.comports()) if _list_ports else []
            if ports:
                for p in ports:
                    info.append(f"- {p.device} | {p.description}")
            else:
                info.append("No serial ports detected.")
        except Exception as e:
            info.append(f"Error listing ports: {e}")
    return "\n".join(info)

# -----------------------------
# Example usage for testing
# -----------------------------
if __name__ == "__main__":
    print(diagnose_serial_environment())
    sc = SerialConsole()
    print("Ports found:", sc.get_available_ports())
