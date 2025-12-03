# services/serial_console.py

import time
import threading

try:
    import serial
    import serial.tools.list_ports
except Exception:
    serial = None


class SerialConsole:
    """Wrapper around pyserial with async read thread."""

    def __init__(self):
        self.ser = None
        self.is_connected = False
        self.stop_flag = False
        self.thread = None

    def list_ports(self):
        if not serial:
            return []
        return [p.device for p in serial.tools.list_ports.comports()]

    def connect(self, port, baud=115200, timeout=1.0):
        if not serial:
            return False
        try:
            self.ser = serial.Serial(
                port=port, baudrate=baud,
                timeout=timeout, parity=serial.PARITY_NONE,
                bytesize=serial.EIGHTBITS, stopbits=serial.STOPBITS_ONE
            )
            self.is_connected = True
            return True
        except Exception:
            return False

    def disconnect(self):
        self.stop_flag = True
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1)
        if self.ser:
            try:
                self.ser.close()
            except:
                pass
        self.is_connected = False

    def send(self, text):
        if self.ser and self.is_connected:
            try:
                self.ser.write((text + "\r\n").encode("utf-8"))
            except:
                pass

    def start_reader(self, callback):
        if not self.ser:
            return

        def loop():
            while not self.stop_flag and self.is_connected:
                try:
                    if self.ser.in_waiting:
                        data = self.ser.readline().decode("utf-8", errors="ignore")
                        if data:
                            callback(data)
                except:
                    break
                time.sleep(0.05)

        self.stop_flag = False
        self.thread = threading.Thread(target=loop, daemon=True)
        self.thread.start()
