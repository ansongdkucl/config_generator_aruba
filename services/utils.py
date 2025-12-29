# services/utils.py

import tkinter as tk

def safe_log(widget: tk.Text, text: str):
    """Simple thread-safe append to a Tkinter Text widget."""
    try:
        # Using after(0) is the safest way to schedule a call back to the main thread
        widget.after(0, lambda: [
            widget.insert(tk.END, text + "\n"),
            widget.see(tk.END)
        ])
    except Exception:
        pass


def serial_safe_log(widget: tk.Text, text: str):
    """
    Thread-safe append designed for the continuous output of the serial reader thread.
    (Serial data often includes its own newlines, so we don't add one here.)
    """
    try:
        # Schedule the update to be executed in the main thread
        widget.after(0, lambda: [
            widget.insert(tk.END, text),
            widget.see(tk.END)
        ])
    except Exception:
        pass


def clean_excel_value(value):
    """
    Clean any Excel-loaded value:
    - Remove .0 float artefacts
    - Turn NaN into empty string
    - Strip whitespace
    """
    if value is None:
        return ""

    value = str(value).strip()

    if value.lower() == "nan":
        return ""

    if value.endswith(".0"):
        return value[:-2]

    return value