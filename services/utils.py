# services/utils.py

import tkinter as tk

def safe_log(widget: tk.Text, text: str):
    """Thread-safe append to a Tkinter Text widget."""
    try:
        widget.insert(tk.END, text + "\n")
        widget.see(tk.END)
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
