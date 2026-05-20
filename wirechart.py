##############################################################################################
# (c) 2025-2025 Copyright, Real-Time Innovations, Inc. (RTI) All rights reserved.
#
# RTI grants Licensee a license to use, modify, compile, and create derivative works of the
# software solely for use with RTI Connext DDS. Licensee may redistribute copies of the
# software, provided that all such copies are subject to this license. The software is
# provided "as is", with no warranty of any type, including any warranty for fitness for any
# purpose. RTI is under no obligation to maintain or support the software. RTI shall not be
# liable for any incidental or consequential damages arising out of the use or inability to
# use the software.
#
##############################################################################################

# Third-Party Library Imports
import sys
import tkinter as tk

# Project-Specific Imports
from src.gui.config_gui import ConfigGui


MIN_PYTHON = (3, 11)


def _enforce_minimum_python_version() -> None:
    if sys.version_info < MIN_PYTHON:
        required = ".".join(str(part) for part in MIN_PYTHON)
        current = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        raise SystemExit(
            f"Wirechart requires Python {required} or newer. Current version: {current}."
        )

if __name__ == "__main__":
    _enforce_minimum_python_version()
    root = tk.Tk()
    icon = tk.PhotoImage(file="./img/wirechart_icon.png")
    root.iconphoto(True, icon)
    app = ConfigGui(root)
    root.mainloop()