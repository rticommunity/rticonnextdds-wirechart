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
import tkinter as tk

# Project-Specific Imports
from src.gui.config_gui import ConfigGui

if __name__ == "__main__":
    root = tk.Tk()
    icon = tk.PhotoImage(file="./img/wirechart_icon.png")
    root.iconphoto(True, icon)
    app = ConfigGui(root)
    root.mainloop()