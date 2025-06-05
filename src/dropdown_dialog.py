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

import tkinter as tk
from tkinter import ttk, simpledialog

class DropdownDialog(simpledialog.Dialog):
    def __init__(self, parent, title, prompt, options):
        self.prompt = prompt
        self.options = options
        self.selection = None
        super().__init__(parent, title)

    def body(self, master):
        ttk.Label(master, text=self.prompt).grid(row=0, column=0, padx=5, pady=5)

        self.var = tk.StringVar()
        self.dropdown = ttk.Combobox(master, textvariable=self.var, values=self.options, state="readonly", width=64)
        self.dropdown.grid(row=1, column=0, padx=5, pady=5)
        self.dropdown.current(0)  # Set default selection

        return self.dropdown  # initial focus

    def apply(self):
        self.selection = self.var.get()

# Usage example
if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()  # Hide the root window

    options = ["Option 1", "Option 2", "Option 3"]
    dialog = DropdownDialog(root, "Choose an Option", "Please select an option:", options)

    if dialog.selection:
        print("You selected:", dialog.selection)