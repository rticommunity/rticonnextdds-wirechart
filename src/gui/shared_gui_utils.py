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

# Standard Library Imports
from platform import system

def center_window(window, width=None, height=None):
    """
    Centers a Tkinter window (Tk or Toplevel).

    :param window: The window to center (e.g., Tk() or Toplevel()).
    :param width: Desired width. If None, use window's requested width.
    :param height: Desired height. If None, use window's requested height.
    """
    if system() == "Windows":
        window.update_idletasks()  # Ensure accurate measurements

        # Use provided size or the window's actual size
        window_width = width if width else window.winfo_width()
        window_height = height if height else window.winfo_height()

        # Get screen size
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()

        # Calculate position
        x = int((screen_width / 2) - (window_width / 2))
        y = int((screen_height / 2) - (window_height / 2))

        # Apply geometry
        window.geometry(f'{window_width}x{window_height}+{x}+{y}')

def maximize_window(window):
    """
    Maximizes a Tkinter window (Tk or Toplevel).

    :param window: The window to maximize (e.g., Tk() or Toplevel()).
    """
    if system() == "Windows":
        window.state('zoomed')  # Windows
    elif system() == "Linux":
        # root.attributes('-zoomed', True)   # Linux/macOS
        # window.attributes('-fullscreen', True)  # Linux
        pass
    elif system() == "Darwin":  # macOS
        # window.attributes('-fullscreen', True)
        # screen_width = window.winfo_screenwidth()
        # screen_height = window.winfo_screenheight()
        # window.geometry(f"{screen_width}x{screen_height}+0+0")
        pass