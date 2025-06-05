import tkinter as tk
from src.config_gui import ConfigGui

if __name__ == "__main__":
    root = tk.Tk()
    app = ConfigGui(root)
    root.mainloop()