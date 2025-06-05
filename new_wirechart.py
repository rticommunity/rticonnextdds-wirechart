import tkinter as tk
from src.config_gui import ConfigGui

if __name__ == "__main__":
    root = tk.Tk()
    icon = tk.PhotoImage(file="./img/wirechart_icon.png")
    root.iconphoto(True, icon)
    app = ConfigGui(root)
    root.mainloop()