import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import threading
from wirechart import parse_range
from src.log_handler import configure_root_logger, get_log_level, TkinterTextHandler
from src.menu import MenuState, StandardMenuOption, MenuType
from src.rtps_capture import RTPSCapture
from src.rtps_display import RTPSDisplay
from src.rtps_analyze_capture import RTPSAnalyzeCapture
from src.readers.tshark_reader import TsharkReader
from src.shared_utils import create_output_path
import sys
import logging

logger = logging.getLogger('Wirechart')

class WirechartApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Wirechart - Input Configuration")

        self.args = {
            'pcap': tk.StringVar(),
            'output': tk.StringVar(value='output'),
            'no_gui': tk.BooleanVar(),
            'frame_range': tk.StringVar(),
            'console_log_level': tk.StringVar(value='ERROR'),
            'file_log_level': tk.StringVar(value='INFO')
        }

        self.build_input_gui()

    def build_input_gui(self):
        frame = ttk.Frame(self.root, padding=20)
        frame.grid(row=0, column=0)

        ttk.Label(frame, text="PCAP File:").grid(row=0, column=0, sticky="w")
        pcap_entry = ttk.Entry(frame, textvariable=self.args['pcap'], width=40)
        pcap_entry.grid(row=0, column=1)
        ttk.Button(frame, text="Browse", command=self.browse_pcap).grid(row=0, column=2)

        ttk.Label(frame, text="Output Directory:").grid(row=1, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.args['output'], width=40).grid(row=1, column=1)

        # Frame Range
        ttk.Label(frame, text="Frame Range:").grid(row=2, column=0, sticky="w")

        self.args['frame_start'] = tk.StringVar()
        self.args['frame_end'] = tk.StringVar()
        range_frame = ttk.Frame(frame)
        range_frame.grid(row=2, column=1, sticky="w")
        ttk.Entry(range_frame, textvariable=self.args['frame_start'], width=10).grid(row=0, column=0)
        ttk.Label(range_frame, text=":").grid(row=0, column=1)
        ttk.Entry(range_frame, textvariable=self.args['frame_end'], width=10).grid(row=0, column=2)

        ttk.Label(frame, text="Console Log Level:").grid(row=3, column=0, sticky="w")
        ttk.Combobox(frame, textvariable=self.args['console_log_level'],
                     values=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]).grid(row=3, column=1)

        ttk.Label(frame, text="File Log Level:").grid(row=4, column=0, sticky="w")
        ttk.Combobox(frame, textvariable=self.args['file_log_level'],
                     values=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]).grid(row=4, column=1)

        ttk.Checkbutton(frame, text="Disable GUI plotting (--no-gui)", variable=self.args['no_gui']).grid(row=5, column=1, sticky='w')

        ttk.Button(frame, text="Run Analysis", command=self.run_analysis).grid(row=6, column=1, pady=10)

    def browse_pcap(self):
        filename = filedialog.askopenfilename(title="Select PCAP File", filetypes=[("PCAP files", "*.pcap")])
        if filename:
            self.args['pcap'].set(filename)

    def run_analysis(self):
        try:
            output_log_path = create_output_path(self.args['pcap'].get(), self.args['output'].get(), 'log')
            configure_root_logger(
                output_log_path,
                console_level=get_log_level(self.args['console_log_level'].get()),
                file_level=get_log_level(self.args['file_log_level'].get())
            )

            start, finish = None, None
            if self.args['frame_range'].get():
                start, finish = parse_range(self.args['frame_range'].get())

            TsharkReader.get_tshark_version()
            rtps_frames = RTPSCapture()
            rtps_display = RTPSDisplay(self.args['no_gui'].get())
            rtps_frames.extract_rtps_frames(
                TsharkReader.read_pcap,
                self.args['pcap'].get(),
                display_filter='rtps',
                start_frame=start,
                finish_frame=finish
            )
            rtps_analysis = RTPSAnalyzeCapture(rtps_frames)
            rtps_analysis.analyze_capture()

            self.launch_menu_gui(rtps_display, rtps_frames, rtps_analysis)

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def launch_menu_gui(self, display, frames, analysis):
        menu_window = tk.Toplevel(self.root)
        menu_window.title("Wirechart - Menu")

        # Configure resizing grid
        menu_window.columnconfigure(0, weight=1)
        menu_window.columnconfigure(1, weight=1)
        menu_window.rowconfigure(1, weight=1)

        # Labels for text boxes
        left_label = ttk.Label(menu_window, font=('TkDefaultFont', 10, 'bold'))
        left_label.grid(row=0, column=0, padx=5, pady=(5, 0), sticky="w")

        right_label = ttk.Label(menu_window, font=('TkDefaultFont', 10, 'bold'))
        right_label.grid(row=0, column=1, padx=5, pady=(5, 0), sticky="w")

        # Left text box
        left_text = ScrolledText(menu_window, wrap=tk.WORD, width=60, height=50)
        left_text.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

        # Right text box
        right_text = ScrolledText(menu_window, wrap=tk.WORD, width=120, height=50)
        right_text.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)

        # --- Bottom logger output window ---
        logger_label = ttk.Label(menu_window, text="Logger Output", font=('TkDefaultFont', 10, 'bold'))
        logger_label.grid(row=3, column=0, columnspan=2, sticky="w", padx=5)
        logger_output = ScrolledText(menu_window, wrap=tk.WORD, height=8)
        logger_output.grid(row=4, column=0, columnspan=2, sticky="nsew", padx=5, pady=(0, 5))

        menu_window.rowconfigure(4, weight=1)

        # Configure the logger to write to the ScrolledText widget
        gui_handler = TkinterTextHandler(logger_output)
        gui_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        gui_handler.setLevel(logging.ERROR)
        logging.getLogger().addHandler(gui_handler)

        # Ensure the logger is removed when the window is closed
        def on_close():
                logging.getLogger().removeHandler(gui_handler)
                menu_window.destroy()
        menu_window.protocol("WM_DELETE_WINDOW", on_close)

        state = MenuState()

        def update_boxes(left=None, right=None, left_label_text=None, right_label_text=None):
            if left_label_text is not None:
                left_label.config(text=left_label_text)
            if right_label_text is not None:
                right_label.config(text=right_label_text)
            if left is not None:
                left_text.delete(1.0, tk.END)
                left_text.insert(tk.END, left)
            if right is not None:
                right_text.delete(1.0, tk.END)
                right_text.insert(tk.END, right)

        update_boxes(left_label_text="Topics", left=display.print_topics(frames))

        def handle_option(choice):
            try:
                match choice:
                    case "Capture Summary":
                        update_boxes(right_label_text="Capture Summary", right=display.print_capture_summary(frames))
                    case "Stats - Count":
                        update_boxes(right_label_text="Stats (Submessage Count)", right=display.print_stats(analysis))
                    case "Stats - Bytes":
                        update_boxes(right_label_text="Stats (Submessage Bytes)", right=display.print_stats_in_bytes(analysis))
                    case "Bar Chart - Count":
                        display.plot_stats_by_frame_count(analysis, state.plot_discovery, state.scale)
                    case "Bar Chart - Bytes":
                        display.plot_stats_by_frame_length(analysis, state.plot_discovery, state.scale)
                    case "Topology Graph":
                        topic = tk.simpledialog.askstring("Enter Topic", "Enter a topic to plot (leave blank for all):", parent=menu_window)
                        if topic:
                            display.plot_topic_graph(analysis, topic)
                        else:
                            display.plot_multi_topic_graph(analysis)
                    case "Save to Excel":
                        analysis.save_to_excel(self.args['pcap'].get(), self.args['output'].get(), 'PCAPStats')
                    case "Exit":
                        on_close()
            except Exception as e:
                messagebox.showerror("Error", str(e))

        options = [
            "Capture Summary", "Stats - Count", "Stats - Bytes",
            "Bar Chart - Count", "Bar Chart - Bytes", "Topology Graph", "Save to Excel", "Exit"
        ]

        # UI: Action buttons
        button_frame = ttk.Frame(menu_window)
        button_frame.grid(row=2, column=0, columnspan=2, pady=10)

        for opt in options:
            ttk.Button(button_frame, text=opt, command=lambda o=opt: handle_option(o)).pack(side="left", padx=5)

if __name__ == "__main__":
    root = tk.Tk()
    app = WirechartApp(root)
    root.mainloop()
