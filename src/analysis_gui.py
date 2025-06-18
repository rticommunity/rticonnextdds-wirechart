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
import logging
import json
from enum import Enum, auto

# Third-Party Library Imports
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText

# Project-Specific Imports
from src.log_handler import TkinterTextHandler
from src.rtps_display import RTPSDisplay, PlotScale
from src.rtps_analyze_capture import RTPSAnalyzeCapture
from src.shared_utils import create_output_path
from src.wireshark_filters import WiresharkFilters
from src.rtps_capture import RTPSCapture
from src.topic_domain_dropdown_dialog import TopicDomainDropdownDialog
from src.shared_gui_utils import center_window

logger = logging.getLogger('Wirechart')

BUTTON_WIDTH = 18

class MenuAction(Enum):
    CAPTURE_SUMMARY = auto()
    STATS_COUNT = auto()
    STATS_BYTES = auto()
    BAR_COUNT = auto()
    BAR_BYTES = auto()
    TOPOLOGY_GRAPH = auto()
    SHOW_REPAIRS = auto()
    SHOW_DURABLE_REPAIRS = auto()
    SAVE_TO_EXCEL = auto()
    WIRESHARK_UNIQUE_ENDPOINTS = auto()
    WIRESHARK_TOPIC_ENDPOINTS = auto()
    EXPORT_JSON = auto()  # Placeholder for future JSON export functionality
    EXIT = auto()

    def __str__(self):
        return {
            MenuAction.CAPTURE_SUMMARY: "Capture Summary",
            MenuAction.STATS_COUNT: "Stats - Count",
            MenuAction.STATS_BYTES: "Stats - Bytes",
            MenuAction.BAR_COUNT: "Bar Chart - Count",
            MenuAction.BAR_BYTES: "Bar Chart - Bytes",
            MenuAction.TOPOLOGY_GRAPH: "Topology Graph",
            MenuAction.SHOW_REPAIRS: "List Repairs",
            MenuAction.SHOW_DURABLE_REPAIRS: "List Durable Repairs",
            MenuAction.SAVE_TO_EXCEL: "Save to Excel",
            MenuAction.WIRESHARK_UNIQUE_ENDPOINTS: "Unique Endpoints",
            MenuAction.WIRESHARK_TOPIC_ENDPOINTS: "Endpoints Filter",
            MenuAction.EXPORT_JSON: "Export to JSON",
            MenuAction.EXIT: "Exit"
        }[self]

class TextWindowHandles:
    left_label: ttk.Label
    left_text: ScrolledText
    right_label: ttk.Label
    right_text: ScrolledText

    def __init__(self, left_label, left_text, right_label, right_text):
        self.left_label = left_label
        self.left_text = left_text
        self.right_label = right_label
        self.right_text = right_text

    def update_left(self, label_text=None, text=None):
        if label_text is not None:
            self.left_label.config(text=label_text)
        if text is not None:
            self.left_text.config(state='normal')
            self.left_text.delete(1.0, tk.END)
            self.left_text.insert(tk.END, text)
            self.left_text.config(state='disabled')

    def update_right(self, label_text=None, text=None):
        if label_text is not None:
            self.right_label.config(text=label_text)
        if text is not None:
            self.right_text.config(state='normal')
            self.right_text.delete(1.0, tk.END)
            self.right_text.insert(tk.END, text)
            self.right_text.config(state='disabled')

    def clear_left(self):
        self.update_left(label_text="", text="")

    def clear_right(self):
        self.update_right(label_text="", text="")

class AnalysisGui:
    def __init__(self, root: tk.Tk, frames: RTPSCapture, analysis: RTPSAnalyzeCapture, display: RTPSDisplay, args):
        self.root = root
        self.display = display
        self.frames = frames
        self.analysis = analysis
        self.args = args
        self.topics = self.display.print_topics(self.frames)
        self.ws_filters_enabled = True
        try:
            self.wireshark_filters = WiresharkFilters(self.analysis.graph_edges)
        except ValueError:
            self.ws_filters_enabled = False

    def launch(self):
        menu_window = tk.Toplevel(self.root)
        menu_window.title(f"{self.args['pcap'].get()} - Analysis")
        center_window(menu_window, width=1598, height=1074)

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
        left_text = ScrolledText(menu_window, wrap=tk.WORD, width=64, height=50, state="disabled")
        left_text.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

        # Right text box
        right_text = ScrolledText(menu_window, wrap=tk.WORD, width=128, height=50, state="disabled")
        right_text.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)

        text_handles = TextWindowHandles(left_label, left_text, right_label, right_text)

        # Add Boolean options side-by-side above the logger box
        checkbox_frame = ttk.Frame(menu_window)
        checkbox_frame.grid(row=2, column=0, columnspan=2, sticky="w", padx=5, pady=5)

        plot_discovery = tk.BooleanVar(value=False)
        log_scale = tk.BooleanVar(value=False)
        ttk.Checkbutton(checkbox_frame, text="Include Discovery Traffic", variable=plot_discovery).pack(side="left", padx=10)
        ttk.Checkbutton(checkbox_frame, text="Use Log Scale", variable=log_scale).pack(side="left", padx=0)

        # Logger Window
        logger_label = ttk.Label(menu_window, text="Logger Output", font=('TkDefaultFont', 10, 'bold'))
        logger_label.grid(row=4, column=0, columnspan=2, sticky="w", padx=5)
        logger_output = ScrolledText(menu_window, wrap=tk.WORD, height=5)
        logger_output.grid(row=5, column=0, columnspan=2, sticky="nsew", padx=5, pady=(0, 5))
        menu_window.rowconfigure(5, weight=1)

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

        text_handles.update_left(label_text=f"{len(self.topics)} Topic{'s' if len(self.topics) != 1 else ''} Found",
                                 text="\n".join(self.topics))

        def handle_option(choice):
            try:
                match choice:
                    case MenuAction.CAPTURE_SUMMARY:
                        text_handles.update_right("Capture Summary", self.display.print_capture_summary(self.frames))
                    case MenuAction.STATS_COUNT:
                        text_handles.update_right("Stats (Submessage Count)", self.display.print_stats(self.analysis))
                    case MenuAction.STATS_BYTES:
                        text_handles.update_right("Stats (Submessage Bytes)", self.display.print_stats_in_bytes(self.analysis))
                    case MenuAction.BAR_COUNT:
                        self.display.plot_stats_by_frame_count(self.analysis, plot_discovery.get(),
                                                            PlotScale.LOGARITHMIC if log_scale.get() else PlotScale.LINEAR)
                    case MenuAction.BAR_BYTES:
                        self.display.plot_stats_by_frame_length(self.analysis, plot_discovery.get(),
                                                            PlotScale.LOGARITHMIC if log_scale.get() else PlotScale.LINEAR)
                    case MenuAction.TOPOLOGY_GRAPH:
                        dialog = TopicDomainDropdownDialog(menu_window, self.analysis.graph_edges)
                        if dialog.user_ok():
                            topic = dialog.topic_selected
                            domain = dialog.domain_selected
                            if topic is None or domain is None:
                                self.display.plot_multi_topic_graph(self.analysis, topic=topic, domain=domain)
                            else:
                                self.display.plot_topic_graph(self.analysis, topic=topic, domain=domain)
                    case MenuAction.SHOW_REPAIRS:
                        repairs = self.frames.list_repairs()
                        repair_string = "\n".join(str(obj) for obj in repairs)
                        text_handles.update_right("Repair Samples",
                                                  repair_string if repair_string else "No repairs found.")
                    case MenuAction.SHOW_DURABLE_REPAIRS:
                        durable_repairs = self.frames.list_durable_repairs()
                        durable_repair_string = "\n".join(str(obj) for obj in durable_repairs)
                        text_handles.update_right("Durable Repair Samples",
                                                  durable_repair_string if durable_repair_string else "No durable repairs found.")
                    case MenuAction.SAVE_TO_EXCEL:
                        self.analysis.save_to_excel(self.args['pcap'].get(), self.args['output'].get(), 'PCAPStats')
                    case MenuAction.WIRESHARK_UNIQUE_ENDPOINTS:
                        dialog = TopicDomainDropdownDialog(menu_window, self.analysis.graph_edges)
                        if dialog.user_ok():
                            topic = dialog.topic_selected
                            domain = dialog.domain_selected
                            text_handles.update_right(f"Unique Endpoints for Topic: {'ALL' if topic is None else topic},"
                                                      f" Domain: {'ALL' if domain is None else domain}",
                                                      self.wireshark_filters.print_all_unique_endpoints(topic=topic, domain=domain))
                        else:
                            text_handles.clear_right()
                    case MenuAction.WIRESHARK_TOPIC_ENDPOINTS:
                        dialog = TopicDomainDropdownDialog(menu_window, self.analysis.graph_edges)
                        if dialog.user_ok():
                            topic = dialog.topic_selected
                            domain = dialog.domain_selected
                            text_handles.update_right(f"Wireshark Endpoint Filter for Topic: {'ALL' if topic is None else topic},"
                                                      f" Domain: {'ALL' if domain is None else domain}",
                                                      self.wireshark_filters.all_endpoints_filter(topic=topic, domain=domain))
                        else:
                            text_handles.clear_right()
                    case MenuAction.EXPORT_JSON:
                        output = create_output_path(str(self.args['pcap'].get()), str(self.args['output'].get()), 'json')
                        data = self.analysis.to_json()
                        try:
                            with open(output, 'w') as f:
                                json.dump(data, f, indent=2)
                            messagebox.showinfo("Export Successful", f"Data exported to {output}")
                        except Exception as e:
                            messagebox.showerror("Export Failed", f"Failed to export data to {output}. Error: {str(e)}")
                    case MenuAction.EXIT:
                        on_close()
            except Exception as e:
                messagebox.showerror("Error", str(e))

        # Standard Buttons
        options = [
            MenuAction.CAPTURE_SUMMARY,
            MenuAction.STATS_COUNT,
            MenuAction.STATS_BYTES,
            MenuAction.BAR_COUNT,
            MenuAction.BAR_BYTES,
            MenuAction.TOPOLOGY_GRAPH,
            MenuAction.SHOW_REPAIRS,
            MenuAction.SHOW_DURABLE_REPAIRS
        ]
        standard_button_frame = ttk.Frame(menu_window)
        standard_button_frame.grid(row=3, column=0, columnspan=2, sticky="w", padx=5, pady=0)
        AnalysisGui._create_buttons(standard_button_frame, options, handle_option)

        # Wireshark Buttons
        options = [
            MenuAction.WIRESHARK_UNIQUE_ENDPOINTS,
            MenuAction.WIRESHARK_TOPIC_ENDPOINTS
        ]
        wireshark_button_frame = ttk.Frame(menu_window)
        wireshark_button_frame.grid(row=4, column=0, columnspan=2, sticky="w", padx=5, pady=10)
        AnalysisGui._create_buttons(wireshark_button_frame, options, handle_option, enable=self.ws_filters_enabled)

        # Save_Excel and Exit button
        options = [
            MenuAction.EXPORT_JSON,
            MenuAction.SAVE_TO_EXCEL,
            MenuAction.EXIT
        ]
        exit_button_frame = ttk.Frame(menu_window)
        exit_button_frame.grid(row=6, column=0, columnspan=2, sticky="e", padx=5, pady=10)
        AnalysisGui._create_buttons(exit_button_frame, options, handle_option)

    @staticmethod
    def _set_button_state(frame: ttk.Frame, state: bool):
        for widget in frame.winfo_children():
            if isinstance(widget, ttk.Button):
                widget.config(state="disabled" if state else "normal")

    @staticmethod
    def _create_buttons(frame: ttk.Frame, options: list[MenuAction], command: callable, enable: bool = True):
        for opt in options:
            ttk.Button(
                frame,
                text=str(opt),  # Uses __str__ if defined, otherwise .name
                command=lambda o=opt: command(o),
                state="normal" if enable else "disabled",
                width=BUTTON_WIDTH
            ).pack(side="left", padx=5)