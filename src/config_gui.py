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

# Third-Party Library Imports
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Project-Specific Imports
from src.log_handler import configure_root_logger, get_log_level
from src.rtps_capture import RTPSCapture
from src.rtps_display import RTPSDisplay
from src.rtps_analyze_capture import RTPSAnalyzeCapture
from src.readers.tshark_reader import TsharkReader
from src.shared_utils import create_output_path
from src.analysis_gui import AnalysisGui
from src.shared_gui_utils import center_window

logger = logging.getLogger(__name__)

class ConfigGui:
    def __init__(self, root):
        self.root = root
        self.root.title("Wirechart - Input Configuration")

        self.args = {
            'pcap': tk.StringVar(),
            'output': tk.StringVar(value='output'),
            'frame_range': tk.StringVar(),
            'console_log_level': tk.StringVar(value='ERROR'),
            'file_log_level': tk.StringVar(value='INFO')
        }

        self.build_input_gui()

    def build_input_gui(self):
        frame = ttk.Frame(self.root, padding=20)
        frame.grid(row=0, column=0)
        center_window(self.root, width=485, height=194)

        # PCAP File
        ttk.Label(frame, text="PCAP File:").grid(row=0, column=0, sticky="w")
        pcap_entry = ttk.Entry(frame, textvariable=self.args['pcap'], width=40)
        pcap_entry.grid(row=0, column=1, sticky="w", padx=(10, 0))
        ttk.Button(frame, text="Browse", command=self.browse_pcap).grid(row=0, column=2, sticky="w", padx=(10, 0))

        # Output Directory
        ttk.Label(frame, text="Output Directory:").grid(row=1, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.args['output'], width=40).grid(row=1, column=1, sticky="w", padx=(10, 0))

        # Frame Range
        ttk.Label(frame, text="Frame Range:").grid(row=2, column=0, sticky="w")
        self.args['frame_start'] = tk.StringVar()
        self.args['frame_end'] = tk.StringVar()
        range_frame = ttk.Frame(frame)
        range_frame.grid(row=2, column=1, sticky="w", padx=(10, 0))
        ttk.Entry(range_frame, textvariable=self.args['frame_start'], width=10).grid(row=0, column=0, sticky="w")
        ttk.Label(range_frame, text="-").grid(row=0, column=1, padx=5)
        ttk.Entry(range_frame, textvariable=self.args['frame_end'], width=10).grid(row=0, column=2, sticky="w")

        # Console Log Level
        ttk.Label(frame, text="Console Log Level:").grid(row=3, column=0, sticky="w")
        ttk.Combobox(frame, textvariable=self.args['console_log_level'],
                    values=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], width=37).grid(row=3, column=1, sticky="w", padx=(10, 0))

        # File Log Level
        ttk.Label(frame, text="File Log Level:").grid(row=4, column=0, sticky="w")
        ttk.Combobox(frame, textvariable=self.args['file_log_level'],
                    values=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], width=37).grid(row=4, column=1, sticky="w", padx=(10, 0))

        # Run Button
        ttk.Button(frame, text="Run Analysis", command=self.run_analysis).grid(row=5, column=1, pady=10, sticky="w", padx=(10, 0))

    def browse_pcap(self):
        filename = filedialog.askopenfilename(title="Select PCAP File", filetypes=[("PCAP Files", "*.pcap*")])
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

            start = int(self.args['frame_start'].get()) if self.args['frame_start'].get().isdigit() else None
            finish = int(self.args['frame_end'].get()) if self.args['frame_end'].get().isdigit() else None
            if start is not None and finish is not None and start > finish:
                raise ValueError("Start frame cannot be greater than finish frame.")

            TsharkReader.get_tshark_version()
            rtps_frames = RTPSCapture(self.args['pcap'].get())
            rtps_frames.extract_rtps_frames(
                TsharkReader.read_pcap,
                display_filter='rtps',
                start_frame=start,
                finish_frame=finish
            )
            rtps_analysis = RTPSAnalyzeCapture(rtps_frames)
            rtps_analysis.analyze_capture()
            rtps_display = RTPSDisplay()  # Removed the no_gui parameter

            analysis_gui = AnalysisGui(self.root, rtps_frames, rtps_analysis, rtps_display, self.args)
            analysis_gui.launch()

        except Exception as e:
            messagebox.showerror("Error", str(e))