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
import argparse

# Local Application Imports
from src.log_handler import configure_root_logger, logging, get_log_level
from src.menu import MenuOption, get_user_menu_choice
from src.rtps_capture import PlotScale, RTPSCapture
from src.rtps_capture_analysis import RTPSCaptureAnalysis
from src.rtps_display import RTPSDisplay
from src.shared_utils import log_env_vars, create_output_path
from src.readers.tshark_reader import TsharkReader

logger = logging.getLogger('Wirechart')

def main():
    parser = argparse.ArgumentParser(description="Extract unique topics from a pcap file.")
    parser.add_argument('--pcap', type=str, required=True, help='Required argument. Specify the PCAP file.')
    parser.add_argument('--output', type=str, default='output', help='Specify an output file for PCAP statistics.')
    parser.add_argument('--no-gui', action='store_true', default=False, help='Disable GUI-based plotting.')
    parser.add_argument('--frame-range', type=str, default=None, help='Specify a range of frames to analyze in the format START:FINISH.')
    parser.add_argument('--console-log-level', type=str, default='ERROR', help='Specify the console log level (DEBUG, INFO, WARNING, *ERROR*, CRITICAL).')
    parser.add_argument('--file-log-level', type=str, default='INFO', help='Specify the file log level (DEBUG, *INFO*, WARNING, ERROR, CRITICAL).')
    args = parser.parse_args()

    # Configure the logger
    configure_root_logger(create_output_path(args.pcap, args.output, 'log'),
                          console_level=get_log_level(args.console_log_level),
                          file_level=get_log_level(args.file_log_level))

    logger.debug(f"Command Arguments: {args}")
    log_env_vars()  # Log environment variables for debugging
    TsharkReader.get_tshark_version()
    logger.always("Starting the PCAP analysis.")

    start, finish = None, None
    if args.frame_range:
        start, finish = parse_range(args.frame_range)

    rtps_frames = RTPSCapture()
    rtps_analysis = RTPSCaptureAnalysis()
    rtps_display = RTPSDisplay(args.no_gui)

    rtps_frames.extract_rtps_frames(TsharkReader.read_pcap,
                                    args.pcap,
                                    display_filter='rtps',
                                    start_frame=start,
                                    finish_frame=finish)
    rtps_analysis.analyze_capture(rtps_frames)  # Analyze the capture

    scale = PlotScale.LINEAR  # Default scale
    plot_discovery = False
    while True:
        menu_choice, scale, plot_discovery, topic = get_user_menu_choice(scale, plot_discovery)
        match menu_choice:
            case MenuOption.PRINT_CAPTURE_SUMMARY:
                rtps_display.print_capture_summary(rtps_frames)
            case MenuOption.PRINT_TOPICS:
                rtps_display.print_topics(rtps_frames)
            case MenuOption.PRINT_STATS_COUNT:
                rtps_display.print_stats(rtps_analysis)
            case MenuOption.PRINT_STATS_BYTES:
                rtps_display.print_stats_in_bytes(rtps_analysis)
            case MenuOption.PLOT_BAR_CHART_COUNT:
                if not args.no_gui:
                    rtps_display.plot_stats_by_frame_count(rtps_analysis, plot_discovery, scale)
            case MenuOption.PLOT_BAR_CHART_BYTES:
                if not args.no_gui:
                    rtps_display.plot_stats_by_frame_length(rtps_analysis, plot_discovery, scale)
            case MenuOption.PLOT_TOPOLOGY_GRAPH:
                if not args.no_gui:
                    if topic:
                        rtps_display.plot_topic_graph(rtps_analysis, topic=topic)
                    else:
                        rtps_display.plot_multi_topic_graph(rtps_analysis)
            case MenuOption.SAVE_EXCEL:
                rtps_analysis.save_to_excel(args.pcap, args.output, 'PCAPStats')
            case MenuOption.EXIT:
                print("Exiting program.")
                break
            case (MenuOption.INVALID |
                  MenuOption.CHANGE_SCALE |
                  MenuOption.TOGGLE_DISCOVERY):
                continue
            case _:
                print("Unrecognized option.")

def parse_range(value: str):
    if ':' not in value:
        logger.error(f"Invalid range format: {value}. Expected format is 'before:after'.  Exiting program.")
        raise ValueError(f"Invalid range format: {value}. Expected format is 'before:after'.")

    before, after = value.split(':', 1)

    def parse_part(part):
        if part == '':
            return None
        if part.isdigit():
            num = int(part)
            if num >= 0:
                return num
            logger.error(f"Invalid positive integer: {part}. Exiting program.")
            raise ValueError(f"Invalid positive integer: {part}. Exiting program.")

    before = parse_part(before)
    after = parse_part(after)
    if before is not None and after is not None and before > after:
        logger.error(f"Invalid range: {value}. 'before' must be less than or equal to 'after'. Exiting program.")
        raise ValueError(f"Invalid range: {value}. 'before' must be less than or equal to 'after'. Exiting program.")

    return before, after

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.error(e)