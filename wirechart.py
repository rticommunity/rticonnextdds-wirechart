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
import subprocess

# Local Application Imports
from src.log_handler import configure_root_logger, logging
from src.menu import MenuOption, get_user_menu_choice
from src.rtps_capture import PlotScale, RTPSCapture
from src.shared_utils import create_output_path

logger = logging.getLogger('Wirechart')

def main():
    parser = argparse.ArgumentParser(description="Extract unique topics from a pcap file.")
    parser.add_argument('--pcap', type=str, required=True, help='Required argument. Specify the PCAP file.')
    parser.add_argument('--output', type=str, default='output', help='Specify an output file for PCAP statistics.')
    parser.add_argument('--no-gui', action='store_true', default=False, help='Disable GUI-based plotting.')
    parser.add_argument('--frame-range', type=str, default=None, help='Specify a range of frames to analyze in the format START:FINISH.')
    args = parser.parse_args()
    # Configure the logger
    configure_root_logger(create_output_path(args.pcap, args.output, 'log'))

    logger.debug(f"Command Arguments: {args}")
    get_tshark_version()
    logger.always("Starting the PCAP analysis.")

    start, finish = None, None
    if args.frame_range:
        start, finish = parse_range(args.frame_range)

    # tshark seems to return commands in a hierarchy, i.e. frame -> udp -> rtps so order matters
    pcap_fields = list(['frame.number',
                        'ip.src', 'ip.dst', 'udp.length',
                        'rtps.guidPrefix.src', 'rtps.sm.wrEntityId',        # Writer GUID
                        'rtps.guidPrefix.dst', 'rtps.sm.rdEntityId',        # Reader GUID
                        'rtps.sm.seqNumber', 'rtps.sm.octetsToNextHeader',
                        'rtps.sm.id', '_ws.col.Info'])

    rtps_frames = RTPSCapture(args.pcap, pcap_fields, 'rtps', start_frame=start, finish_frame=finish)
    rtps_frames.analyze_capture()  # Analyze the capture

    scale = PlotScale.LINEAR  # Default scale
    plot_discovery = False
    while True:
        menu_choice, scale, plot_discovery, topic = get_user_menu_choice(scale, plot_discovery)
        match menu_choice:
            case MenuOption.PRINT_CAPTURE_SUMMARY:
                rtps_frames.print_capture_summary()
            case MenuOption.PRINT_TOPICS:
                rtps_frames.print_topics()
            case MenuOption.PRINT_STATS_COUNT:
                rtps_frames.print_stats()
            case MenuOption.PRINT_STATS_BYTES:
                rtps_frames.print_stats_in_bytes()
            case MenuOption.PLOT_BAR_CHART_COUNT:
                if not args.no_gui:
                    rtps_frames.plot_stats_by_frame_count(plot_discovery, scale)
            case MenuOption.PLOT_BAR_CHART_BYTES:
                if not args.no_gui:
                    rtps_frames.plot_stats_by_frame_length(plot_discovery, scale)
            case MenuOption.PLOT_TOPOLOGY_GRAPH:
                if not args.no_gui:
                    if topic:
                        rtps_frames.plot_topic_graph(topic=topic)
                    else:
                        rtps_frames.plot_multi_topic_graph()
            case MenuOption.SAVE_EXCEL:
                rtps_frames.save_to_excel(args.pcap, args.output, 'PCAPStats')
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

def get_tshark_version():
    try:
        output = subprocess.check_output(["tshark", "--version"], stderr=subprocess.STDOUT, text=True)
        logger.always(output.splitlines()[0])
    except FileNotFoundError:
        logger.error("Error: tshark is not installed.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running tshark: {e.output.strip()}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.error(e)