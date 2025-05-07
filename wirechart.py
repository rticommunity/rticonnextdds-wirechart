import argparse
from PCAPUtils import *
from RTPSFrame import *
from RTPSCapture import *
from PCAPStats import *
from log_handler import logging, configure_root_logger

logger = logging.getLogger('Wirechart')

# TODO: What's this?
def write_to_file(output_file_path, unique_topics):
    with open(output_file_path, 'w', encoding='utf-8') as outfile:
        for value in sorted(unique_topics):
            outfile.write(value + '\n')

def main():
    parser = argparse.ArgumentParser(description="Extract unique topics from a pcap file.")
    parser.add_argument('--pcap', type=str, required=True, help='Required argument. Specify the PCAP file.')
    parser.add_argument('--output', type=str, default='output', help='Specify an output file for PCAP statistics.')
    parser.add_argument('--no-gui', action='store_true', default=False, help='Disable GUI-based plotting.')
    parser.add_argument('--frame-range', type=str, default=None, help='Specify a range of frames to analyze in the format START:FINISH.')
    parser.add_argument('--plot-discovery', action='store_true', default=False, help='Include discovery frames in the plot.')
    # TODO: Command option for log or linear display
    args = parser.parse_args()
    # Configure the logger
    configure_root_logger(create_output_path(args.pcap, args.output, 'log'))
    
    logger.debug(f"Command Arguments: {args}")
    logger.always("Starting the PCAP analysis.")

    start, finish = None, None
    if args.frame_range:
        start, finish = parse_range(args.frame_range)

    # tshark seems to return commands in a hierarchy, i.e. frame -> udp -> rtps so order matters
    pcap_fields = list(['frame.number', 'udp.length',
                        'rtps.guidPrefix.src', 'rtps.sm.wrEntityId',        # Writer GUID
                        'rtps.guidPrefix.dst', 'rtps.sm.rdEntityId',        # Reader GUID
                        'rtps.sm.seqNumber', 'rtps.sm.octetsToNextHeader', 'rtps.sm.id', '_ws.col.Info'])

    rtps_frames = RTPSCapture(args.pcap, pcap_fields, 'rtps', start_frame=start, finish_frame=finish)
    # rtps_frames.print_capture_summary()  # Print summary of the capture
    stats = PCAPStats(rtps_frames.analyze_capture())  # Analyze the capture
    stats.print_stats()  # Print statistics
    stats.print_stats_in_bytes()  # Print statistics in bytes

    # Plot statistics only if GUI is enabled
    if not args.no_gui:
        stats.plot_stats_by_frame_count(args.plot_discovery)  # Plot by frame count
        stats.plot_stats_by_frame_length(args.plot_discovery)  # Plot by frame length

    # Write the DataFrame to an Excel file if an output path is provided
    if args.output:
        stats.save_to_excel(args.pcap, args.output, 'PCAPStats')  # Write to Excel

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

    return (parse_part(before), parse_part(after))

# Check for existence of the output path
def create_output_path(pcap_file, output_path, extension, description=None):
    if not os.path.exists(output_path):
        os.makedirs(output_path)

    # Create filename based on pcap_file
    filename = os.path.splitext(os.path.basename(pcap_file))[0]  # get filename without extension
    suffix = f"_{description}" if description else ""
    return os.path.join(output_path, f"{filename}{suffix}.{extension}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.always(f"Unhandled Exception: {e}")