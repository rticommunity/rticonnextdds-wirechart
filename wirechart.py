import argparse
from PCAPUtils import *
from RTPSFrame import *
from RTPSCapture import *
from PCAPStats import *
from log_handler import logging, configure_root_logger

logger = logging.getLogger(__name__)
configure_root_logger()

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
    args = parser.parse_args()
    #TODO: Add parser arguments for start and stop frames and max frames
    logger.info(f"Command Arguments: {args}")
    logger.info("Starting the PCAP analysis.")

    start, finish = None, None
    if args.frame_range:
        start, finish = parse_range(args.frame_range)

    # tshark seems to return commands in a hierarchy, i.e. frame -> udp -> rtps so order matters
    pcap_fields = list(['frame.number', 'udp.length', 'rtps.guidPrefix.src', 'rtps.sm.wrEntityId',
                       'rtps.sm.seqNumber', 'rtps.sm.octetsToNextHeader', 'rtps.sm.id', '_ws.col.Info'])

    rtps_frames = RTPSCapture()
    rtps_frames.extract_rtps_frames(args.pcap, pcap_fields, 'rtps', start_frame=start, finish_frame=finish)
    rtps_frames.print_capture_summary()  # Print summary of the capture
    # rtps_frames.print_all_frames()  # Print all frames

    # pcap_stats = PCAPStats(count_user_messages(pcap_data, unique_topics))
    # pcap_stats.print_stats()  # Print statistics
    # pcap_stats.print_stats_in_bytes()  # Print statistics in bytes

    # # Plot statistics only if GUI is enabled
    # if not args.no_gui:
    #     pcap_stats.plot_stats_by_frame_count()  # Plot by frame count
    #     pcap_stats.plot_stats_by_frame_length()  # Plot by frame length

    # # Write the DataFrame to an Excel file if an output path is provided
    # if args.output:
    #     pcap_stats.save_to_excel(args.output, 'PCAPStats')  # Write to Excel

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


if __name__ == "__main__":
    try:
        main()
    except InvalidPCAPDataException as e:
        print(f"Invalid PCAP File: {e.message}.")
    except Exception as e:
        print(f"An error occurred: {e}")