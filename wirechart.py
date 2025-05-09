import argparse
import subprocess
from PCAPUtils import *
from RTPSFrame import *
from RTPSCapture import *
from PCAPStats import *
from log_handler import logging, configure_root_logger

logger = logging.getLogger('Wirechart')

def main():
    parser = argparse.ArgumentParser(description="Extract unique topics from a pcap file.")
    parser.add_argument('--pcap', type=str, required=True, help='Required argument. Specify the PCAP file.')
    parser.add_argument('--output', type=str, default='output', help='Specify an output file for PCAP statistics.')
    parser.add_argument('--no-gui', action='store_true', default=False, help='Disable GUI-based plotting.')
    parser.add_argument('--frame-range', type=str, default=None, help='Specify a range of frames to analyze in the format START:FINISH.')
    # parser.add_argument('--plot-discovery', action='store_true', default=False, help='Include discovery frames in the plot.')
    # TODO: Command option for log or linear display
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
    pcap_fields = list(['frame.number', 'udp.length',
                        'rtps.guidPrefix.src', 'rtps.sm.wrEntityId',        # Writer GUID
                        'rtps.guidPrefix.dst', 'rtps.sm.rdEntityId',        # Reader GUID
                        'rtps.sm.seqNumber', 'rtps.sm.octetsToNextHeader',
                        'rtps.sm.id', '_ws.col.Info'])

    rtps_frames = RTPSCapture(args.pcap, pcap_fields, 'rtps', start_frame=start, finish_frame=finish)
    rtps_frames.print_capture_summary()  # Print summary of the capture
    stats = PCAPStats(rtps_frames.analyze_capture())  # Analyze the capture
    rtps_frames.plot_topic_graph()  # Print topic graph

    scale = PlotScale.LINEAR  # Default scale
    plot_discovery = False
    while True:
        print("\n--- Menu ---")
        print("0. Print Statistics")
        print("1. Plot Message Count")
        print("2. Plot Message Size")
        print("3. Change Scale")
        print("4. Include Discovery Frames")
        print("5. Save to Excel")
        print("6. Exit")

        choice = input("Enter your choice (1-6): ")
        logger.debug(f"User choice: {choice}")

        match choice:
            case '0':
                stats.print_stats()  # Print statistics
                stats.print_stats_in_bytes()  # Print statistics in bytes
            case '1':
                if not args.no_gui:
                    stats.plot_stats_by_frame_count(plot_discovery, scale)  # Plot by frame count
            case '2':
                # Plot Bytes
                if not args.no_gui:
                    stats.plot_stats_by_frame_length(plot_discovery, scale)  # Plot by frame length
            case '3':
                print("\n-- Change Scale --")
                print("a. Linear")
                print("b. Logarithmic")
                sub_choice = input("Choose scale (a/b): ")
                logger.debug(f"User scale choice: {sub_choice}")
                match sub_choice.lower():
                    case 'a':
                        scale = PlotScale.LINEAR
                        print("Scale set to Linear.")
                    case 'b':
                        scale = PlotScale.LOGARITHMIC
                        print("Scale set to Logarithmic.")
                    case _:
                        print("Invalid scale choice.")
            case '4':
                print("\n-- Include Discovery Data --")
                print("a. No")
                print("b. Yes")
                sub_choice = input("Choose option (a/b): ")
                logger.debug(f"User discovery choice: {sub_choice}")
                match sub_choice.lower():
                    case 'a':
                        plot_discovery = False
                        print("Discovery frames excluded from the plot.")
                    case 'b':
                        plot_discovery = True
                        print("Discovery frames included in the plot.")
                    case _:
                        print("Invalid choice.")
            case '5':
                stats.save_to_excel(args.pcap, args.output, 'PCAPStats')  # Write to Excel
            case '6':
                print("Exiting program.")
                break
            case _:
                print("Invalid input. Please enter a number between 0 and 6.")

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