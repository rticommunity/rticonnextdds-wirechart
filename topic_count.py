import re
import argparse
from frame_export import run_tshark_with_filter

def extract_topics(frame_info):
    """
    Extracts all 'topic' values from patterns like 'DATA(r) -> topic' or 'DATA(w) -> topic'
    (with or without a trailing comma), even if there are multiple matches in one string.
    """
    matches = re.findall(r'DATA\([rw]\)\s*->\s*([\w:/]+),?', frame_info)
    return matches

def get_unique_topics(pcap_file):
    unique_topics = set()

    # Returns [Frame_Number, Info]
    frames = run_tshark_with_filter(pcap_file, 'rtps.sm.wrEntityId == 0x000003c2 || rtps.sm.wrEntityId == 0x000004c2 || rtps.sm.wrEntityId == 0xff0003c2 || rtps.sm.wrEntityId == 0xff0004c2')

    for frame in frames:
        unique_topics.update(extract_topics(frame[1]))

    return unique_topics

def write_to_file(output_file_path, unique_topics):
    with open(output_file_path, 'w', encoding='utf-8') as outfile:
        for value in sorted(unique_topics):
            outfile.write(value + '\n')

def main():
    parser = argparse.ArgumentParser(description="Extract unique topics from a pcap file.")
    parser.add_argument('--pcap', type=str, required=True, help='Required argument. Specify the PCAP file.')
    parser.add_argument('--output', type=str, default='unique_topics.txt', help='Specify an output file for unique topics.')
    args = parser.parse_args()

    unique_topics = get_unique_topics(args.pcap)
    write_to_file(args.output, unique_topics)

    print(f"Saved {len(unique_topics)} unique topic values to '{args.output}'")

if __name__ == "__main__":
    main()