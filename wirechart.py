import argparse
import pandas as pd
from pcap_utils import *



def get_unique_topics(pcap_file):
    unique_topics = set()

    pcap_df = extract_pcap_data(pcap_file,
                                ['frame.number', '_ws.col.Info'],
                                display_filter='rtps.sm.wrEntityId == 0x000003c2 || rtps.sm.wrEntityId == 0x000004c2 || rtps.sm.wrEntityId == 0xff0003c2 || rtps.sm.wrEntityId == 0xff0004c2')
    for info_column in pcap_df['_ws.col.Info']:
        if pd.notnull(info_column):  # Check for non-null values
            unique_topics.update(return_all_matches(info_column, r'DATA\([rw]\)\s*->\s*([\w:/]+),?'))

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