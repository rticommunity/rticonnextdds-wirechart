import argparse
import pandas as pd
from pcap_utils import *



def get_unique_topics(pcap_df):
    unique_topics = set()
    
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

    pcap_fields = set(['frame.number'])
    # Discovery Analysis

    if True:  # Replace with actual condition for topic extraction
        pcap_fields.update(['_ws.col.Info'])

    pcap_df = extract_pcap_data(args.pcap, pcap_fields, ENDPOINT_DISCOVERY_DISPLAY_FILTER)
    unique_topics = get_unique_topics(pcap_df)
    write_to_file(args.output, unique_topics)
    print(f"Saved {len(unique_topics)} unique topic values to '{args.output}'")

    # User Data Analysis
    pcap_fields = set(['frame.number'])

    if True:  # Replace with actual condition for message histogram
        pcap_fields.update(['_ws.col.Info'])

    if True:  # Replace with actual condition for performing lost sample analysis
        pcap_fields.update(['rtps.guidPrefix.src', 'rtps.sm.wrEntityId', 'rtps.sm.seqNumber', '_ws.col.Info'])

    pcap_df = extract_pcap_data(args.pcap, pcap_fields, USER_DATA_DISPLAY_FILTER)

    pcap_df.to_csv('pcap_data.csv', index=False)
    print("Saved pcap_df to 'pcap_data.csv'")

if __name__ == "__main__":
    main()