import argparse
from pcap_utils import *
from plotting import *

def write_to_file(output_file_path, unique_topics):
    with open(output_file_path, 'w', encoding='utf-8') as outfile:
        for value in sorted(unique_topics):
            outfile.write(value + '\n')

def main():
    parser = argparse.ArgumentParser(description="Extract unique topics from a pcap file.")
    parser.add_argument('--pcap', type=str, required=True, help='Required argument. Specify the PCAP file.')
    parser.add_argument('--output', type=str, default='', help='Specify an output file PCAP statistics.')
    args = parser.parse_args()

    pcap_fields = set(['frame.number'])

    if True:  # Replace with actual condition for topic extraction
        pcap_fields.update(['_ws.col.Info'])

    if True:  # Replace with actual condition for message histogram
        pcap_fields.update(['_ws.col.Info'])

    if True:  # Replace with actual condition for performing lost sample analysis
        pcap_fields.update(['rtps.guidPrefix.src', 'rtps.sm.wrEntityId', 'rtps.sm.seqNumber', '_ws.col.Info'])

    pcap_df = extract_pcap_data(args.pcap, pcap_fields, 'rtps')
    unique_topics = get_unique_topics(pcap_df)

    stats_df = count_user_messages(pcap_df, unique_topics)
    print_message_statistics(stats_df)  # Print statistics
    plot_nested_map_sorted(stats_df)    # Plot the stacked bar chart

    if args.output:
        write_dataframe_to_excel(stats_df, args.output, 'PCAPStats')  # Write to Excel

if __name__ == "__main__":
    main()