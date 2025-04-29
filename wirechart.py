import argparse
from pcap_utils import *
from plotting import *
from PCAPStats import *

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

    if True:  # Replace with actual condition for data size
        pcap_fields.update(['udp.length', '_ws.col.Info'])

    if True:  # Replace with actual condition for performing lost sample analysis
        pcap_fields.update(['rtps.guidPrefix.src', 'rtps.sm.wrEntityId', 'rtps.sm.seqNumber', '_ws.col.Info'])

    pcap_data = extract_pcap_data(args.pcap, pcap_fields, 'rtps')
    unique_topics = get_unique_topics(pcap_data)

    # stats_df = count_user_messages(pcap_data, unique_topics)
    # print_message_statistics(stats_df)  # Print statistics
    # plot_nested_map_sorted(stats_df)    # Plot the stacked bar chart
    # if args.output:
    #     write_dataframe_to_excel(stats_df, args.output, 'PCAPStats')  # Write to Excel

    pcap_stats = PCAPStats(count_user_messages(pcap_data, unique_topics))
    pcap_stats.print_statistics()  # Print statistics
    pcap_stats.plot_stats_by_frame_count()  # Plot by frame count
    pcap_stats.plot_stats_by_frame_length()  # Plot by frame length
    # Write the DataFrame to an Excel file if an output path is provided
    if args.output:
        pcap_stats.save_to_excel(args.output, 'PCAPStats')  # Write to Excel

    

if __name__ == "__main__":
    main()