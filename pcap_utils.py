import subprocess
import pandas as pd
import re

def return_all_matches(string, regex):
    """
    Extracts all 'topic' values from patterns like 'DATA(r) -> topic' or 'DATA(w) -> topic'
    (with or without a trailing comma), even if there are multiple matches in one string.
    """
    matches = re.findall(regex, string)
    return matches

def extract_pcap_data(pcap_file, fields, display_filter=None, max_frames=None):
    """
    Calls tshark to extract specified fields from a pcap file and returns a DataFrame.
    
    :param pcap_file: Path to the pcap file
    :param fields: List of fields to extract (e.g., ['_ws.col.Info', '_ws.col.Protocol'])
    :param display_filter: Optional display filter (e.g., 'http')
    :param max_frames: Optional limit on number of packets
    :return: DataFrame containing the extracted field values
    """

    fields = list(fields)  # Ensure fields is a list for tshark command

    cmd = ['tshark', '-r', pcap_file, '-T', 'fields']

    # Add each field to the command
    for field in fields:
        cmd.extend(['-e', field])

    if display_filter:
        cmd.extend(['-Y', display_filter])
    if max_frames:
        cmd.extend(['-c', str(max_frames)])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        frame_data = result.stdout.strip().split('\n')

        # Split each line into columns and create a DataFrame
        data = [line.split('\t') for line in frame_data]
        df = pd.DataFrame(data, columns=fields)  # Use the `fields` list as column names

        return df
    except subprocess.CalledProcessError as e:
        print("Error running tshark:", e.stderr)
        return pd.DataFrame(columns=fields)  # Return an empty DataFrame with the correct columns

if __name__ == '__main__':
    pcap_path = 'pcap/shapes.pcapng'
    fields = set()
    fields.update(['frame.number', 'rtps.guidPrefix.src', 'rtps.participant_idx', '_ws.col.Info'])
    display_filter = 'rtps' #'(rtps.sm.wrEntityId.entityKind == 0x02) || (rtps.sm.wrEntityId.entityKind == 0x03)'
    max_frames = None

    # Get the DataFrame directly from the function
    pcap_df = extract_pcap_data(pcap_path, fields, display_filter, max_frames)

    # Save the DataFrame to a CSV file (optional)
    pcap_df.to_csv("out.csv", index=False)

    # Print the DataFrame (optional)
    print(pcap_df['_ws.col.Info'])
