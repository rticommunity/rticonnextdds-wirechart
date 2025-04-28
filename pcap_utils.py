import subprocess
import pandas as pd
import re
from collections import defaultdict
from plotting import *

ENDPOINT_DISCOVERY_DISPLAY_FILTER = 'rtps.sm.wrEntityId == 0x000003c2 || rtps.sm.wrEntityId == 0x000004c2 || rtps.sm.wrEntityId == 0xff0003c2 || rtps.sm.wrEntityId == 0xff0004c2'
USER_DATA_DISPLAY_FILTER = 'rtps.sm.wrEntityId.entityKind == 0x02 || rtps.sm.wrEntityId.entityKind == 0x03'

def return_all_matches(regex, string):
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
    :param fields: Set of fields to extract (e.g., ['_ws.col.Info', '_ws.col.Protocol'])
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

def get_unique_topics(pcap_df):
    unique_topics = set()

    for info_column in pcap_df['_ws.col.Info']:
        if pd.notnull(info_column):  # Check for non-null values
            unique_topics.update(return_all_matches(r'DATA\([rw]\)\s*->\s*([\w:/]+),?', info_column))

    return unique_topics

def count_user_messages(pcap_df):
    message_map = defaultdict(lambda: defaultdict(int))

    for info_column in pcap_df['_ws.col.Info']:
        if pd.notnull(info_column):  # Check for non-null values
            matches = return_all_matches(r',\s*(\w+)\s*->\s*([\w:]+)', info_column)
            for match in matches:
                if match:
                    submessage = match[0]
                    topic = match[1]
                    if submessage == "HEARTBEAT" and len(matches) > 1:
                        # Multiple matches found with a HEARTBEAT, therefore a PIGGYBACK_HEARTBEAT
                        message_map[topic]["PIGGYBACK_HEARTBEAT"] += 1
                    else:
                        message_map[topic][submessage] += 1

    return message_map