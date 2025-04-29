import subprocess
import pandas as pd
import re
# from plotting import *

SUBMESSAGE_ORDER = ["DATA", "PIGGYBACK_HEARTBEAT", "HEARTBEAT", "ACKNACK", "GAP"]
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

def count_user_messages(pcap_df, unique_topics):
    """
    Counts user messages and returns the data as a pandas DataFrame.
    Ensures all unique topics are included, even if they have no messages.
    Orders the submessages based on SUBMESSAGE_ORDER.

    :param pcap_df: DataFrame containing the extracted PCAP data.
    :param unique_topics: A set of unique topics to initialize the DataFrame.
    :return: A pandas DataFrame with columns ['Topic', 'Submessage', 'Count'].
    """
    rows = []  # List to store rows for the DataFrame

    # Process the PCAP data to count messages
    for info_column in pcap_df['_ws.col.Info']:
        if pd.notnull(info_column):  # Check for non-null values
            matches = return_all_matches(r',\s*(\w+)\s*->\s*([\w:]+)', info_column)
            for match in matches:
                if match:
                    submessage = match[0]
                    topic = match[1]
                    if submessage == "HEARTBEAT" and len(matches) > 1:
                        # Multiple matches found with a HEARTBEAT, therefore a PIGGYBACK_HEARTBEAT
                        rows.append({'Topic': topic, 'Submessage': "PIGGYBACK_HEARTBEAT", 'Count': 1})
                    else:
                        rows.append({'Topic': topic, 'Submessage': submessage, 'Count': 1})

    # Convert the rows into a DataFrame
    df = pd.DataFrame(rows)

    # Aggregate the counts for each (Topic, Submessage) pair
    df = df.groupby(['Topic', 'Submessage'], as_index=False).sum()

    # Ensure all unique topics are included in the DataFrame
    all_rows = []
    for topic in unique_topics:
        for submessage in SUBMESSAGE_ORDER:
            if not ((df['Topic'] == topic) & (df['Submessage'] == submessage)).any():
                all_rows.append({'Topic': topic, 'Submessage': submessage, 'Count': 0})

    # Add missing rows with a count of 0
    if all_rows:
        df = pd.concat([df, pd.DataFrame(all_rows)], ignore_index=True)

    # Order the Submessage column based on SUBMESSAGE_ORDER
    df['Submessage'] = pd.Categorical(df['Submessage'], categories=SUBMESSAGE_ORDER, ordered=True)
    df = df.sort_values(by=['Topic', 'Submessage']).reset_index(drop=True)

    return df