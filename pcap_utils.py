import subprocess
import pandas as pd
import re
# from plotting import *

class InvalidPCAPDataException(Exception):
    """Exception raised for invalid PCAP data."""

    def __init__(self, message, pcap_file=None):
        """
        Initializes the exception with a message and an optional PCAP file.

        :param message: The error message.
        :param pcap_file: The path to the PCAP file (optional).
        """
        self.message = message
        self.pcap_file = pcap_file
        super().__init__(self.message)

    def __str__(self):
        if self.pcap_file:
            return f"{self.message} (File: {self.pcap_file})"
        return self.message

SUBMESSAGE_ORDER = ["DATA", "PIGGYBACK_HEARTBEAT", "HEARTBEAT", "ACKNACK", "GAP", "UNREGISTER_DISPOSE"]
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
    Calls tshark to extract specified fields from a pcap file and returns a list of dictionaries.

    :param pcap_file: Path to the pcap file
    :param fields: Set of fields to extract (e.g., ['_ws.col.Info', '_ws.col.Protocol'])
    :param display_filter: Optional display filter (e.g., 'http')
    :param max_frames: Optional limit on number of packets
    :return: List of dictionaries containing the extracted field values
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

        if frame_data == ['']:
            # If the output is empty, raise an exception
            raise InvalidPCAPDataException("tshark returned no RTPS frames", pcap_file)

        # Split each line into columns and create a list of dictionaries
        data = []
        for line in frame_data:
            values = line.split('\t')
            record = {field: value for field, value in zip(fields, values)}
            data.append(record)

        return data
    except subprocess.CalledProcessError as e:
        print("Error running tshark:", e.stderr)
        return []  # Return an empty list in case of an error

def get_unique_topics(pcap_data):
    """
    Extracts unique topics from a dictionary containing PCAP data.

    :param pcap_data: A list of dictionaries containing PCAP data.
    :return: A set of unique topics.
    """
    unique_topics = set()

    for record in pcap_data:
        info_column = record.get('_ws.col.Info')  # Get the '_ws.col.Info' field from the dictionary
        if info_column and pd.notnull(info_column):  # Check for non-null values
            unique_topics.update(return_all_matches(r'DATA\([rw]\)\s*->\s*([\w:/]+),?', info_column))

    return unique_topics

def count_user_messages(pcap_data, unique_topics):
    """
    Counts user messages and returns the data as a pandas DataFrame.
    Ensures all unique topics are included, even if they have no messages.
    Orders the submessages based on SUBMESSAGE_ORDER and includes the length.

    :param pcap_data: A list of dictionaries containing the extracted PCAP data.
    :param unique_topics: A set of unique topics to initialize the DataFrame.
    :return: A pandas DataFrame with columns ['Topic', 'Submessage', 'Count', 'Length'].
    """
    rows = []  # List to store rows for the DataFrame

    # Process the PCAP data to count messages and include lengths
    for record in pcap_data:
        info_column = record.get('_ws.col.Info')  # Get the '_ws.col.Info' field from the dictionary
        udp_length = record.get('udp.length')  # Get the 'udp.length' field from the dictionary

        if info_column and pd.notnull(info_column):  # Check for non-null values
            # matches = return_all_matches(r',\s*(\w+)\s*->\s*([\w:]+)', info_column)
            matches = return_all_matches(r',\s*([A-Z0-9_()[\]]+)\s*->\s*([\w:]+)', info_column) # New
            for match in matches:
                if match:
                    submessage = match[0]
                    topic = match[1]
                    length = int(udp_length) if udp_length and udp_length.isdigit() else 0  # Convert length to int
                    if "([" in submessage:
                        rows.append({'Topic': topic, 'Submessage': "UNREGISTER_DISPOSE", 'Count': 1, 'Length': length})
                    elif submessage == "HEARTBEAT" and len(matches) > 1:
                        # Multiple matches found with a HEARTBEAT, therefore a PIGGYBACK_HEARTBEAT
                        rows.append({'Topic': topic, 'Submessage': "PIGGYBACK_HEARTBEAT", 'Count': 1, 'Length': 0})
                    else:
                        rows.append({'Topic': topic, 'Submessage': submessage, 'Count': 1, 'Length': length})

    if not rows:
        raise InvalidPCAPDataException("No RTPS user frames with associated discovery data", pcap_file=None)

    # Convert the rows into a DataFrame
    df = pd.DataFrame(rows)

    # Aggregate the counts and lengths for each (Topic, Submessage) pair
    df = df.groupby(['Topic', 'Submessage'], as_index=False).agg({'Count': 'sum', 'Length': 'sum'})

    # Ensure all unique topics are included in the DataFrame
    all_rows = []
    for topic in unique_topics:
        for submessage in SUBMESSAGE_ORDER:
            if not ((df['Topic'] == topic) & (df['Submessage'] == submessage)).any():
                all_rows.append({'Topic': topic, 'Submessage': submessage, 'Count': 0, 'Length': 0})

    # Add missing rows with a count of 0 and length of 0
    if all_rows:
        df = pd.concat([df, pd.DataFrame(all_rows)], ignore_index=True)

    # Order the Submessage column based on SUBMESSAGE_ORDER
    df['Submessage'] = pd.Categorical(df['Submessage'], categories=SUBMESSAGE_ORDER, ordered=True)
    df = df.sort_values(by=['Topic', 'Submessage']).reset_index(drop=True)

    return df