import subprocess
import pandas as pd
import re
from collections import defaultdict
from PCAPFrame import *

SUBMESSAGE_ORDER = ["DATA", "DATA_FRAG", "DATA_BATCH", "PIGGYBACK_HEARTBEAT",
                    "PIGGYBACK_HEARTBEAT_BATCH", "HEARTBEAT", "HEARTBEAT_BATCH",
                    "ACKNACK", "REPAIR", "GAP", "UNREGISTER_DISPOSE"]

def return_all_matches(regex, string):
    """
    Extracts all 'topic' values from patterns like 'DATA(r) -> topic' or 'DATA(w) -> topic'
    (with or without a trailing comma), even if there are multiple matches in one string.
    """
    matches = re.findall(regex, string)
    return matches

def extract_pcap_data(pcap_file, fields, display_filter=None, max_frames=None):
    """
    Calls tshark to extract specified fields from a pcap file and returns a list of PCAPFrame objects.

    :param pcap_file: Path to the pcap file
    :param fields: Set of fields to extract (e.g., ['_ws_col_Info', '_ws.col.Protocol'])
    :param display_filter: Optional display filter (e.g., 'http')
    :param max_frames: Optional limit on number of packets
    :return: List of PCAPFrame objects containing the extracted field values
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
            raise InvalidPCAPDataException("tshark returned no RTPS frames")

        # Split each line into columns and create a list of PCAPFrame objects
        frames = []
        for frame in frame_data:
            values = frame.split('\t')
            frame = {field: value for field, value in zip(fields, values)}
            try:
                frames.append(PCAPFrame(frame))  # Create a PCAPFrame object for each record
            except InvalidPCAPDataException as e:
                # print(e.message)
                continue

        for frame in frames:
            frame.print_frame()  # Print the details of each frame

        return frames
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
        info_column = record._ws_col_Info  # Get the '_ws_col_Info' field from the dictionary
        if info_column and pd.notnull(info_column):  # Check for non-null values
            unique_topics.update(return_all_matches(r'DATA\([rw]\)\s*->\s*([\w:/]+),?', info_column))

    return unique_topics

def set_sequence_number(sequence_numbers, frame, sequence_number_index, gap=False):
    sequence_number_index += 1
    frame_seq_number = frame.seq_number[sequence_number_index]

    if gap:
        # GAPs announce the next sequence number, so decrement by 1
        frame_seq_number -= 1

    if frame_seq_number > sequence_numbers[frame.guid]:
        sequence_numbers[frame.guid] = frame_seq_number
    return sequence_number_index

def count_user_messages(pcap_data, unique_topics):
    """
    Counts user messages and returns the data as a pandas DataFrame.
    Ensures all unique topics are included, even if they have no messages.
    Orders the submessages based on SUBMESSAGE_ORDER and includes the length.

    :param pcap_data: A list of dictionaries containing the extracted PCAP data.
    :param unique_topics: A set of unique topics to initialize the DataFrame.
    :return: A pandas DataFrame with columns ['Topic', 'Submessage', 'Count', 'Length'].
    """
    frame_stats = []  # List to store rows for the DataFrame
    sequence_numbers = defaultdict(int)  # Dictionary to store string keys and unsigned integer values

    # Process the PCAP data to count messages and include lengths
    for frame in pcap_data:
        info_column = frame._ws_col_Info  # Get the '_ws_col_Info' field from the dictionary

        if info_column and pd.notnull(info_column):  # Check for non-null values
            # matches = return_all_matches(r',\s*(\w+)\s*->\s*([\w:]+)', info_column)
            matches = return_all_matches(r',\s*([A-Z0-9_()[\]]+)\s*->\s*([\w:]+)', info_column) # New
            seq_num_index = 0
            for match in matches:
                if match:
                    submessage = match[0]
                    topic = match[1]
                    udp_length = frame.udp_length   # Get the 'udp.length' field from the dictionary
                    length = int(udp_length) if udp_length and udp_length.isdigit() else 0  # Convert length to int

                    if "([" in submessage:
                        frame_stats.append({'Topic': topic, 'Submessage': "UNREGISTER_DISPOSE", 'Count': 1, 'Length': length})
                    elif "HEARTBEAT" in submessage:
                        # Record the sequence number
                        seq_num_index = set_sequence_number(sequence_numbers, frame, seq_num_index)

                        if len(matches) > 1:
                            # Subtract the length of the HEARTBEAT from the length of the previous message
                            length = 44 if "HEARTBEAT_BATCH" == submessage else 28
                            frame_stats[-1]['Length'] -= length
                            submessage = "PIGGYBACK_" + submessage

                        # Multiple matches found with a HEARTBEAT, therefore a PIGGYBACK_HEARTBEAT
                        frame_stats.append({'Topic': topic, 'Submessage': submessage, 'Count': 1, 'Length': length})
                    else:
                        if "GAP" == submessage:
                            seq_num_index = set_sequence_number(sequence_numbers, frame, seq_num_index, gap=True)

                        if "DATA" in submessage:
                            if frame.seq_number[seq_num_index] <= sequence_numbers[frame.guid]:
                                submessage = "REPAIR"

                        frame_stats.append({'Topic': topic, 'Submessage': submessage, 'Count': 1, 'Length': length})
                seq_num_index += 1

    if not frame_stats:
        raise InvalidPCAPDataException("No RTPS user frames with associated discovery data")

    # Convert the rows into a DataFrame
    df = pd.DataFrame(frame_stats)

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

    print("Sequence Numbers:")
    for guid, seq_num in sequence_numbers.items():
        print(f"{guid}: {seq_num}")

    return df