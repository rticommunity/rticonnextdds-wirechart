import subprocess
import os
import pandas as pd
from collections import defaultdict
from RTPSFrame import *
from log_handler import logging
from enum import IntEnum

logger = logging.getLogger(__name__)

DISCOVERY_TOPIC = "DISCOVERY"

class FrameClassification(IntEnum):
    STANDARD_FRAME = 0
    REPAIR = 1
    DURABLE_REPAIR = 2

class RTPSCapture:
    """
    Represents a collection of RTPSFrame objects extracted from a PCAP file.
    Provides methods to manage and analyze the captured frames.
    """

    def __init__(self, pcap_file, fields, display_filter=None, start_frame=None, finish_frame=None, max_frames=None):
        """
        Initializes an empty RTPSCapture object.
        """
        if not os.path.exists(pcap_file):
            logger.error(f"PCAP file {pcap_file} does not exist.")
            raise FileNotFoundError(f"PCAP file {pcap_file} does not exist.")

        self.frames = []  # List to store RTPSFrame objects
        self._extract_rtps_frames(pcap_file, fields, display_filter, start_frame, finish_frame, max_frames)

    def __iter__(self):
        self._current_index = 0
        return self

    def __next__(self):
        if self._current_index < len(self.frames):
            packet = self.frames[self._current_index]
            self._current_index += 1
            return packet
        else:
            raise StopIteration

    def add_frame(self, frame):
        """
        Adds an RTPSFrame object to the capture.

        :param frame: An RTPSFrame object to add.
        """
        if isinstance(frame, RTPSFrame):
            self.frames.append(frame)
        else:
            raise TypeError("Only RTPSFrame objects can be added to RTPSCapture.")

    def list_all_topics(self):
        """
        Returns a set of all unique topics across all frames.

        :return: A set of unique topics.
        """
        topics = set()
        for frame in self.frames:
            topics.update(frame.list_topics())
        return topics

    def print_capture_summary(self):
        """
        Prints a summary of the RTPSCapture, including the number of frames and unique topics.
        """
        print(f"Total Frames: {len(self.frames)}")
        print(f"Unique Topics: {len(self.list_all_topics())}")
        print("Topics:")
        for topic in sorted(self.list_all_topics()):
            print(f"  - {topic}")

    def print_all_frames(self):
        """
        Prints the details of all frames in the capture.
        """
        for frame in self.frames:
            print(frame)

    def _extract_rtps_frames(self, pcap_file, fields, display_filter=None, start_frame=None, finish_frame=None, max_frames=None):
        """
        Calls tshark to extract specified fields from a pcap file and returns a list of RTPSFrame objects.

        :param pcap_file: Path to the pcap file
        :param fields: Set of fields to extract (e.g., ['_ws_col_Info', '_ws.col.Protocol'])
        :param display_filter: Optional display filter (e.g., 'http')
        :param max_frames: Optional limit on number of packets
        :return: List of RTPSFrame objects containing the extracted field values
        """
        cmd = ['tshark', '-r', pcap_file, '-T', 'fields']

        # Add each field to the command
        for field in fields:
            cmd.extend(['-e', field])

        filter_parts = []

        if display_filter:
            filter_parts.append(f"({display_filter})")

        if start_frame:
            filter_parts.append(f"(frame.number >= {start_frame})")

        if finish_frame:
            filter_parts.append(f"(frame.number <= {finish_frame})")

        # Join all parts with "&&"
        full_filter = " && ".join(filter_parts)

        if full_filter:
            cmd.extend(['-Y', full_filter])
        if max_frames:
            cmd.extend(['-c', str(max_frames)])

        logger.debug(f"Running command: {' '.join(cmd)}")
        try:
            logger.always("Reading data from from pcap file...")
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            frame_data = result.stdout.strip().split('\n')
            logger.always(f"tshark returned {len(frame_data)} frames")

            if frame_data == ['']:
                raise InvalidPCAPDataException("tshark returned no RTPS frames")

            # Split each line into columns and create a list of RTPSFrame objects
            total_frames = len(frame_data)
            progress_interval = max(total_frames // 10, 1)  # Avoid division by zero for small datasets

            for i, raw_frame in enumerate(frame_data):
                values = raw_frame.split('\t')
                frame = {field: value for field, value in zip(fields, values)}
                try:
                    self.add_frame(RTPSFrame(frame))  # Create a RTPSFrame object for each record
                except InvalidPCAPDataException as e:
                    logger.log(e.log_level, f"Frame {int(frame['frame.number']):09d} dropped. Message: {e}")
                    continue
                except KeyError as e:
                    logger.debug(f"Frame {int(frame['frame.number']):09d} dropped. Message: {e}")
                    continue
                # Print progress every 10%
                if (i + 1) % progress_interval == 0 or (i + 1) == total_frames:
                    percent = ((i + 1) * 100) // total_frames
                    logger.always(f"Processing {percent}% complete")
        except subprocess.CalledProcessError as e:
            logger.error("Error running tshark.")
            raise e

    def analyze_capture(self):
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
        durability_repairs = defaultdict(int) # Dictionary to keep track of sequence numbers for durability repairs

        # Process the PCAP data to count messages and include lengths
        for frame in self.frames:
            frame_classification = FrameClassification.STANDARD_FRAME
            for sm in frame:
                topic = sm.topic
                if frame.discovery_frame:
                    topic = DISCOVERY_TOPIC
                # TODO: Verify not to do this with GAP
                guid_key = (frame.guid_src, frame.guid_dst)
                if "HEARTBEAT" in sm.sm_type.name:
                    sequence_numbers[guid_key[0]] = sm.seq_num()
                elif sm.sm_type in (SubmessageTypes.DATA, SubmessageTypes.DATA_FRAG, SubmessageTypes.DATA_BATCH):
                    # TODO: Discovery repairs?
                    # TODO: Durability repairs?
                    if sm.seq_num() <= sequence_numbers[guid_key[0]]:
                        if sm.seq_num() <= durability_repairs[guid_key]:
                            sm.sm_type = SubmessageTypes.DATA_DURABILITY_REPAIR
                            frame_classification = FrameClassification.DURABLE_REPAIR
                        else:
                            sm.sm_type = SubmessageTypes.DATA_REPAIR
                            frame_classification = FrameClassification.REPAIR
                # TODO: Add support for Discovery repairs?
                elif sm.sm_type == SubmessageTypes.ACKNACK:
                    if sm.seq_num() > 0 and guid_key not in durability_repairs:
                        # Only add this for the first non-zero ACKNACK
                        durability_repairs[guid_key] = sequence_numbers[guid_key[0]]

            if frame_classification > FrameClassification.STANDARD_FRAME:
                logger.info(f"Frame {frame.frame_number} classified as {frame_classification.name}.")

            if frame_class > FrameClassification.STANDARD_FRAME:
                logger.info(f"Frame {frame.frame_number} classified as {frame_class.name}.")
            raise InvalidPCAPDataException("No RTPS user frames with associated discovery data")

        # Convert the rows into a DataFrame
        df = pd.DataFrame(frame_stats)

        # Aggregate the counts and lengths for each (Topic, Submessage) pair
        df = df.groupby(['topic', 'sm'], as_index=False).agg({'count': 'sum', 'length': 'sum'})

        # Ensure all unique topics are included in the DataFrame
        def include_missing_topics_and_sm(df, all_topics, sm_start, sm_end):
            missing_list = []
            for topic in all_topics:
                for sm_type in SubmessageTypes.subset(start = sm_start, end = sm_end):
                    if not ((df['topic'] == topic) & (df['sm'] == sm_type.name)).any():
                        missing_list.append({'topic': topic, 'sm': sm_type.name, 'count': 0, 'length': 0})
            return missing_list

        all_rows = []
        all_rows.extend(include_missing_topics_and_sm(df, {DISCOVERY_TOPIC}, SubmessageTypes.DATA_P, SubmessageTypes.DISCOVERY_STATE))
        all_rows.extend(include_missing_topics_and_sm(df, self.list_all_topics(), SubmessageTypes.DATA, SubmessageTypes.DATA_STATE))

        # Add missing rows with a count of 0 and length of 0
        if all_rows:
            df = pd.concat([df, pd.DataFrame(all_rows)], ignore_index=True)

        # Order the Submessage column based on SubmessageTypes
        # Create an ordered categorical column using enum member names
        df['sm'] = pd.Categorical(
            df['sm'],
            categories=[member.name for member in SubmessageTypes],
            ordered=True)

        # Sort and reset index
        df = df.sort_values(by=['topic', 'sm']).reset_index(drop=True)

        return df