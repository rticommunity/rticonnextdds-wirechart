##############################################################################################
# (c) 2025-2025 Copyright, Real-Time Innovations, Inc. (RTI) All rights reserved.
#
# RTI grants Licensee a license to use, modify, compile, and create derivative works of the
# software solely for use with RTI Connext DDS. Licensee may redistribute copies of the
# software, provided that all such copies are subject to this license. The software is
# provided "as is", with no warranty of any type, including any warranty for fitness for any
# purpose. RTI is under no obligation to maintain or support the software. RTI shall not be
# liable for any incidental or consequential damages arising out of the use or inability to
# use the software.
#
##############################################################################################

# Standard Library Imports
from collections import defaultdict
from enum import IntEnum

# Third-Party Library Imports
import pandas as pd
from tqdm import tqdm

# Local Application Imports
from src.log_handler import logging
from src.rtps_frame import FrameTypes, GUIDEntity, RTPSFrame
from src.shared_utils import DEV_DEBUG, InvalidPCAPDataException, create_output_path
from src.rtps_capture import RTPSCapture
from src.rtps_submessage import SubmessageTypes, SUBMESSAGE_COMBINATIONS, list_combinations_by_flag, RTPSSubmessage

logger = logging.getLogger(__name__)

DISCOVERY_TOPIC = "DISCOVERY"
META_DATA_TOPIC = "META_DATA"

class RTPSAnalyzeCapture:
    def __init__(self, capture: RTPSCapture):
        self.graph_edges = defaultdict(set)
        self.rs_guid_prefix = set()
        self.df = pd.DataFrame()  # DataFrame to store analysis results
        self.capture = capture

    def analyze_capture(self):
        """
        Analyzes the RTPSCapture object and populates the DataFrame with message counts and lengths.
        This method processes each frame in the capture, classifies submessages, and aggregates data.
        """
        sm_list = self._process_submessages()
        self._aggregate_data(sm_list)

    def _process_submessages(self) -> list:
        """
        Counts user messages and returns the data as a pandas DataFrame.
        Ensures all unique topics are included, even if they have no messages.
        Orders the submessages based on SUBMESSAGE_ORDER and includes the length.

        :param pcap_data: A list of dictionaries containing the extracted PCAP data.
        :param unique_topics: A set of unique topics to initialize the DataFrame.
        :return: A pandas DataFrame with columns ['Topic', 'Submessage', 'Count', 'Length'].
        """
        logger.always("Analyzing capture data...")

        sm_list = []  # List to store rows for the DataFrame
        sequence_numbers = defaultdict(int)  # Dictionary to store string keys and unsigned integer values
        durability_repairs = defaultdict(int) # Dictionary to keep track of sequence numbers for durability repairs

        # Process the PCAP data to count messages and include lengths
        for frame in tqdm(self.capture.frames):
            frame_classification = SubmessageTypes.UNSET
            self._set_routing_service_nodes(frame)
            self._set_graph_nodes(frame)
            # Create a unique key using the GUIDs and IP addresses.  This is required in the event multiple interfaces are used.
            guid_key = (frame.guid_src, frame.ip_src, frame.guid_dst, frame.ip_dst)
            for sm in frame:
                topic = RTPSAnalyzeCapture._get_topic(frame)
                RTPSAnalyzeCapture._process_submessage(sm, sequence_numbers, durability_repairs, guid_key)
                frame_classification |= sm.sm_type
                sm_list.append({'topic': topic, 'sm': str(sm.sm_type), 'count': 1, 'length': sm.length})

            RTPSAnalyzeCapture._log_classification(frame, frame_classification)

        if not any(frame.get('topic') != 'DISCOVERY' for frame in sm_list):
            raise InvalidPCAPDataException("No RTPS user frames with associated discovery data")

        return sm_list

    def _aggregate_data(self, sm_list: list):
        # Convert the rows into a DataFrame
        self.df = pd.DataFrame(sm_list)

        # Aggregate the counts and lengths for each (Topic, Submessage) pair
        self.df = self.df.groupby(['topic', 'sm'], as_index=False).agg({'count': 'sum', 'length': 'sum'})

        all_rows = []
        # Ensure all unique topics are included in the DataFrame.  Include DISCOVERY but not META_DATA.
        all_rows.extend(self.include_missing_topics_and_sm(
            {DISCOVERY_TOPIC}, list_combinations_by_flag(SubmessageTypes.DISCOVERY)))
        all_rows.extend(self.include_missing_topics_and_sm(
            self.capture.list_all_topics(), list_combinations_by_flag(SubmessageTypes.DISCOVERY, negate=True)))

        # Add missing rows with a count of 0 and length of 0
        if all_rows:
            self.df = pd.concat([self.df, pd.DataFrame(all_rows)], ignore_index=True)

        # Order the Submessage column based on SubmessageTypes
        # Create an ordered categorical column using enum member names
        self.df['sm'] = pd.Categorical(
            self.df['sm'],
            categories=[str(s) for s in SUBMESSAGE_COMBINATIONS],
            ordered=True)

        # Sort and reset index
        self.df = self.df.sort_values(by=['topic', 'sm']).reset_index(drop=True)

        if DEV_DEBUG:
            duplicates = self.df[self.df.duplicated(subset=['topic', 'sm'], keep=False)]
            if not duplicates.empty:
                print("Duplicate entries found:")
                print(duplicates)

    def _set_routing_service_nodes(self, frame: RTPSFrame):
        if FrameTypes.ROUTING_SERVICE in frame.frame_type:
            # Add the GUID prefix to the set of Routing Service GUID prefixes
            self.rs_guid_prefix.add(frame.guid_prefix_and_entity_id(GUIDEntity.GUID_SRC)[0])

    def _set_graph_nodes(self, frame: RTPSFrame):
        """
        Sets the graph edges based on the frame's GUIDs and IP addresses.
        This method is called during the analysis of the capture to build the topology graph.
        """
        # TODO: Add this check after the frame is classified as a repair?  Otherwise,
        # multicast frame repairs might be added to the graph, which doesn't accurately
        # represent the topology for a multicast writer.
        if (FrameTypes.USER_DATA == frame.frame_type) and all([frame.guid_src, frame.guid_dst]):
            self.graph_edges[frame.get_topic()].add((frame.guid_src, frame.guid_dst))

    # Ensure all unique topics are included in the DataFrame
    def include_missing_topics_and_sm(self, all_topics, sm_list):
        missing_list = []
        for topic in all_topics:
            for sm_type in sm_list:
                if not ((self.df['topic'] == topic) & (self.df['sm'] == str(sm_type))).any():
                    missing_list.append({'topic': topic, 'sm': str(sm_type), 'count': 0, 'length': 0})
        return missing_list

    @staticmethod
    def _process_submessage(sm: RTPSSubmessage, sequence_numbers: dict, durability_repairs: dict, guid_key: tuple):
        # Declare the GUIDKey enum for local scope
        class GUIDKey(IntEnum):
            GUID_SRC        = 0
            IP_SRC          = 1
            GUID_DST        = 2
            IP_DST          = 3
        # TODO: Verify not to do this with GAP
        if sm.sm_type & SubmessageTypes.HEARTBEAT:
            # Not all submessages have a DST GUID, so we must only use the SRC GUID to key
            # the SN dictionary.  Since the SN of a writer is not dependent on the reader,
            # this approach is valid.
            # d.update({k: 99 for k in d if k[0] == 'a'})
            sequence_numbers[guid_key] = sm.seq_num()
        elif (sm.sm_type & SubmessageTypes.DATA) and not (sm.sm_type & SubmessageTypes.FRAGMENT):
        # elif (sm.sm_type & SubmessageTypes.DATA):
            # TODO: Not sure how to handle FRAGs, so ignoring them for now
            # TODO: Discovery repairs?
            # Check if this submessage is some form of a repair.  Not all HEARTBEATs have a GUID_DST,
            # so we must consider the both cases where the GUID_DST is None and where it is not.
            if sm.seq_num() <= max(sequence_numbers[guid_key],
                                    sequence_numbers[guid_key[GUIDKey.GUID_SRC], guid_key[GUIDKey.IP_SRC], None, guid_key[GUIDKey.IP_DST]]):
                sm.sm_type |= SubmessageTypes.REPAIR
                # If this is a repair, there will be a GUID_DST, and we can key on the entire GUID_KEY
                if sm.seq_num() <= durability_repairs[guid_key]:
                    sm.sm_type |= SubmessageTypes.DURABLE
        elif sm.sm_type & SubmessageTypes.ACKNACK:
            # Record the writer SN when the first non-zero ACKNACK is received.  All repairs with
            # a SN less than or equal to this number are considered durability repairs while all
            # repairs after this SN are considered standard repairs.
            if sm.seq_num() > 0 and guid_key not in durability_repairs:
                # Only add this for the first non-zero ACKNACK
                durability_repairs[guid_key] = sequence_numbers[guid_key]

    @staticmethod
    def _get_topic(frame: RTPSFrame):
        """
        Returns the topic of the frame based on its submessage type.
        If the frame is a discovery frame, returns DISCOVERY_TOPIC.
        If the frame is a metadata frame, returns META_DATA_TOPIC.
        Otherwise, returns the topic from the first submessage.
        """
        if FrameTypes.DISCOVERY in frame.frame_type:
            return DISCOVERY_TOPIC
        elif FrameTypes.META_DATA in frame.frame_type:
            return META_DATA_TOPIC
        else:
            return frame.get_topic()

    @staticmethod
    def _log_classification(frame: RTPSFrame, classification: SubmessageTypes):
        if classification & (SubmessageTypes.REPAIR | SubmessageTypes.DURABLE):
            classification &= (SubmessageTypes.DISCOVERY | SubmessageTypes.DATA |
                               SubmessageTypes.FRAGMENT | SubmessageTypes.BATCH |
                               SubmessageTypes.REPAIR | SubmessageTypes.DURABLE)
            logger.info(f"Frame {frame.frame_number} classified as {classification}.")

    def save_to_excel(self, pcap_file, output_path, sheet_name="Sheet1"):
        """
        Writes a pandas DataFrame to an Excel file.

        :param df: A pandas DataFrame to write to Excel.
        :param output_file: The path to the output Excel file.
        :param sheet_name: The name of the sheet in the Excel file (default is "Sheet1").
        """
        try:
            filename = create_output_path(pcap_file, output_path, 'xlsx', 'stats')
            self.df.to_excel(filename, sheet_name=sheet_name, index=False)
            logger.always(f"DataFrame successfully written to {filename} in sheet '{sheet_name}'.")
        except Exception as e:
            logger.error(f"Error writing DataFrame to Excel: {e}")