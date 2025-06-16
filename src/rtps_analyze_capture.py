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
from dataclasses import dataclass, field
from enum import IntEnum

# Third-Party Library Imports
import pandas as pd
from tqdm import tqdm

# Local Application Imports
from src.flex_dictionary import FlexDictKey, FlexDict
from src.log_handler import logging
from src.rtps_frame import FrameTypes, GUIDEntity, RTPSFrame
from src.shared_utils import DEV_DEBUG, TEST_MODE, InvalidPCAPDataException, create_output_path
from src.rtps_capture import RTPSCapture
from src.rtps_submessage import SubmessageTypes, SUBMESSAGE_COMBINATIONS, list_combinations_by_flag, RTPSSubmessage

logger = logging.getLogger(__name__)

DISCOVERY_TOPIC = "DISCOVERY"
META_DATA_TOPIC = "META_DATA"

@dataclass
class FrameSequenceTracker:
    frame_number: int
    sequence_number: int

@dataclass
class RepairTracker:
    last_heartbeat: dict = field(default_factory=dict)          # Tracks the last heartbeat for each GUID pair
    last_acknack: dict = field(default_factory=dict)            # Tracks the last ACKNACK for each GUID pair
    durability_sn: dict = field(default_factory=dict)           # Tracks the initial sequence number for durability repairs
    durable_repairs_sent: dict = field(default_factory=dict)    # Tracks the sequence numbers of durable repairs sent for each GUID pair


class RTPSAnalyzeCapture:
    def __init__(self, capture: RTPSCapture):
        self.graph_edges = FlexDict()
        # TODO: Should this be a defaultdict of sets?
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
        Counts user messages and preprocesses the data to convert to a pandas DataFrame.
        Perform reliability/durability repair analysis.
        """
        logger.always("Analyzing capture data...")

        sm_list = []  # List to store rows for the DataFrame
        repair_tracker = RepairTracker()

        # Process the PCAP data to count messages and include lengths
        for frame in tqdm(self.capture.frames, disable=TEST_MODE):
            frame_classification = SubmessageTypes.UNSET
            self._set_routing_service_nodes(frame)
            self._set_graph_nodes(frame)
            # Create a GUID key for the SRC and DST GUIDs
            guid_key = (frame.guid_src, frame.guid_dst)
            for sm in frame:
                topic = RTPSAnalyzeCapture._get_topic(frame)
                RTPSAnalyzeCapture._process_submessage(frame.frame_number, sm, repair_tracker, guid_key)
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
        Sets the graph edges based on the frame's GUID.
        This method is called during the analysis of the capture to build the topology graph.
        """
        if (FrameTypes.USER_DATA == frame.frame_type) and all([frame.guid_src, frame.guid_dst]):
            key = FlexDictKey(frame.get_topic(), frame.get_domain_id())
            try:
                # Attempt to add the edge to the graph edge set.
                self.graph_edges[key].add((frame.guid_src, frame.guid_dst))
            except KeyError:
                # If the key/set does not exist, create it.
                self.graph_edges[key] = {(frame.guid_src, frame.guid_dst)}


    # Ensure all unique topics are included in the DataFrame
    def include_missing_topics_and_sm(self, all_topics, sm_list):
        missing_list = []
        for topic in all_topics:
            for sm_type in sm_list:
                if not ((self.df['topic'] == topic) & (self.df['sm'] == str(sm_type))).any():
                    missing_list.append({'topic': topic, 'sm': str(sm_type), 'count': 0, 'length': 0})
        return missing_list

    @staticmethod
    def _process_submessage(frame_number: int, sm: RTPSSubmessage, repair_tracker: RepairTracker, guid_key: tuple):

        def get_heartbeat_sn(last_heartbeat: dict, guid_key: tuple) -> int:
            """
            Returns the maximum sequence number from the last heartbeat for the given GUID key.
            Also checks for GUID_DST=None.  Raises KeyError if no sequence number is found.
            """
            seq_num = []
            keys = [guid_key, (guid_key[GUIDEntity.GUID_SRC], None)]

            for key in keys:
                try:
                    seq_num.append(last_heartbeat[key].sequence_number)
                except KeyError:
                    pass
            if not seq_num:
                raise KeyError(f"No heartbeat found for GUID key: {guid_key}")
            # Return the maximum sequence number found
            return max(seq_num)

        # TODO: Not sure how to handle FRAGs, so ignoring them for now
        if (sm.sm_type & SubmessageTypes.DATA) and not (sm.sm_type & SubmessageTypes.FRAGMENT):
        # if (sm.sm_type & SubmessageTypes.DATA):
            try:
                # To qualify as a repair, the sequence number must be less than or equal to the last HEARTBEAT and
                # must be sent after the last ACKNACK for this GUID pair.
                if (sm.seq_num() <= get_heartbeat_sn(repair_tracker.last_heartbeat, guid_key)) and \
                   (repair_tracker.last_acknack[guid_key].frame_number > repair_tracker.last_heartbeat[guid_key].frame_number):
                        sm.sm_type |= SubmessageTypes.REPAIR
                        if sm.seq_num() <= repair_tracker.durability_sn[guid_key].sequence_number:
                            if (guid_key in repair_tracker.durable_repairs_sent) and \
                               (sm.seq_num() <= repair_tracker.durable_repairs_sent[guid_key]):
                                # The durable repair has already been sent, so this is just a standard repair.
                                pass
                            else: # This is a durable repair
                                sm.sm_type |= SubmessageTypes.DURABLE
                                if guid_key in repair_tracker.durable_repairs_sent:
                                    # Repairs should be sequential, but check just in case.
                                    if sm.seq_num() > repair_tracker.durable_repairs_sent[guid_key]:
                                        repair_tracker.durable_repairs_sent[guid_key] = sm.seq_num()
                                else:
                                    # If the key does not exist, this is likely the first time
                                    # we are seeing this GUID pair.  Just add it.
                                    repair_tracker.durable_repairs_sent[guid_key] = sm.seq_num()
            except KeyError:
                # If the key does not exist, it means this is the first time we are seeing this GUID pair.
                # We can safely assume that this is not a repair.
                pass
        elif sm.sm_type & SubmessageTypes.HEARTBEAT:
            repair_tracker.last_heartbeat[guid_key] = FrameSequenceTracker(frame_number, sm.seq_num())
        elif sm.sm_type & SubmessageTypes.ACKNACK:
            repair_tracker.last_acknack[guid_key] = FrameSequenceTracker(frame_number, sm.seq_num())
            # Record the writer SN when the first non-zero ACKNACK is received.  All repairs with
            # a SN less than or equal to this number are considered durability repairs while all
            # repairs after this SN are considered standard repairs.
            if sm.seq_num() > 0 and guid_key not in repair_tracker.durability_sn:
                # Only add this for the first non-zero ACKNACK
                try:
                    repair_tracker.durability_sn[guid_key] = FrameSequenceTracker(frame_number, get_heartbeat_sn(repair_tracker.last_heartbeat, guid_key))
                except KeyError:
                    guid_key_str = [f"{x:#x}" for x in guid_key]
                    logger.warning(f"ACKNACK received for GUID key {guid_key_str} without a previous HEARTBEAT.")

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

    def to_json(self):
        """
        Converts the RTPSAnalyzeCapture object to a JSON-serializable dictionary.
        This method is useful for exporting the analysis results in a structured format.
        :return: A dictionary representation of the RTPSAnalyzeCapture object.
        """
        return {
            'nodes_edges': self.graph_edges.to_dict(),
            'rs_guid_prefix': list(self.rs_guid_prefix),
            'statistics': self.df.to_dict(orient='records'),  # Convert DataFrame to a list of dictionaries
            **self.capture.to_json()
        }