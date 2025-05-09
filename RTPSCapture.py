import subprocess
import os
import pandas as pd
from collections import defaultdict
import networkx as nx
import matplotlib.pyplot as plt
from RTPSFrame import *
from log_handler import logging
from enum import IntEnum

logger = logging.getLogger(__name__)

DISCOVERY_TOPIC = "DISCOVERY"

class FrameClassification(IntEnum):
    STANDARD_FRAME = 0
    REPAIR = 1
    DURABLE_REPAIR = 2

class GUIDKey(IntEnum):
    GUID_SRC = 0
    GUID_DST = 1

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
        self.graph_edges = defaultdict(set)
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

    def count_participants(self):
        participants = set()
        for frame in self.frames:
            if frame.discovery_frame:
                participants.add(frame.guid_prefix_and_entity_id()[0])
        return len(participants)

    def count_writers_and_readers(self, include_builtin=False):
        """
        Returns a tuple containing the number of writers and readers in the capture.

        :return: A tuple (num_writers, num_readers).
        """
        writers = set()
        readers = set()
        for frame in self.frames:
            if include_builtin or not frame.discovery_frame:
                writers.add(frame.guid_src)
                if frame.guid_dst:
                    readers.add(frame.guid_dst)
        return len(writers), len(readers)

    def print_capture_summary(self):
        """
        Prints a summary of the RTPSCapture, including the number of frames and unique topics.
        """
        print(f"Total Frames: {len(self.frames)}")
        print(f"Total Participants: {self.count_participants()}")
        num_writers, num_readers = self.count_writers_and_readers()
        print(f"Total Writers: {num_writers} and Readers: {num_readers}")
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
                    logger.log(e.log_level, f"Frame {int(frame['frame.number']):09d} ignored. Message: {e}")
                    continue
                except KeyError as e:
                    logger.debug(f"Frame {int(frame['frame.number']):09d} ignored. Message: {e}")
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

        logger.always("Analyzing capture data...")

        frame_list = []  # List to store rows for the DataFrame
        sequence_numbers = defaultdict(int)  # Dictionary to store string keys and unsigned integer values
        durability_repairs = defaultdict(int) # Dictionary to keep track of sequence numbers for durability repairs

        # Process the PCAP data to count messages and include lengths
        for frame in self.frames:
            frame_classification = FrameClassification.STANDARD_FRAME
            if frame.guid_src is None:
                logger.error(f"Frame {frame.frame_number} has no GUID source. Exiting.")
                # TODO: Could maybe continue here, but exiting for now
                raise InvalidPCAPDataException(f"Frame {frame.frame_number} has no GUID source. Exiting.")
            guid_key = (frame.guid_src, frame.guid_dst)
            for sm in frame:
                topic = sm.topic
                # TODO: This method doesn't work for best effort.  A better approach would be to:
                # 1. Differentiate between DATA(w) and DATA(r)s when creating Frame/SMs
                # 2. For DATA(w) SMs, save guid_key to graph_edges[topic]
                # 3. Test with square_best_effort.pcapng
                # 4. May need to understand better, this approach may not be correct
                if not frame.discovery_frame and all(x is not None for x in guid_key):
                    self.graph_edges[topic].add(guid_key)
                if frame.discovery_frame:
                    topic = DISCOVERY_TOPIC
                # TODO: Verify not to do this with GAP
                if "HEARTBEAT" in sm.sm_type.name:
                    # Not all submessages have a DST GUID, so we must only use the SRC GUID to key
                    # the SN dictionary.  Since the SN of a writer is not dependent on the reader,
                    # this approach is valid.
                    sequence_numbers[guid_key[GUIDKey.GUID_SRC]] = sm.seq_num()
                elif sm.sm_type in (SubmessageTypes.DATA, SubmessageTypes.DATA_FRAG, SubmessageTypes.DATA_BATCH):
                    # TODO: Discovery repairs?
                    # TODO: Durability repairs?
                    # Check if this submessage is some form of a repair
                    if sm.seq_num() <= sequence_numbers[guid_key[GUIDKey.GUID_SRC]]:
                        # If this is a repair, there will be a GUID_DST, and we can key on the entire GUID_KEY
                        if sm.seq_num() <= durability_repairs[guid_key]:
                            sm.sm_type = SubmessageTypes.DATA_DURABILITY_REPAIR
                            frame_classification = FrameClassification.DURABLE_REPAIR
                        else:
                            sm.sm_type = SubmessageTypes.DATA_REPAIR
                            frame_classification = FrameClassification.REPAIR
                # TODO: Add support for Discovery repairs?
                elif sm.sm_type == SubmessageTypes.ACKNACK:
                    # Record the writer SN when the first non-zero ACKNACK is received.  All repairs with
                    # a SN less than or equal to this number are considered durability repairs while all
                    # repairs after this SN are considered standard repairs.
                    if sm.seq_num() > 0 and guid_key not in durability_repairs:
                        # Only add this for the first non-zero ACKNACK
                        durability_repairs[guid_key] = sequence_numbers[guid_key[GUIDKey.GUID_SRC]]

                frame_list.append({'topic': topic, 'sm': sm.sm_type.name, 'count': 1, 'length': sm.length})

            if frame_classification > FrameClassification.STANDARD_FRAME:
                logger.info(f"Frame {frame.frame_number} classified as {frame_classification.name}.")

        if not any(frame.get('topic') != 'DISCOVERY' for frame in frame_list):
            raise InvalidPCAPDataException("No RTPS user frames with associated discovery data")

        # Convert the rows into a DataFrame
        df = pd.DataFrame(frame_list)

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

    def plot_multi_topic_graph(self):
        topic_node_counts = {
            topic: len(set([n for edge in edges for n in edge]))
            for topic, edges in self.graph_edges.items()
        }
        top_topics = sorted(topic_node_counts, key=topic_node_counts.get, reverse=True)[:6]

        _ , axs = plt.subplots(2, 3, figsize=(18, 14))
        for i, topic in enumerate(top_topics):
            self.plot_topic_graph(topic=topic, ax=axs.flatten()[i])
        plt.tight_layout()
        plt.show()

    def plot_topic_graph(self, topic = None, ax = None):
        """
        Draws a directed graph using edges provided in a set of tuples.
        Labels the first node in each tuple as 'DW' and the second as 'DR'.

        Parameters:
            edge_tuples (set): Set of (source, target) tuples
        """
        # TODO: Make this a hierarchical graph so that all writers are on the left and all readers are on the right

        # TODO: Maybe remove this?
        # If not topic is provided, use the one with the most edges

        ax_none = (ax is None)

        if not topic:
            topic = max(self.graph_edges, key=lambda k: len(self.graph_edges[k]))

        G = nx.DiGraph()
        G.add_edges_from(self.graph_edges[topic])

        # Layout
        pos = nx.spring_layout(G, k=4, iterations=100, seed=42)

        # Define a color map for start nodes (sources)
        source_colors = {}
        color_palette = ['red', 'blue', 'green', 'orange', 'purple', 'cyan', 'magenta',
                        'gold', 'teal', 'coral', 'olive', 'darkgreen', 'deepskyblue', 'mediumorchid']
        color_index = 0

        edge_colors = []
        node_labels = {}
        for src, dst in self.graph_edges[topic]:
            node_labels[src] = "DW"
            node_labels[dst] = "DR"
            if src not in source_colors:
                source_colors[src] = color_palette[color_index % len(color_palette)]
                color_index += 1
            edge_colors.append(source_colors[src])

        # If no Axes passed, create a new figure and axes
        if ax_none:
            fig, ax = plt.subplots(figsize=(14, 10))

        # Draw graph using the correct Axes
        nx.draw_networkx_nodes(G, pos, ax=ax, node_size=2000, node_color='lightblue', edgecolors='black')
        nx.draw_networkx_labels(G, pos, ax=ax, labels=node_labels, font_size=12, font_weight='bold')
        nx.draw_networkx_edges(
            G,
            pos,
            ax=ax,
            edgelist=list(self.graph_edges[topic]),
            edge_color=edge_colors,
            arrowstyle='-|>',
            arrowsize=20,
            width=1,
            node_size=2000
        )

        ax.set_title(f"Topic: {topic}", fontsize=14)
        ax.axis('off')

        if ax_none:
            plt.tight_layout()
            plt.show()