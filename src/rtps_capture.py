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
from enum import Enum, IntEnum

# Third-Party Library Imports
import matplotlib.pyplot as plt
import networkx as nx
import pandas as pd
from matplotlib.ticker import StrMethodFormatter

# Local Application Imports
from src.log_handler import logging
from src.rtps_frame import RTPSFrame, FrameTypes
from src.builders.rtps_frame_builder import RTPSFrameBuilder
from src.shared_utils import DEV_DEBUG, InvalidPCAPDataException, NoDiscoveryDataException, create_output_path, guid_prefix
from src.rtps_submessage import SubmessageTypes, SUBMESSAGE_COMBINATIONS, list_combinations_by_flag

logger = logging.getLogger(__name__)

class PlotScale(Enum):
    LINEAR          = 'linear'
    LOGARITHMIC     = 'log'

DISCOVERY_TOPIC = "DISCOVERY"
META_DATA_TOPIC = "META_DATA"

# tshark seems to return commands in a hierarchy, i.e. frame -> udp -> rtps so order matters
PCAP_FIELDS = list(['frame.number', 'frame.len',
                    'ip.src', 'ip.dst',
                    'rtps.guidPrefix.src', 'rtps.sm.wrEntityId',        # Writer GUID
                    'rtps.guidPrefix.dst', 'rtps.sm.rdEntityId',        # Reader GUID
                    'rtps.sm.seqNumber', 'rtps.sm.octetsToNextHeader',
                    'rtps.sm.id', 'rtps.param.service_kind', '_ws.col.Info'])

class RTPSCapture:
    """
    Represents a collection of RTPSFrame objects extracted from a PCAP file.
    Provides methods to manage and analyze the captured frames.
    """

    def __init__(self):
        """
        Initializes an empty RTPSCapture object.
        """
        self.frames = []  # List to store RTPSFrame objects
        self.graph_edges = defaultdict(set)
        self.rs_guid_prefix = set()
        self.df = pd.DataFrame()  # DataFrame to store analysis results

    def __eq__(self, value):
        if isinstance(value, RTPSCapture):
            return (self.frames == value.frames and
                    self.graph_edges == value.graph_edges and
                    self.df.equals(value.df))
        else:
            return False

    def partial_eq(self, value):
        if isinstance(value, RTPSCapture):
            return (self.graph_edges == value.graph_edges and
                    self.df.equals(value.df))
        else:
            return False

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
            if FrameTypes.DISCOVERY in frame.frame_type:
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
            if include_builtin or not (FrameTypes.DISCOVERY in frame.frame_type):
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

    def print_topics(self):
        print("Topics:")
        for topic in sorted(self.list_all_topics()):
            print(f"  - {topic}")

    def print_all_frames(self):
        """
        Prints the details of all frames in the capture.
        """
        for frame in self.frames:
            print(frame)

    def extract_rtps_frames(self, read_pcap_method, pcap_file, fields=PCAP_FIELDS , display_filter=None, start_frame=None, finish_frame=None, max_frames=None):
        """
        Extracts RTPS frames from a pcap file by using an injected method to read the data.

        :param read_pcap_method: Callable that reads the pcap file and returns raw frame data
        :param pcap_file: Path to the pcap file
        :param fields: Set of fields to extract
        :param display_filter: Optional display filter
        :param start_frame: Optional start frame number
        :param finish_frame: Optional finish frame number
        :param max_frames: Optional limit on number of packets
        """
        logger.always("Reading data from pcap file using the provided method...")
        frame_dict = read_pcap_method(pcap_file, fields, display_filter, start_frame, finish_frame, max_frames)
        self._process_frames(frame_dict)

    def _process_frames(self, frame_dict):
        """
        Processes frame dictionary list and populates the RTPSCapture object.

        :param frame_data: List of dictionaries containing (field, value) pairs for each frame
        :param fields: Set of fields to extract
        """
        if not frame_dict:
            raise InvalidPCAPDataException("No RTPS frames to process")

        total_frames = len(frame_dict)
        progress_interval = max(total_frames // 10, 1)  # Avoid division by zero for small datasets

        exception_counts = {
            "frame_critical_errors": 0,
            "frame_errors": 0,
            "frame_warnings": 0,
            "discovery_warnings": 0
        }

        for i, frame in enumerate(frame_dict):
            try:
                self.add_frame(RTPSFrameBuilder(frame).build())  # Create a RTPSFrame object for each record
            except InvalidPCAPDataException as e:
                logger.log(e.log_level, f"Frame {int(frame['frame.number']):09d} ignored. Message: {e}")
                if e.log_level == logging.CRITICAL:
                    exception_counts["frame_critical_errors"] += 1
                    if DEV_DEBUG:
                        raise e
                elif e.log_level == logging.ERROR:
                    exception_counts["frame_errors"] += 1
                elif e.log_level == logging.WARNING:
                    exception_counts["frame_warnings"] += 1
                continue
            except NoDiscoveryDataException as e:
                exception_counts["discovery_warnings"] += 1
                logger.warning(f"Frame {int(frame['frame.number']):09d} ignored. Message: {e}")
                continue
            except KeyError as e:
                exception_counts["frame_errors"] += 1
                logger.debug(f"Frame {int(frame['frame.number']):09d} ignored. Message: {e}")
                continue
            # Print progress every 10%
            if (i + 1) % progress_interval == 0 or (i + 1) == total_frames:
                percent = ((i + 1) * 100) // total_frames
                logger.always(f"Processing {percent}% complete")

        logger.always(f"Discovery warnings: {exception_counts['discovery_warnings']} | "
                      f"Critical errors: {exception_counts['frame_critical_errors']} | "
                      f"Frame warnings: {exception_counts['frame_warnings']} | "
                      f"Frame errors: {exception_counts['frame_errors']}")
    # TODO: Refactor this method to its own class and extract methods for each step (irene)
    def analyze_capture(self):
        """
        Counts user messages and returns the data as a pandas DataFrame.
        Ensures all unique topics are included, even if they have no messages.
        Orders the submessages based on SUBMESSAGE_ORDER and includes the length.

        :param pcap_data: A list of dictionaries containing the extracted PCAP data.
        :param unique_topics: A set of unique topics to initialize the DataFrame.
        :return: A pandas DataFrame with columns ['Topic', 'Submessage', 'Count', 'Length'].
        """
        # Declare the GUIDKey enum for local scope
        class GUIDKey(IntEnum):
            GUID_SRC        = 0
            IP_SRC          = 1
            GUID_DST        = 2
            IP_DST          = 3

        logger.always("Analyzing capture data...")

        frame_list = []  # List to store rows for the DataFrame
        sequence_numbers = defaultdict(int)  # Dictionary to store string keys and unsigned integer values
        durability_repairs = defaultdict(int) # Dictionary to keep track of sequence numbers for durability repairs

        # Process the PCAP data to count messages and include lengths
        for frame in self.frames:
            frame_classification = SubmessageTypes.UNSET
            if frame.guid_src is None:
                logger.error(f"Frame {frame.frame_number} has no GUID source. Exiting.")
                # TODO: Could maybe continue here, but exiting for now
                raise InvalidPCAPDataException(f"Frame {frame.frame_number} has no GUID source. Exiting.")
            if FrameTypes.ROUTING_SERVICE in frame.frame_type:
                # Add the GUID prefix to the set of Routing Service GUID prefixes
                self.rs_guid_prefix.add(frame.guid_prefix_and_entity_id()[0])
            # Create a unique key using the GUIDs and IP addresses.  This is required in the event multiple interfaces are used.
            guid_key = (frame.guid_src, frame.ip_src, frame.guid_dst, frame.ip_dst)
            for sm in frame:
                topic = sm.topic
                # TODO: Probably want to just check for USER_DATA and ignore other flags
                # TODO: Add this check after the frame is classified as a repair?  Otherwise,
                # multicast frame repairs might be added to the graph, which doesn't accurately
                # represent the topology for a multicast writer.
                if (FrameTypes.DISCOVERY not in frame.frame_type) and all([frame.guid_src, frame.guid_dst]):
                    self.graph_edges[topic].add((frame.guid_src, frame.guid_dst))
                if FrameTypes.DISCOVERY in frame.frame_type:
                    topic = DISCOVERY_TOPIC
                elif FrameTypes.META_DATA in frame.frame_type:
                    topic = META_DATA_TOPIC
                # TODO: Verify not to do this with GAP
                if sm.sm_type & SubmessageTypes.HEARTBEAT:
                    # Not all submessages have a DST GUID, so we must only use the SRC GUID to key
                    # the SN dictionary.  Since the SN of a writer is not dependent on the reader,
                    # this approach is valid.
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

                frame_classification |= sm.sm_type
                frame_list.append({'topic': topic, 'sm': str(sm.sm_type), 'count': 1, 'length': sm.length})

            if frame_classification & (SubmessageTypes.REPAIR | SubmessageTypes.DURABLE):
                frame_classification &= (SubmessageTypes.DISCOVERY | SubmessageTypes.DATA |
                                         SubmessageTypes.FRAGMENT | SubmessageTypes.REPAIR | SubmessageTypes.DURABLE)
                logger.info(f"Frame {frame.frame_number} classified as {frame_classification}.")

        if not any(frame.get('topic') != 'DISCOVERY' for frame in frame_list):
            raise InvalidPCAPDataException("No RTPS user frames with associated discovery data")

        # Convert the rows into a DataFrame
        self.df = pd.DataFrame(frame_list)

        # Aggregate the counts and lengths for each (Topic, Submessage) pair
        self.df = self.df.groupby(['topic', 'sm'], as_index=False).agg({'count': 'sum', 'length': 'sum'})

        # Ensure all unique topics are included in the DataFrame
        def include_missing_topics_and_sm(df, all_topics, sm_list):
            missing_list = []
            for topic in all_topics:
                for sm_type in sm_list:
                    if not ((df['topic'] == topic) & (df['sm'] == str(sm_type))).any():
                        missing_list.append({'topic': topic, 'sm': str(sm_type), 'count': 0, 'length': 0})
            return missing_list

        all_rows = []
        all_rows.extend(include_missing_topics_and_sm(self.df, {DISCOVERY_TOPIC}, list_combinations_by_flag(SubmessageTypes.DISCOVERY)))
        # Do not include missing topics/SMs for META_DATA_TOPIC
        all_rows.extend(include_missing_topics_and_sm(self.df, self.list_all_topics(), list_combinations_by_flag(SubmessageTypes.DISCOVERY, negate=True)))

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

        duplicates = self.df[self.df.duplicated(subset=['topic', 'sm'], keep=False)]
        if not duplicates.empty:
            print("Duplicate entries found:")
            print(duplicates)
    # TODO: move the plot_* and print_* methods to a separate class (irene)
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
        ax_none = (ax is None)

        if topic not in self.graph_edges:
            logger.always(f"Topic '{topic}' does not have a topology graph.")
            return

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

        # Set node labels and edge colors
        edge_colors = []
        node_labels = {}
        for src, dst in self.graph_edges[topic]:
            node_labels[src] = "RS" if guid_prefix(src) in self.rs_guid_prefix else "DW"
            node_labels[dst] = "RS" if guid_prefix(dst) in self.rs_guid_prefix else "DR"
            if src not in source_colors:
                source_colors[src] = color_palette[color_index % len(color_palette)]
                color_index += 1
            edge_colors.append(source_colors[src])

        # Set node colors based on labels
        node_colors = []
        for node in G.nodes():
            if node_labels.get(node) == "DW":
                node_colors.append("lightblue")   # Color for DW nodes
            elif node_labels.get(node) == "DR":
                node_colors.append("mistyrose")   # Color for DR nodes
            elif node_labels.get(node) == "RS":
                node_colors.append("lightyellow")   # Color for DR nodes
            else:
                node_colors.append("gray")        # Fallback for undefined

        # If no Axes passed, create a new figure and axes
        if ax_none:
            fig, ax = plt.subplots(figsize=(14, 10))

        # Draw graph using the correct Axes
        nx.draw_networkx_nodes(G, pos, ax=ax, node_size=2000, node_color=node_colors, edgecolors='black')
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

    def print_stats(self):
        """
        Prints statistics about the PCAP data, including total messages,
        messages by topic, and messages by submessage type.
        """
        # Calculate total messages
        total_messages = self.df['count'].sum()
        print(f"Total number of messages: {total_messages}")

        # Calculate total messages by topic and sort in descending order
        total_messages_by_topic = self.df.groupby('topic')['count'].sum().sort_values(ascending=False)
        print(f"{' ' * 2}Total messages by topic:")
        for topic, count in total_messages_by_topic.items():
            print(f"{' ' * 4}{topic}: {count}")

        # Calculate counts for each submessage type
        submessage_counts = self.df.groupby('sm', observed=False)['count'].sum()
        print(f"{' ' * 2}Submessage counts:")
        for submsg in [str(s) for s in SUBMESSAGE_COMBINATIONS]:
            if submsg in submessage_counts:
                print(f"{' ' * 4}{submsg}: {submessage_counts[submsg]}")
        for submsg, count in submessage_counts.items():
            if submsg not in [str(s) for s in SUBMESSAGE_COMBINATIONS]:
                print(f"  {submsg}: {count}")
        print()

    def print_stats_in_bytes(self):
        """
        Prints statistics about the PCAP data in bytes, including total message lengths,
        lengths by topic, and lengths by submessage type.
        """
        # Calculate total message length
        total_length = self.df['length'].sum()
        print(f"Total message length: {total_length:,} bytes")

        # Calculate total message length by topic and sort in descending order
        total_length_by_topic = self.df.groupby('topic')['length'].sum().sort_values(ascending=False)
        print(f"{' ' * 2}Total message length by topic:")
        for topic, length in total_length_by_topic.items():
            print(f"{' ' * 4}{topic}: {length:,} bytes")

        # Calculate total lengths for each submessage type
        submessage_lengths = self.df.groupby('sm', observed=False)['length'].sum()
        print(f"{' ' * 2}Submessage lengths:")
        # Get all submessage types
        for submsg in [str(s) for s in SUBMESSAGE_COMBINATIONS]:
            if submsg in submessage_lengths:
                print(f"{' ' * 4}{submsg}: {submessage_lengths[submsg]:,} bytes")
        for submsg, length in submessage_lengths.items():
            if submsg not in [str(s) for s in SUBMESSAGE_COMBINATIONS]:
                print(f"{' ' * 4}{submsg}: {length:,} bytes")
        print()

    def plot_stats_by_frame_count(self, include_discovery=False, scale=PlotScale.LINEAR):
        self._plot_statistics(metric='count', include_discovery=include_discovery, scale=scale)

    def plot_stats_by_frame_length(self, include_discovery=False, scale=PlotScale.LINEAR):
        self._plot_statistics(metric='length', include_discovery=include_discovery, scale=scale)

    # TODO: Ensure correct order of submessages in the plot
    def _plot_statistics(self, metric='count', include_discovery=False, scale=PlotScale.LINEAR):
        """
        Plots a stacked bar chart of submessage counts or lengths by topic.

        :param metric: The column to plot, either 'count' or 'length'.
        :param include_discovery: If False, excludes the "DISCOVERY" topic from the plot.
        :param scale: The scale of the y-axis, either PlotScale.LINEAR or PlotScale.LOGARITHMIC.
        """
        if metric not in ['count', 'length']:
            raise ValueError("Invalid metric. Choose either 'count' or 'length'.")

        # Define units based on the metric
        units = "messages" if metric == 'count' else "bytes"

        # Filter out the "DISCOVERY" topic if include_discovery is False
        df = self.df.copy()
        if not include_discovery:
            df = df[df['topic'] != DISCOVERY_TOPIC]

        # Ensure all submessages in SubmessageTypes are included, even if missing
        df = df.set_index(['topic', 'sm']).unstack(fill_value=0).stack(future_stack=True).reset_index()

        # Calculate total messages or lengths per topic and sort topics by total value
        df['TotalMetric'] = df.groupby('topic')[metric].transform('sum')
        df = df.sort_values(by='TotalMetric', ascending=False)

        # Pivot the DataFrame to prepare for plotting
        pivot_df = df.pivot(index='topic', columns='sm', values=metric).fillna(0)

        # Ensure the columns (submessages) are ordered based on SubmessageTypes
        submessage_order = [str(s) for s in (SUBMESSAGE_COMBINATIONS if include_discovery
            else list_combinations_by_flag(SubmessageTypes.DISCOVERY, negate=True))]
        pivot_df = pivot_df.reindex(columns=submessage_order, fill_value=0)

        # Filter out topics with no submessages (all values are zero)
        pivot_df = pivot_df[(pivot_df.sum(axis=1) > 0)]

        # Sort pivot_df by the total value of the metric (row-wise sum)
        pivot_df['TotalMetric'] = pivot_df.sum(axis=1)
        pivot_df = pivot_df.sort_values(by='TotalMetric', ascending=False)

        # Extract total metric values for each topic
        total_metric_by_topic = pivot_df['TotalMetric']
        pivot_df = pivot_df.drop(columns=['TotalMetric'])  # Remove the helper column

        # Define a consistent color mapping for submessages
        colors = [
            "#1f77b4",  # blue
            "#ff7f0e",  # orange
            "#2ca02c",  # green
            "#d62728",  # red
            "#9467bd",  # purple
            "#8c564b",  # brown
            "#e377c2",  # pink
            "#7f7f7f",  # gray
            "#bcbd22",  # lime
            "#17becf",  # cyan
            "#3a44b1",  # darker indigo
            "#c43b2b",  # deeper coral
            "#00996f",  # deeper teal
            "#8b3cf9",  # darker violet
            "#cc6d30",  # richer peach
            "#139abf",  # deeper sky blue
            "#86b84f",  # earthier green
            "#cc33cc",  # richer magenta
            "#e0a000"   # deeper sunflower yellow
        ]

        # Map colors to submessages
        color_mapping = {submsg: colors[i % len(colors)] for i, submsg in enumerate([str(s) for s in SUBMESSAGE_COMBINATIONS])}

        # Generate a list of colors for the submessage order
        plot_colors = [color_mapping[submsg] for submsg in submessage_order if submsg in color_mapping]

        # Plot the stacked bar chart with consistent colors
        ax = pivot_df.plot(kind='bar', stacked=True, figsize=(20, 13), color=plot_colors)

        # Add totals to the legend, filtering out submessages not in submessage_order
        submessage_totals = self.df.groupby('sm', observed=False)[metric].sum()
        filtered_totals = {label: total for label, total in submessage_totals.items() if label in submessage_order and total > 0}
        handles, labels = ax.get_legend_handles_labels()
        filtered_handles_labels = [
            (handle, label) for handle, label in zip(handles, labels) if label in filtered_totals
        ]
        filtered_handles, filtered_labels = zip(*filtered_handles_labels) if filtered_handles_labels else ([], [])
        ax.legend(
            filtered_handles,
            [f"{label} ({filtered_totals[label]:,} {units})" for label in filtered_labels],
            title='Submessage Types'
        )

        # Set axis labels and title
        topic_count = df['topic'].nunique() - int(include_discovery)
        topic_label = f"Topics ({topic_count:,}" + (" plus Discovery)" if include_discovery else ")")

        ax.set_xlabel(topic_label)
        ax.set_ylabel(f"{metric.capitalize()} ({df[metric].sum():,} {units})")
        ax.set_title(f"Submessage {metric.capitalize()} by Topic ({units})")

        # Update x-axis labels to include total metric values
        x_labels = [f"{topic} ({int(total_metric_by_topic[topic]):,})" for topic in pivot_df.index]
        ax.set_xticks(range(len(pivot_df.index)))
        ax.set_xticklabels(x_labels, rotation=90, ha='center')

        ax.set_yscale(scale.value)  # Set the y-axis scale (linear or logarithmic)

        # Disable scientific notation and format y-axis tick marks with commas
        ax.get_yaxis().set_major_formatter(StrMethodFormatter('{x:,.0f}'))

        # Adjust layout and show the plot
        plt.tight_layout()
        plt.show()

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