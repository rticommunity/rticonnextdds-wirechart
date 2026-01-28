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
from enum import Enum
from platform import system
from collections import defaultdict

# Third-Party Library Imports
import matplotlib

from src.flex_dictionary import FlexDict

if system() == "Linux":
    matplotlib.use("TkAgg")  # or "Qt5Agg"
elif system() == "Windows":
    matplotlib.use("TkAgg")
# elif system() == "Darwin":  # macOS
#     matplotlib.use("MacOSX")  # or another backend supported on macOS

import matplotlib.pyplot as plt
import networkx as nx
from matplotlib.ticker import StrMethodFormatter
import numpy as np
import mplcursors

# Local Application Imports
from src.log_handler import logging
from src.rtps_frame import FrameTypes, GUIDEntity, RTPSFrame
from src.rtps_capture import RTPSCapture
from src.rtps_analyze_capture import DISCOVERY_TOPIC, RTPSAnalyzeCapture
from src.rtps_submessage import SubmessageTypes, SUBMESSAGE_COMBINATIONS, list_combinations_by_flag
from src.shared_utils import TEST_MODE

logger = logging.getLogger(__name__)

COLOR_PALETTE = ['red', 'blue', 'green', 'orange', 'purple', 'cyan', 'magenta', 'gold',
                 'teal', 'coral', 'olive', 'darkgreen', 'deepskyblue', 'mediumorchid']

# colors = [
#     "#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd", "#8c564b", "#e377c2",
#     "#7f7f7f", "#bcbd22", "#17becf", "#3a44b1", "#c43b2b", "#00996f", "#8b3cf9",
#     "#cc6d30", "#139abf", "#86b84f", "#cc33cc", "#e0a000"]

class PlotScale(Enum):
    LINEAR          = 'linear'
    LOGARITHMIC     = 'log'

def show_plot_on_top():
    plt.show(block=False)  # Show without blocking the GUI

    try:
        manager = plt.get_current_fig_manager()
        window = manager.window

        # Maximize window depending on backend/platform
        try:
            # For TkAgg (Windows)
            window.state('zoomed')
        except Exception:
            try:
                # For Qt5Agg
                window.showMaximized()
            except Exception:
                try:
                    # Generic fallback (if supported)
                    manager.resize(*manager.window.maxsize())
                except Exception:
                    logger.debug("Could not maximize the plot window.")

        # Bring the window to the front
        window.lift()
        window.focus_force()
        window.attributes('-topmost', True)
        window.after_idle(window.attributes, '-topmost', False)
    except Exception as e:
        logger.debug(f"Could not bring plot to front or maximize: {e}")

class RTPSDisplay():
    def __init__(self, no_gui=False):
        self.no_gui = no_gui
        logger.debug(f"Display backend used {matplotlib.get_backend()}")

    def count_participants(self, capture: RTPSCapture):
        participants = set()
        for frame in capture.frames:
            if FrameTypes.DISCOVERY in frame.frame_type:
                participants.add(frame.guid_prefix_and_entity_id(GUIDEntity.GUID_SRC)[0])
        return len(participants)

    def count_endpoints_by_topic_and_domain(self, endpoints: FlexDict, topic: str = None, domain: int = None, sort_by_domain: bool = True) -> list:
        """
        Counts unique DataWriters and DataReaders for each topic/domain combination.

        Args:
            topic (str, optional): The topic to filter by. If None, processes all topics. Defaults to None.
            domain (int, optional): The domain to filter by. Defaults to None.
            sort_by_domain (bool, optional): If True, sorts by domain first. If False, ignores domain in sorting. Defaults to True.

        Returns:
            list: A list of tuples containing topic/domain keys and their endpoint counts.
                 Format: "TOPIC_NAME (DW: #, DR: #)"

        Example:
            Square (DW: 3, DR: 2)
            Circle (DW: 2, DR: 1)
            Triangle (DW: 1, DR: 1)
        """
        def max_edges(edges):
            source_to_dests = defaultdict(set)

            for src, dst in edges:
                source_to_dests[src].add(dst)

            if not source_to_dests:
                return 0

            return max(len(dests) for dests in source_to_dests.values())

        topic_counts = {}

        # Get all topic/domain keys to iterate over
        if topic is not None:
            # Process only the specified topic
            if not endpoints.key_present(topic=topic):
                logger.warning(f"No endpoints found for topic '{topic}'")
                return ""

            elements = endpoints.get_elements_as_set(topic=topic, domain=domain)
            max_edge_count = max_edges(elements)
            dw_count = len({guid_src for guid_src, _ in elements})
            dr_count = len({guid_dst for _, guid_dst in elements})
            # Determine the actual domain (could be None if filtering all domains)
            actual_domain = domain if domain is not None else 0  # Default to 0 if None
            topic_counts[(topic, actual_domain)] = (max_edge_count, dw_count, dr_count)
        else:
            # Process all topics
            # Need to iterate through the endpoints dictionary structure
            for topic_key in endpoints.keys():
                elements = endpoints.get_elements_as_set(topic=topic_key.topic, domain=topic_key.domain)
                if elements:
                    max_edge_count = max_edges(elements)
                    dw_count = len({guid_src for guid_src, _ in elements})
                    dr_count = len({guid_dst for _, guid_dst in elements})
                    topic_counts[(topic_key.topic, topic_key.domain)] = (max_edge_count, dw_count, dr_count)

        # Sort by domain first (if enabled), then by DW ascending, then DR descending
        if sort_by_domain:
            sorted_items = sorted(topic_counts.items(), key=lambda x: (x[0][1], -x[1][0]))
        else:
            sorted_items = sorted(topic_counts.items(), key=lambda x: -x[1][0])
        
        # Remove total_endpoints from the tuple, keeping only (dw_count, dr_count)
        return [(key, (dw_count, dr_count)) for key, ( _ , dw_count, dr_count) in sorted_items]


    def count_endpoints_by_topic_string(self, endpoints: FlexDict, topic: str = None, domain: int = None) -> str:
        sorted_topics = self.count_endpoints_by_topic_and_domain(endpoints, topic=topic, domain=domain)
        # Format the output with domain headers and indented topics
        result = []
        current_domain = None
        for (topic_name, domain), (dw, dr) in sorted_topics:
            if domain != current_domain:
                if result:  # Add blank line between domains
                    result.append("")
                result.append(f"Domain {domain}")
                current_domain = domain
            result.append(f"\t{topic_name} (DW: {dw}, DR: {dr})")

        return "\n".join(result)

    def plot_endpoint_counts(self, endpoints: FlexDict, topic: str = None, domain: int = None):
        """
        Plots endpoint counts (DataWriters and DataReaders) in a vertical bar chart
        with separate bars for each topic.

        Args:
            endpoints (FlexDict): The endpoints dictionary containing topic/domain data.
            topic (str, optional): The topic to filter by. If None, processes all topics. Defaults to None.
            domain (int, optional): The domain to filter by. Defaults to None.
        """
        if self.no_gui:
            logger.warning("GUI is disabled. Cannot plot endpoint counts.")
            return

        sorted_topics = self.count_endpoints_by_topic_and_domain(endpoints, topic=topic, domain=domain, sort_by_domain=False)

        if not sorted_topics:
            logger.always("No endpoint data to plot.")
            return

        # Create figure
        fig, ax = plt.subplots(figsize=(16, 10))

        # Prepare data for plotting
        x_labels = []
        dw_counts = []
        dr_counts = []

        for (topic_name, topic_domain), (dw, dr) in sorted_topics:
            x_labels.append(f"{topic_name}")
            dw_counts.append(dw)
            dr_counts.append(dr)

        # Set up bar positions
        x_pos = np.arange(len(x_labels))
        bar_width = 0.35

        # Create bars
        bars1 = ax.bar(x_pos - bar_width/2, dw_counts, bar_width, label='DataWriters', color='lightblue', edgecolor='black')
        bars2 = ax.bar(x_pos + bar_width/2, dr_counts, bar_width, label='DataReaders', color='mistyrose', edgecolor='black')

        # Customize plot
        ax.set_ylabel('Endpoint Count', fontsize=12)
        ax.set_title('Endpoint Counts by Topic', fontsize=14, fontweight='bold')
        ax.set_xticks(x_pos)
        ax.set_xticklabels(x_labels, rotation=90, ha='center')
        ax.legend()
        ax.grid(axis='y', alpha=0.3)

        # Format y-axis with commas
        ax.get_yaxis().set_major_formatter(StrMethodFormatter('{x:,.0f}'))

        # Set window title
        fig.canvas.manager.set_window_title("Endpoint Counts by Topic")

        plt.tight_layout()
        show_plot_on_top()

    def count_writers_and_readers(self, capture: RTPSCapture, include_builtin=False):
        """
        Returns a tuple containing the number of writers and readers in the capture.

        :return: A tuple (num_writers, num_readers).
        """
        writers = set()
        readers = set()
        for frame in capture.frames:
            if include_builtin or not (FrameTypes.DISCOVERY in frame.frame_type):
                writers.add(frame.guid_src)
                if frame.guid_dst:
                    readers.add(frame.guid_dst)
        return len(writers), len(readers)

    def print_capture_summary(self, capture: RTPSCapture):
        """
        Prints a summary of the RTPSCapture, including the number of frames and unique topics.
        """
        lines = []

        num_writers, num_readers = self.count_writers_and_readers(capture)
        lines.append(f"{'Total Frames:':<20}{len(capture.frames):,}")
        lines.append(f"{'Total Participants:':<20}{self.count_participants(capture):,}")
        lines.append(f"{'Total Writers:':<20}{num_writers:,}")
        lines.append(f"{'Total Readers:':<20}{num_readers:,}")
        lines.append(f"{'Unique Topics:':<20}{len(capture.list_all_topics()):,}")
        return "\n".join(lines)

    def print_topics(self, capture: RTPSCapture):
        return sorted(capture.list_all_topics())

    def print_all_frames(self, capture: RTPSCapture):
        """
        Prints the details of all frames in the capture.
        """
        for frame in capture.frames:
            print(frame)

    def plot_multi_topic_graph(self, analysis: RTPSAnalyzeCapture, topic: str=None, domain: int=None):
        if self.no_gui:
            logger.warning("GUI is disabled. Cannot plot graphs.")
            return

        largest_topics = analysis.graph_edges.most_nodes(top_n=6, topic=topic, domain=domain)

        if not largest_topics:
            logger.always("No topics found with sufficient edges to plot graphs.")
            return
        if len(largest_topics) == 1:
            self.plot_topic_graph(analysis, topic=largest_topics[0].topic, domain=largest_topics[0].domain)
        else:
            # Create figure and axes
            fig, axs = plt.subplots(2, 3, figsize=(18, 14))

            # Set the main figure window title
            fig.canvas.manager.set_window_title("RTPS Topology Graphs for Top Topics")

            for i, key in enumerate(largest_topics):
                self.plot_topic_graph(analysis, topic=key.topic, domain=key.domain, ax=axs.flatten()[i])
            plt.tight_layout()
            show_plot_on_top()

    def plot_topic_graph(self, analysis: RTPSAnalyzeCapture, topic: str=None, domain: int=None, ax: plt.Axes = None):
        """
        Draws a directed graph using edges provided in a set of tuples.
        Labels the first node in each tuple as 'DW' and the second as 'DR'.

        Parameters:
            edge_tuples (set): Set of (source, target) tuples
        """
        if self.no_gui:
            logger.warning("GUI is disabled. Cannot plot graph.")
            return

        ax_none = (ax is None)

        # Ensure the topic exists in the graph edges
        if not analysis.graph_edges.key_present(topic=topic, domain=domain):
            logger.always(f"Topic '{topic}' does not have a topology graph.")
            return

        edges = analysis.graph_edges.get_elements_as_set(topic=topic, domain=domain)

        G = nx.DiGraph()
        G.add_edges_from(edges)

        # Define a color map for start nodes (sources)
        source_colors = {}
        color_index = 0

        # Set node labels and edge colors
        edge_colors = []
        node_labels = {}
        sources = set()
        destinations = set()
        for src, dst in edges:
            node_labels[src] = "RS" if RTPSFrame.static_guid_prefix_and_entity_id(src)[0] in analysis.rs_guid_prefix else "DW"
            node_labels[dst] = "RS" if RTPSFrame.static_guid_prefix_and_entity_id(dst)[0] in analysis.rs_guid_prefix else "DR"
            if src not in source_colors:
                source_colors[src] = COLOR_PALETTE[color_index % len(COLOR_PALETTE)]
                color_index += 1
            edge_colors.append(source_colors[src])
            sources.add(src)
            destinations.add(dst)

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

        # Assume: sources and destinations are lists
        sources = list(sources)
        destinations = list(destinations)

        pos = {}

        n_sources = len(sources)
        n_dests = len(destinations)

        # Plot layout parameters
        top_y = 0.8        # vertical position for sources (top)
        bottom_y = 0.2     # vertical position for destinations (bottom)
        center_x = 0.5

        # ---- Sources (top row) ----
        if n_sources == 1:
            pos[sources[0]] = (center_x, top_y)
        else:
            # Evenly spaced x positions between 0.01 and 0.99
            xs = np.linspace(0.01, 0.99, n_sources)
            for x, source in zip(xs, sources):
                pos[source] = (x, top_y)

        # ---- Destinations (bottom row) ----
        if n_dests == 1:
            pos[destinations[0]] = (center_x, bottom_y)
        else:
            xs = np.linspace(0.01, 0.99, n_dests)
            for x, dest in zip(xs, destinations):
                pos[dest] = (x, bottom_y)

        # If no Axes passed, create a new figure and axes
        if ax_none:
            fig, ax = plt.subplots(figsize=(14, 10))
            fig.canvas.manager.set_window_title(f"RTPS Topology Graph for Topic: {topic}")

        # Draw graph using the correct Axes
        nx.draw_networkx_nodes(G, pos, ax=ax, node_size=1000, node_color=node_colors, edgecolors='black')
        nx.draw_networkx_labels(G, pos, ax=ax, labels=node_labels, font_size=10, font_weight='bold')
        nx.draw_networkx_edges(
            G,
            pos,
            ax=ax,
            edgelist=list(edges),
            edge_color=edge_colors,
            arrowstyle='-|>',
            arrowsize=20,
            width=1,
            node_size=1000
        )

        topic_label = topic if isinstance(topic, str) else "All Topics"
        domain_label = domain if isinstance(domain, int) else "All Domains"

        ax.set_title(f"Topic: {topic_label}, Domain: {domain_label}", fontsize=14)
        ax.axis('off')

        if ax_none:
            plt.tight_layout()
            show_plot_on_top()

    def print_stats(self, analysis: RTPSAnalyzeCapture):
        """
        Prints statistics about the PCAP data, including total messages,
        messages by topic, and messages by submessage type.
        """
        lines = []
        # Calculate total messages
        total_messages = analysis.df['count'].sum()
        lines.append(f"Total number of messages: {total_messages:,}")

        # Total messages by topic
        total_messages_by_topic = analysis.df.groupby('topic')['count'].sum().sort_values(ascending=False)
        lines.append("  Total messages by topic:")
        for topic, count in total_messages_by_topic.items():
            lines.append(f"    {topic}: {count:,}")

        # Submessage counts
        submessage_counts = analysis.df.groupby('sm', observed=False)['count'].sum()
        lines.append("  Submessage counts:")
        for submsg in [str(s) for s in SUBMESSAGE_COMBINATIONS]:
            if submsg in submessage_counts:
                lines.append(f"    {submsg}: {submessage_counts[submsg]}")

        # Include any submessages not in SUBMESSAGE_COMBINATIONS
        for submsg, count in submessage_counts.items():
            if submsg not in [str(s) for s in SUBMESSAGE_COMBINATIONS]:
                lines.append(f"  {submsg}: {count:,}")

        return "\n".join(lines)

    def print_stats_in_bytes(self, analysis: RTPSAnalyzeCapture):
        """
        Prints statistics about the PCAP data in bytes, including total message lengths,
        lengths by topic, and lengths by submessage type.
        """
        lines = []
        # Calculate total message length
        total_length = analysis.df['length'].sum()
        lines.append(f"Total message length: {total_length:,} bytes")

        # Total message length by topic
        total_length_by_topic = analysis.df.groupby('topic')['length'].sum().sort_values(ascending=False)
        lines.append("  Total message length by topic:")
        for topic, length in total_length_by_topic.items():
            lines.append(f"    {topic}: {length:,} bytes")

        # Submessage lengths
        submessage_lengths = analysis.df.groupby('sm', observed=False)['length'].sum()
        lines.append("  Submessage lengths:")
        for submsg in [str(s) for s in SUBMESSAGE_COMBINATIONS]:
            if submsg in submessage_lengths:
                lines.append(f"    {submsg}: {submessage_lengths[submsg]:,} bytes")
        for submsg, length in submessage_lengths.items():
            if submsg not in [str(s) for s in SUBMESSAGE_COMBINATIONS]:
                lines.append(f"    {submsg}: {length:,} bytes")

        return "\n".join(lines)

    def print_instances_found(self, analysis: RTPSAnalyzeCapture):
        """
        Prints the instance count for each topic in the capture.
        """
        # lines = []
        # lines.append("Instance IDs found by topic:")
        # for topic, instances in analysis.instances_found.items():
        #     instance_list = ', '.join(f"0x{instance_id:06X}" for instance_id in sorted(instances))
        #     lines.append(f"  {topic}: {instance_list}")
        # return "\n".join(lines)
        lines = []
        lines.append("Instance count by topic:")
        for topic, instances in analysis.instances_found.items():
            instance_count = len(instances)
            lines.append(f"  {topic}: {instance_count}")
        return "\n".join(lines)

    def plot_stats_by_frame_count(self, analysis: RTPSAnalyzeCapture, include_discovery=False, scale=PlotScale.LINEAR, enable_plot_cursors=False):
        if self.no_gui:
            logger.warning("GUI is disabled. Cannot plot statistics.")
            return
        self._plot_statistics(analysis, metric='count', include_discovery=include_discovery, scale=scale, enable_plot_cursors=enable_plot_cursors)

    def plot_stats_by_frame_length(self, analysis: RTPSAnalyzeCapture, include_discovery=False, scale=PlotScale.LINEAR, enable_plot_cursors=False):
        if self.no_gui:
            logger.warning("GUI is disabled. Cannot plot statistics.")
            return
        self._plot_statistics(analysis, metric='length', include_discovery=include_discovery, scale=scale, enable_plot_cursors=enable_plot_cursors)

    # TODO: Ensure correct order of submessages in the plot
    def _plot_statistics(self, analysis: RTPSAnalyzeCapture, metric='count', include_discovery=False, scale=PlotScale.LINEAR, enable_plot_cursors=False):
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
        df = analysis.df.copy()
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

        # Map colors to submessages
        color_mapping = {submsg: COLOR_PALETTE[i % len(COLOR_PALETTE)] for i, submsg in enumerate([str(s) for s in SUBMESSAGE_COMBINATIONS])}

        # Generate a list of colors for the submessage order
        plot_colors = [color_mapping[submsg] for submsg in submessage_order if submsg in color_mapping]

        # Plot the stacked bar chart with consistent colors
        ax = pivot_df.plot(kind='bar', stacked=True, figsize=(20, 13), color=plot_colors)

        # Add totals to the legend, filtering out submessages not in submessage_order
        submessage_totals = analysis.df.groupby('sm', observed=False)[metric].sum()
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

        # Set the window title
        fig = ax.get_figure()
        fig.canvas.manager.set_window_title(f"Submessage {metric.capitalize()} by Topic")

        # Add interactive cursor
        if enable_plot_cursors:
            cursor = mplcursors.cursor(ax, hover=True)
            @cursor.connect("add")
            def on_add(sel):
                height = sel.artist.patches[sel.index].get_height()
                sel.annotation.set_text(f'{sel.artist.get_label()}: {height:,.0f} {units}')

        # Adjust layout and show the plot
        plt.tight_layout()
        show_plot_on_top()