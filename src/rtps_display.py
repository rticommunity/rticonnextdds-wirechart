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

# Third-Party Library Imports
import matplotlib

if system() == "Linux":
    matplotlib.use("TkAgg")  # or "Qt5Agg"
elif system() == "Windows":
    matplotlib.use("TkAgg")
# elif system() == "Darwin":  # macOS
#     matplotlib.use("MacOSX")  # or another backend supported on macOS

import matplotlib.pyplot as plt
import networkx as nx
from matplotlib.ticker import StrMethodFormatter

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
        lines = [
            f"Total Frames: {len(capture.frames)}",
            f"Total Participants: {self.count_participants(capture)}"
        ]

        num_writers, num_readers = self.count_writers_and_readers(capture)
        lines.append(f"Total Writers: {num_writers} and Readers: {num_readers}")
        lines.append(f"Unique Topics: {len(capture.list_all_topics())}")
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

        # Layout
        pos = nx.spring_layout(G, k=4, iterations=100, seed=42)

        # Define a color map for start nodes (sources)
        source_colors = {}
        color_index = 0

        # Set node labels and edge colors
        edge_colors = []
        node_labels = {}
        for src, dst in edges:
            node_labels[src] = "RS" if RTPSFrame.static_guid_prefix_and_entity_id(src)[0] in analysis.rs_guid_prefix else "DW"
            node_labels[dst] = "RS" if RTPSFrame.static_guid_prefix_and_entity_id(dst)[0] in analysis.rs_guid_prefix else "DR"
            if src not in source_colors:
                source_colors[src] = COLOR_PALETTE[color_index % len(COLOR_PALETTE)]
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
            fig.canvas.manager.set_window_title(f"RTPS Topology Graph for Topic: {topic}")

        # Draw graph using the correct Axes
        nx.draw_networkx_nodes(G, pos, ax=ax, node_size=2000, node_color=node_colors, edgecolors='black')
        nx.draw_networkx_labels(G, pos, ax=ax, labels=node_labels, font_size=12, font_weight='bold')
        nx.draw_networkx_edges(
            G,
            pos,
            ax=ax,
            edgelist=list(edges),
            edge_color=edge_colors,
            arrowstyle='-|>',
            arrowsize=20,
            width=1,
            node_size=2000
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
        lines.append(f"Total number of messages: {total_messages}")

        # Total messages by topic
        total_messages_by_topic = analysis.df.groupby('topic')['count'].sum().sort_values(ascending=False)
        lines.append("  Total messages by topic:")
        for topic, count in total_messages_by_topic.items():
            lines.append(f"    {topic}: {count}")

        # Submessage counts
        submessage_counts = analysis.df.groupby('sm', observed=False)['count'].sum()
        lines.append("  Submessage counts:")
        for submsg in [str(s) for s in SUBMESSAGE_COMBINATIONS]:
            if submsg in submessage_counts:
                lines.append(f"    {submsg}: {submessage_counts[submsg]}")

        # Include any submessages not in SUBMESSAGE_COMBINATIONS
        for submsg, count in submessage_counts.items():
            if submsg not in [str(s) for s in SUBMESSAGE_COMBINATIONS]:
                lines.append(f"  {submsg}: {count}")

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

    def plot_stats_by_frame_count(self, analysis: RTPSAnalyzeCapture, include_discovery=False, scale=PlotScale.LINEAR):
        if self.no_gui:
            logger.warning("GUI is disabled. Cannot plot statistics.")
            return
        self._plot_statistics(analysis, metric='count', include_discovery=include_discovery, scale=scale)

    def plot_stats_by_frame_length(self, analysis: RTPSAnalyzeCapture, include_discovery=False, scale=PlotScale.LINEAR):
        if self.no_gui:
            logger.warning("GUI is disabled. Cannot plot statistics.")
            return
        self._plot_statistics(analysis, metric='length', include_discovery=include_discovery, scale=scale)

    # TODO: Ensure correct order of submessages in the plot
    def _plot_statistics(self, analysis: RTPSAnalyzeCapture, metric='count', include_discovery=False, scale=PlotScale.LINEAR):
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

        # Adjust layout and show the plot
        plt.tight_layout()
        show_plot_on_top()