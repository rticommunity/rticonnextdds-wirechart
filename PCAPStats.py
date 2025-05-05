import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.ticker import StrMethodFormatter
from log_handler import logging
from RTPSFrame import SubmessageTypes
from RTPSCapture import DISCOVERY_TOPIC
from wirechart import create_output_path

logger = logging.getLogger(__name__)

class PCAPStats:
    """
    A class to manage and analyze PCAP statistics stored in a pandas DataFrame.
    """

    def __init__(self, df):
        """
        Initializes the PCAPStats object with a pandas DataFrame.

        :param df: A pandas DataFrame with columns ['topic', 'sm', 'count'].
        """
        self.df = df

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
        print(f"{" " * 2}Total messages by topic:")
        for topic, count in total_messages_by_topic.items():
            print(f"{" " * 4}{topic}: {count}")

        # Calculate counts for each submessage type
        submessage_counts = self.df.groupby('sm', observed=False)['count'].sum()
        print(f"{" " * 2}Submessage counts:")
        for submsg in SubmessageTypes.subset_names():
            if submsg in submessage_counts:
                print(f"{" " * 4}{submsg}: {submessage_counts[submsg]}")
        for submsg, count in submessage_counts.items():
            if submsg not in SubmessageTypes.subset_names():
                print(f"  {submsg}: {count}")
        print()

    # TODO: Add logic to print by count and length
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
        print(f"{" " * 2}Total message length by topic:")
        for topic, length in total_length_by_topic.items():
            print(f"{" " * 4}{topic}: {length:,} bytes")

        # Calculate total lengths for each submessage type
        submessage_lengths = self.df.groupby('sm', observed=False)['length'].sum()
        print(f"{" " * 2}Submessage lengths:")
        # Get all submessage types
        for submsg in SubmessageTypes.subset_names():
            if submsg in submessage_lengths:
                print(f"{" " * 4}{submsg}: {submessage_lengths[submsg]:,} bytes")
        for submsg, length in submessage_lengths.items():
            if submsg not in SubmessageTypes.subset_names():
                print(f"{" " * 4}{submsg}: {length:,} bytes")
        print()

    def plot_stats_by_frame_count(self, include_discovery=False):
        self._plot_statistics(metric='count', include_discovery=include_discovery)

    def plot_stats_by_frame_length(self, include_discovery=False):
        """
        Plots a stacked bar chart of submessage lengths by topic.
        :param include_discovery: If True, includes discovery submessages in the plot.
        """
        self._plot_statistics(metric='length', include_discovery=include_discovery)

    def _plot_statistics(self, metric='count', include_discovery=False):
        """
        Plots a stacked bar chart of submessage counts or lengths by topic.

        :param metric: The column to plot, either 'count' or 'length'.
        :param include_discovery: If False, excludes the "DISCOVERY" topic from the plot.
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

        # Filter out topics with no submessages (all values are zero)
        pivot_df = pivot_df[(pivot_df.sum(axis=1) > 0)]

        # Sort pivot_df by the total value of the metric (row-wise sum)
        pivot_df['TotalMetric'] = pivot_df.sum(axis=1)
        pivot_df = pivot_df.sort_values(by='TotalMetric', ascending=False)

        # Extract total metric values for each topic
        total_metric_by_topic = pivot_df['TotalMetric']
        pivot_df = pivot_df.drop(columns=['TotalMetric'])  # Remove the helper column

        # Define a consistent color mapping for submessages
        color_mapping = {
            "DATA_P": "#ff7f0e",                        # Orange
            "DATA_RW": "#2ca02c",                       # Green
            "DISCOVERY_HEARTBEAT": "#1f77b4",           # Blue
            "DISCOVERY_ACKNACK": "#9467bd",             # Purple
            "DISCOVERY_STATE": "#d62728",               # Red
            "DATA": "#8c564b",                          # Brown
            "DATA_FRAG": "#17becf",                     # Teal
            "DATA_BATCH": "#ff7f7f",                    # Light Red
            "DATA_REPAIR": "#7f7f7f",                   # Gray
            "HEARTBEAT": "#aec7e8",                     # Light Blue
            "HEARTBEAT_BATCH": "#ffbb78",               # Light Orange
            "PIGGYBACK_HEARTBEAT": "#98df8a",           # Light Green
            "PIGGYBACK_HEARTBEAT_BATCH": "#bcbd22",     # Olive
            "ACKNACK": "#e377c2",                       # Pink
            "GAP": "#c49c94",                           # Rose Brown
            "DATA_STATE": "#393b79",                    # Navy Blue
        }
        colors = [color_mapping[submsg] for submsg in SubmessageTypes.subset_names()]

        # Plot the stacked bar chart with consistent colors
        ax = pivot_df.plot(kind='bar', stacked=True, figsize=(20, 13), color=colors)

        # Add totals to the legend, filtering out submessages with zero totals
        submessage_totals = self.df.groupby('sm', observed=False)[metric].sum()
        filtered_totals = {label: total for label, total in submessage_totals.items() if total > 0}  # Filter nonzero totals
        handles, labels = ax.get_legend_handles_labels()
        filtered_handles_labels = [
            (handle, label) for handle, label in zip(handles, labels) if label in filtered_totals
        ]
        filtered_handles, filtered_labels = zip(*filtered_handles_labels) if filtered_handles_labels else ([], [])
        ax.legend(
            filtered_handles,
            [f"{label} ({filtered_totals[label]:,} {units})" for label in filtered_labels],
            title='sm'
        )

        # Set axis labels and title
        ax.set_xlabel(f'Topics ({df["topic"].nunique():,})')
        ax.set_ylabel(f"{metric} ({df[metric].sum():,} {units})")
        ax.set_title(f"Submessage {metric} by Topic ({units})")

        # Update x-axis labels to include total metric values
        x_labels = [f"{topic} ({int(total_metric_by_topic[topic]):,})" for topic in pivot_df.index]
        ax.set_xticks(range(len(pivot_df.index)))
        ax.set_xticklabels(x_labels, rotation=90, ha='center')

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
            logger.info(f"DataFrame successfully written to {filename} in sheet '{sheet_name}'.")
        except Exception as e:
            logger.error(f"Error writing DataFrame to Excel: {e}")