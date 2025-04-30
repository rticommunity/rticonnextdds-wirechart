import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.ticker import StrMethodFormatter
from PCAPUtils import SUBMESSAGE_ORDER

class PCAPStats:
    """
    A class to manage and analyze PCAP statistics stored in a pandas DataFrame.
    """

    def __init__(self, df):
        """
        Initializes the PCAPStats object with a pandas DataFrame.

        :param df: A pandas DataFrame with columns ['Topic', 'Submessage', 'Count'].
        """
        self.df = df

    def print_stats(self):
        """
        Prints statistics about the PCAP data, including total messages, 
        messages by topic, and messages by submessage type.
        """
        # Calculate total messages
        total_messages = self.df['Count'].sum()
        print(f"Total number of messages: {total_messages}")

        # Calculate total messages by topic and sort in descending order
        total_messages_by_topic = self.df.groupby('Topic')['Count'].sum().sort_values(ascending=False)
        print("\nTotal messages by topic:")
        for topic, count in total_messages_by_topic.items():
            print(f"  {topic}: {count}")

        # Calculate counts for each submessage type
        submessage_counts = self.df.groupby('Submessage', observed=False)['Count'].sum()
        print("\nSubmessage counts:")
        for submsg in SUBMESSAGE_ORDER:
            if submsg in submessage_counts:
                print(f"  {submsg}: {submessage_counts[submsg]}")
        for submsg, count in submessage_counts.items():
            if submsg not in SUBMESSAGE_ORDER:
                print(f"  {submsg}: {count}")

    def print_stats_in_bytes(self):
        """
        Prints statistics about the PCAP data in bytes, including total message lengths,
        lengths by topic, and lengths by submessage type.
        """
        # Calculate total message length
        total_length = self.df['Length'].sum()
        print(f"Total message length: {total_length:,} bytes")

        # Calculate total message length by topic and sort in descending order
        total_length_by_topic = self.df.groupby('Topic')['Length'].sum().sort_values(ascending=False)
        print("\nTotal message length by topic:")
        for topic, length in total_length_by_topic.items():
            print(f"  {topic}: {length:,} bytes")

        # Calculate total lengths for each submessage type
        submessage_lengths = self.df.groupby('Submessage', observed=False)['Length'].sum()
        print("\nSubmessage lengths:")
        for submsg in SUBMESSAGE_ORDER:
            if submsg in submessage_lengths:
                print(f"  {submsg}: {submessage_lengths[submsg]:,} bytes")
        for submsg, length in submessage_lengths.items():
            if submsg not in SUBMESSAGE_ORDER:
                print(f"  {submsg}: {length:,} bytes")

        # Calculate total number of topics
        total_topics = self.df['Topic'].nunique()
        print(f"\nTotal number of topics found: {total_topics}")

    def plot_stats_by_frame_count(self):
        self._plot_statistics(metric="Count")
    
    def plot_stats_by_frame_length(self):
        self._plot_statistics(metric="Length")
    
    def _plot_statistics(self, metric="Count"):
        """
        Plots a stacked bar chart of submessage counts or lengths by topic.

        :param metric: The column to plot, either "Count" or "Length".
        """
        if metric not in ["Count", "Length"]:
            raise ValueError("Invalid metric. Choose either 'Count' or 'Length'.")

        # Define units based on the metric
        units = "messages" if metric == "Count" else "bytes"

        # Ensure all submessages in SUBMESSAGE_ORDER are included, even if missing
        df = self.df.set_index(['Topic', 'Submessage']).unstack(fill_value=0).stack(future_stack=True).reset_index()

        # Calculate total messages or lengths per topic and sort topics by total value
        df['TotalMetric'] = df.groupby('Topic')[metric].transform('sum')
        df = df.sort_values(by='TotalMetric', ascending=False)

        # Pivot the DataFrame to prepare for plotting
        pivot_df = df.pivot(index='Topic', columns='Submessage', values=metric).fillna(0)

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
            "DATA": "#1f77b4",  # Blue
            "DATA_FRAG": "#aec7e8",  # Light Blue
            "DATA_BATCH": "#add8e6",  # Light Blue
            "PIGGYBACK_HEARTBEAT": "#ff7f0e",  # Orange
            "PIGGYBACK_HEARTBEAT_BATCH": "#ffbb78",  # Light Orange
            "HEARTBEAT": "#2ca02c",  # Green
            "HEARTBEAT_BATCH": "#98df8a",  # Light Green
            "ACKNACK": "#d62728",  # Red
            "GAP": "#9467bd",  # Purple
            "UNREGISTER_DISPOSE": "#8c564b",  # Brown
        }
        colors = [color_mapping[submsg] for submsg in SUBMESSAGE_ORDER]

        # Plot the stacked bar chart with consistent colors
        ax = pivot_df.plot(kind='bar', stacked=True, figsize=(20, 13), color=colors)

        # Add totals to the legend
        submessage_totals = self.df.groupby('Submessage', observed=False)[metric].sum()
        handles, labels = ax.get_legend_handles_labels()
        ax.legend(
            handles,
            [f"{label} ({submessage_totals[label]:,} {units})" for label in labels],
            title='Submessage'
        )

        # Set axis labels and title
        ax.set_xlabel(f'Topics ({self.df["Topic"].nunique():,})')
        ax.set_ylabel(f"{metric} ({self.df[metric].sum():,} {units})")
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

    def save_to_excel(self, output_file, sheet_name="Sheet1"):
        """
        Writes a pandas DataFrame to an Excel file.

        :param df: A pandas DataFrame to write to Excel.
        :param output_file: The path to the output Excel file.
        :param sheet_name: The name of the sheet in the Excel file (default is "Sheet1").
        """
        try:
            # Write the DataFrame to an Excel file
            self.df.to_excel(output_file, sheet_name=sheet_name, index=False)
            print(f"DataFrame successfully written to {output_file}")
        except Exception as e:
            print(f"An error occurred while writing the DataFrame to Excel: {e}")