import matplotlib.pyplot as plt
from matplotlib.ticker import StrMethodFormatter
from pcap_utils import SUBMESSAGE_ORDER

def _plot_statistics(self, metric="Count"):
    """
    Plots a stacked bar chart of submessage counts or lengths by topic.

    :param metric: The column to plot, either "Count" or "Length".
    """
    if metric not in ["Count", "Length"]:
        raise ValueError("Invalid metric. Choose either 'Count' or 'Length'.")

    # Ensure all submessages in SUBMESSAGE_ORDER are included, even if missing
    df = self.df.set_index(['Topic', 'Submessage']).unstack(fill_value=0).stack().reset_index()

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
        "PIGGYBACK_HEARTBEAT": "#ff7f0e",  # Orange
        "HEARTBEAT": "#2ca02c",  # Green
        "ACKNACK": "#d62728",  # Red
        "GAP": "#9467bd",  # Purple
    }
    colors = [color_mapping[submsg] for submsg in SUBMESSAGE_ORDER]

    # Plot the stacked bar chart with consistent colors
    ax = pivot_df.plot(kind='bar', stacked=True, figsize=(20, 13), color=colors)

    # Add totals to the legend with comma-separated values
    submessage_totals = self.df.groupby('Submessage', observed=False)[metric].sum()
    handles, labels = ax.get_legend_handles_labels()
    ax.legend(
        handles,
        [f"{label} ({submessage_totals[label]:,})" for label in labels],
        title='Submessage'
    )

    # Set axis labels and title with comma-separated y-axis total
    ax.set_xlabel(f'Topics ({self.df["Topic"].nunique()})')
    ax.set_ylabel(f"{metric} ({self.df[metric].sum():,})")
    ax.set_title(f'Submessage {metric} by Topic')

    # Update x-axis labels to include total metric values
    x_labels = [f"{topic} ({int(total_metric_by_topic[topic]):,})" for topic in pivot_df.index]
    ax.set_xticks(range(len(pivot_df.index)))
    ax.set_xticklabels(x_labels, rotation=90, ha='center')

    # Disable scientific notation and format y-axis tick marks with commas
    ax.get_yaxis().set_major_formatter(StrMethodFormatter('{x:,.0f}'))

    # Adjust layout and show the plot
    plt.tight_layout()
    plt.show()

def print_message_statistics(df):
    """
    Prints the total number of messages, the count of each submessage type, 
    and the total number of topics found using a pandas DataFrame.

    :param df: A pandas DataFrame with columns ['Topic', 'Submessage', 'Count'].
    """
    # Calculate total messages
    total_messages = df['Count'].sum()
    print(f"Total number of messages: {total_messages}")

    # Calculate total messages by topic and sort in descending order
    total_messages_by_topic = df.groupby('Topic')['Count'].sum().sort_values(ascending=False)
    print("\nTotal messages by topic:")
    for topic, count in total_messages_by_topic.items():
        print(f"  {topic}: {count}")

    # Calculate counts for each submessage type
    submessage_counts = df.groupby('Submessage', observed=False)['Count'].sum()
    print("\nSubmessage counts:")
    for submsg in SUBMESSAGE_ORDER:
        if submsg in submessage_counts:
            print(f"  {submsg}: {submessage_counts[submsg]}")
    for submsg, count in submessage_counts.items():
        if submsg not in SUBMESSAGE_ORDER:
            print(f"  {submsg}: {count}")

    # Calculate total number of topics
    total_topics = df['Topic'].nunique()
    print(f"\nTotal number of topics found: {total_topics}")

def write_dataframe_to_excel(df, output_file, sheet_name="Sheet1"):
    """
    Writes a pandas DataFrame to an Excel file.

    :param df: A pandas DataFrame to write to Excel.
    :param output_file: The path to the output Excel file.
    :param sheet_name: The name of the sheet in the Excel file (default is "Sheet1").
    """
    try:
        # Write the DataFrame to an Excel file
        df.to_excel(output_file, sheet_name=sheet_name, index=False)
        print(f"DataFrame successfully written to {output_file}")
    except Exception as e:
        print(f"An error occurred while writing the DataFrame to Excel: {e}")