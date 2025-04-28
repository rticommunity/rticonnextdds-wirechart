from collections import defaultdict
import matplotlib.pyplot as plt
import pandas as pd

SUBMESSAGE_ORDER = ["DATA", "PIGGYBACK_HEARTBEAT", "HEARTBEAT", "ACKNACK", "GAP"]

def plot_nested_map_sorted(nested_map):
    """
    Plots a stacked bar chart of submessage counts by topic using a pandas DataFrame.
    """
    # Convert nested_map to a DataFrame
    df = nested_map_to_dataframe(nested_map)

    # Ensure all submessages in SUBMESSAGE_ORDER are included, even if missing
    df = df.set_index(['Topic', 'Submessage']).unstack(fill_value=0).stack(future_stack=True).reset_index()

    # Calculate total messages per topic and sort topics by total count
    df['TotalMessages'] = df.groupby('Topic')['Count'].transform('sum')
    df = df.sort_values(by='TotalMessages', ascending=False)

    # Pivot the DataFrame to prepare for plotting
    pivot_df = df.pivot(index='Topic', columns='Submessage', values='Count').fillna(0)
    pivot_df = pivot_df[SUBMESSAGE_ORDER]  # Ensure submessages are in the correct order

    # Sort pivot_df by the total number of submessages (row-wise sum)
    pivot_df['TotalMessages'] = pivot_df.sum(axis=1)
    pivot_df = pivot_df.sort_values(by='TotalMessages', ascending=False)

    # Extract total messages for each topic
    total_messages_by_topic = pivot_df['TotalMessages']
    pivot_df = pivot_df.drop(columns=['TotalMessages'])  # Remove the helper column

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

    # Add counts to the legend
    submessage_totals = df.groupby('Submessage')['Count'].sum()
    handles, labels = ax.get_legend_handles_labels()
    ax.legend(handles, [f"{label} ({submessage_totals[label]})" for label in labels], title='Submessage')

    # Add labels to the bars
    # for i, topic in enumerate(pivot_df.index):
    #     bottom = 0
    #     for submsg in SUBMESSAGE_ORDER:
    #         value = pivot_df.loc[topic, submsg]
    #         if value > 0:
    #             ax.text(i, bottom + value / 2, int(value), ha='center', va='center', fontsize=8)
    #             bottom += value

    # Set axis labels and title
    ax.set_xlabel('Topics')
    ax.set_ylabel(f'Count ({df['Count'].sum()})')
    ax.set_title('Submessage Counts by Topic')

    # Update x-axis labels to include total messages
    x_labels = [f"{topic} ({int(total_messages_by_topic[topic])})" for topic in pivot_df.index]
    ax.set_xticks(range(len(pivot_df.index)))
    ax.set_xticklabels(x_labels, rotation=90, ha='center')

    # Adjust layout and show the plot
    plt.tight_layout()
    plt.show()

def print_message_statistics(nested_map):
    """
    Prints the total number of messages, the count of each submessage type, 
    and the total number of topics found.
    """
    # Calculate total messages
    total_messages = sum(
        sum(submsg.values()) for submsg in nested_map.values()
    )
    print(f"Total number of messages: {total_messages}")

    # Calculate counts for each submessage type
    submessage_counts = defaultdict(int)
    for submsg_map in nested_map.values():
        for submsg, count in submsg_map.items():
            submessage_counts[submsg] += count

    print("Submessage counts:")
    # Print submessages in MESSAGE_ORDER
    for submsg in SUBMESSAGE_ORDER:
        if submsg in submessage_counts:
            print(f"  {submsg}: {submessage_counts[submsg]}")

    # Print any remaining submessages not in MESSAGE_ORDER
    for submsg, count in submessage_counts.items():
        if submsg not in SUBMESSAGE_ORDER:
            print(f"  {submsg}: {count}")

    # Calculate total number of topics
    total_topics = len(nested_map)
    print(f"Total number of topics found: {total_topics}")

def nested_map_to_dataframe(nested_map):
    """
    Converts a nested dictionary (nested_map) to a pandas DataFrame.
    :param nested_map: A dictionary where keys are topics and values are dictionaries
                       of submessages and their counts.
    :return: A pandas DataFrame with columns ['Topic', 'Submessage', 'Count'].
    """
    rows = []
    for topic, submessages in nested_map.items():
        for submessage, count in submessages.items():
            rows.append({'Topic': topic, 'Submessage': submessage, 'Count': count})
    return pd.DataFrame(rows)