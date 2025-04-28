from collections import defaultdict
import matplotlib.pyplot as plt

SUBMESSAGE_ORDER = ["DATA", "PIGGYBACK_HEARTBEAT", "HEARTBEAT", "ACKNACK", "GAP"]

def plot_nested_map_sorted(nested_map):
    """
    Plots a stacked bar chart of submessage counts by topic.

    :param nested_map: A dictionary where keys are topics and values are dictionaries
    of submessages and their counts.
    """
    # Step 1: Calculate total count per topic and sort topics by total count descending
    # Create a dictionary with the total count of all submessages for each topic
    total_messages_by_topic = {topic: sum(submsg.values()) for topic, submsg in nested_map.items()}
    # Sort topics by their total counts in descending order
    total_messages_by_topic_descending = sorted(total_messages_by_topic.keys(), key=lambda t: total_messages_by_topic[t], reverse=True)
    # Calculate the total number of messages across all topics
    total_messages = sum(total_messages_by_topic.values())

    # Calculate total count for each submessage across all topics
    total_messages_by_submessage = {submsg: 0 for submsg in SUBMESSAGE_ORDER}
    for submsg_map in nested_map.values():
        for submsg, count in submsg_map.items():
            total_messages_by_submessage[submsg] += count

    # Step 3: Organize data for plotting
    # Create a dictionary to store the counts of each submessage for each topic
    data = {submsg: [] for submsg in SUBMESSAGE_ORDER}
    for topic in total_messages_by_topic_descending:
        for submsg in SUBMESSAGE_ORDER:
            # Append the count of the submessage for the current topic (default to 0 if not present)
            data[submsg].append(nested_map[topic].get(submsg, 0))

    # Step 4: Plot as a stacked bar chart
    # Create a range for the x-axis based on the number of topics
    x = range(len(total_messages_by_topic_descending))
    # Create a figure and axis for the plot
    fig, ax = plt.subplots(figsize=(20, 13))

    # Initialize the bottom of the stack for each topic
    bottom = [0] * len(total_messages_by_topic_descending)
    for submsg in SUBMESSAGE_ORDER:
        # Plot the bars for the current submessage
        bars = ax.bar(
            x,
            data[submsg],
            bottom=bottom,
            label=f"{submsg} ({total_messages_by_submessage[submsg]})"  # Add count to the legend
        )
        # Add quantities to each portion of the bar chart if visible
        for i, bar in enumerate(bars):
            # Dynamically calculate the threshold as a percentage of the y-axis height
            y_max = ax.get_ylim()[1]  # Get the maximum y-axis value
            threshold = y_max * 0.02  # Set threshold as 2% of the y-axis height

            # Only annotate if the bar segment height is greater than the threshold
            if data[submsg][i] > 0 and data[submsg][i] > threshold:
                ax.text(
                    bar.get_x() + bar.get_width() / 2,  # Center of the bar
                    bottom[i] + data[submsg][i] / 2,   # Middle of the bar segment
                    str(data[submsg][i]),             # The value to display
                    ha='center', va='center', fontsize=8, color='black'
                )
        # Update the bottom to include the current submessage's values
        bottom = [bottom[i] + data[submsg][i] for i in range(len(bottom))]

    # Step 5: Update X-axis tick labels to include the number of submessages and total messages
    # Create labels for each topic, including the total count of messages for that topic
    topic_labels_with_count = [
        f"{topic} ({total_messages_by_topic[topic]})"
        for topic in total_messages_by_topic_descending
    ]

    # Set axis labels and title
    ax.set_xlabel('Topics')
    ax.set_ylabel(f'Count ({total_messages})')
    ax.set_title('Submessage Counts by Topic')
    # Set the x-axis tick positions and labels
    ax.set_xticks(x)
    ax.set_xticklabels(topic_labels_with_count, rotation=90, ha='center')
    # Add a legend with the submessage names and their total counts
    ax.legend(title='Submessage')
    # Adjust the layout to prevent overlapping elements
    plt.tight_layout()
    # Display the plot
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