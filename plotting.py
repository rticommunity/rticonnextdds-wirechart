from collections import defaultdict
import matplotlib.pyplot as plt

MESSAGE_ORDER = ["DATA", "PIGGYBACK_HEARTBEAT", "HEARTBEAT", "ACKNACK", "GAP"]

def plot_nested_map_sorted(nested_map):
    # Step 1: Calculate total count per topic and sort topics by total count descending
    topic_totals = {topic: sum(submsg.values()) for topic, submsg in nested_map.items()}
    sorted_topics = sorted(topic_totals.keys(), key=lambda t: topic_totals[t], reverse=True)

    # Calculate the total number of messages across all topics
    total_messages = sum(topic_totals.values())

    # Step 2: Define custom order for submessages
    submessages = sorted(
        {submsg for subs in nested_map.values() for submsg in subs},
        key=lambda x: MESSAGE_ORDER.index(x) if x in MESSAGE_ORDER else len(MESSAGE_ORDER)
    )

    # Calculate total count for each submessage
    submessage_totals = {submsg: 0 for submsg in submessages}
    for submsg_map in nested_map.values():
        for submsg, count in submsg_map.items():
            submessage_totals[submsg] += count

    # Step 3: Organize data for plotting
    data = {submsg: [] for submsg in submessages}
    for topic in sorted_topics:
        for submsg in submessages:
            data[submsg].append(nested_map[topic].get(submsg, 0))

    # Step 4: Plot as a stacked bar chart
    x = range(len(sorted_topics))
    fig, ax = plt.subplots(figsize=(20, 13))

    bottom = [0] * len(sorted_topics)  # Initialize the bottom of the stack
    for submsg in submessages:
        bars = ax.bar(
            x,
            data[submsg],
            bottom=bottom,
            label=f"{submsg} ({submessage_totals[submsg]})"  # Add count to the legend
        )
        # Add quantities to each portion of the bar chart if visible
        for i, bar in enumerate(bars):
            # Dynamically calculate the threshold as a percentage of the y-axis height
            y_max = ax.get_ylim()[1]  # Get the maximum y-axis value
            threshold = y_max * 0.02  # Set threshold as 2% of the y-axis height

            if data[submsg][i] > 0 and data[submsg][i] > threshold:  # Only annotate if height > threshold
                ax.text(
                    bar.get_x() + bar.get_width() / 2,  # Center of the bar
                    bottom[i] + data[submsg][i] / 2,   # Middle of the bar segment
                    str(data[submsg][i]),             # The value to display
                    ha='center', va='center', fontsize=8, color='black'
                )
        # Update the bottom to include the current submessage's values
        bottom = [bottom[i] + data[submsg][i] for i in range(len(bottom))]

    # Step 5: Update X-axis tick labels to include the number of submessages and total messages
    topic_labels_with_count = [
        f"{topic} ({topic_totals[topic]})"
        for topic in sorted_topics
    ]

    ax.set_xlabel('Topics')
    ax.set_ylabel(f'Count ({total_messages})')
    ax.set_title('Submessage Counts by Topic')
    ax.set_xticks(x)
    ax.set_xticklabels(topic_labels_with_count, rotation=90, ha='center')
    ax.legend(title='Submessage')
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
    for submsg in MESSAGE_ORDER:
        if submsg in submessage_counts:
            print(f"  {submsg}: {submessage_counts[submsg]}")

    # Print any remaining submessages not in MESSAGE_ORDER
    for submsg, count in submessage_counts.items():
        if submsg not in MESSAGE_ORDER:
            print(f"  {submsg}: {count}")

    # Calculate total number of topics
    total_topics = len(nested_map)
    print(f"Total number of topics found: {total_topics}")