import csv
import re
from collections import defaultdict
import matplotlib.pyplot as plt

# Wireshark Display Filter: (rtps.sm.wrEntityId.entityKind == 0x02) || (rtps.sm.wrEntityId.entityKind == 0x03)

# Regular expression pattern to match SUBMESSAGE_NAME and TOPIC_NAME
pattern = r',\s*(\w+)\s*->\s*([\w:]+)'

def extract_heartbeat_and_topic(file_path):
    nested_map = defaultdict(lambda: defaultdict(int))

    with open(file_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            for cell in row:
                matches = re.findall(pattern, cell)
                for match in matches:
                    if match:
                        submessage = match[0]
                        topic = match[1]
                        nested_map[topic][submessage] += 1

    print(f"Total number of topics found: {len(nested_map)}")
    return nested_map


def plot_nested_map_sorted(nested_map):
    # Step 1: Calculate total count per topic and sort topics by total count descending
    topic_totals = {topic: sum(submsg.values()) for topic, submsg in nested_map.items()}
    sorted_topics = sorted(topic_totals.keys(), key=lambda t: topic_totals[t], reverse=True)

    # Calculate the total number of messages across all topics
    total_messages = sum(topic_totals.values())
    print(f"Total number of messages: {total_messages}")

    # Step 2: Define custom order for submessages
    custom_order = ["DATA", "HEARTBEAT", "ACKNACK", "GAP"]
    submessages = sorted(
        {submsg for subs in nested_map.values() for submsg in subs},
        key=lambda x: custom_order.index(x) if x in custom_order else len(custom_order)
    )

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
        ax.bar(
            x,
            data[submsg],
            bottom=bottom,
            label=submsg
        )
        # Update the bottom to include the current submessage's values
        bottom = [bottom[i] + data[submsg][i] for i in range(len(bottom))]

    # Step 5: Update X-axis tick labels to include the number of submessages and total messages
    topic_labels_with_count = [
        f"{topic} ({topic_totals[topic]})"
        for topic in sorted_topics
    ]

    ax.set_xlabel('Topics')
    ax.set_ylabel('Count')
    ax.set_title('Submessage Counts by Topic')
    ax.set_xticks(x)
    ax.set_xticklabels(topic_labels_with_count, rotation=90, ha='center')
    ax.legend(title='Submessage')
    plt.tight_layout()
    plt.show()

if __name__ == '__main__':
    nested_map = extract_heartbeat_and_topic('histogram_test.csv')
    plot_nested_map_sorted(nested_map)
