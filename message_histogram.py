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

    # Step 2: Gather all submessages
    submessages = sorted({submsg for subs in nested_map.values() for submsg in subs})

    # Step 3: Organize data for plotting
    data = {submsg: [] for submsg in submessages}
    for topic in sorted_topics:
        for submsg in submessages:
            data[submsg].append(nested_map[topic].get(submsg, 0))

    # Step 4: Plot
    x = range(len(sorted_topics))
    bar_width = 0.15
    fig, ax = plt.subplots(figsize=(20, 13))

    for i, submsg in enumerate(submessages):
        ax.bar(
            [xi + i * bar_width for xi in x],
            data[submsg],
            width=bar_width,
            label=submsg
        )

    # Step 5: Update X-axis tick labels to include the number of submessages and total messages
    topic_labels_with_count = [
        f"{topic} ({topic_totals[topic]})"
        for topic in sorted_topics
    ]

    ax.set_xlabel('Topics (sorted by total count)')
    ax.set_ylabel('Count')
    ax.set_title('Submessage Counts by Topic (Sorted by Total Entries)')
    ax.set_xticks([xi + bar_width * (len(submessages)-1)/2 for xi in x])
    ax.set_xticklabels(topic_labels_with_count, rotation=90, ha='center')
    ax.legend(title='Submessage')
    plt.tight_layout()
    plt.show()

if __name__ == '__main__':
    nested_map = extract_heartbeat_and_topic('histogram_test.csv')
    plot_nested_map_sorted(nested_map)
