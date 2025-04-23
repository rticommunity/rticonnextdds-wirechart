import csv
import re

# Wireshark Display Filter: rtps.sm.wrEntityId == 0x000003c2 || rtps.sm.wrEntityId == 0x000004c2 || rtps.sm.wrEntityId == 0xff0003c2 || rtps.sm.wrEntityId == 0xff0004c2

def extract_topics(cell):
    """
    Extracts all 'topic' values from patterns like 'DATA(r) -> topic' or 'DATA(w) -> topic'
    (with or without a trailing comma), even if there are multiple matches in one cell.
    """
    matches = re.findall(r'DATA\([rw]\)\s*->\s*([\w:]+),?', cell)
    return matches



def get_unique_topics(csv_file_path):
    unique_topics = set()

    with open(csv_file_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            for cell in row:
                results = extract_topics(cell.strip())
                unique_topics.update(results)

    return unique_topics


def write_to_file(output_file_path, values):
    with open(output_file_path, 'w', encoding='utf-8') as outfile:
        for value in sorted(values):
            outfile.write(value + '\n')

# Example usage:
if __name__ == "__main__":
    input_file = 'wireshark_test.csv'      # Replace with your input CSV file path
    output_file = 'unique_topics.txt'      # Output file name

    unique_topics = get_unique_topics(input_file)
    write_to_file(output_file, unique_topics)

    print(f"Saved {len(unique_topics)} unique topic values to '{output_file}'")
