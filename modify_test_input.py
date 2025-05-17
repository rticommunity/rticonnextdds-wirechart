import os

TEST_INPUT_FOLDER = "test\\test_input"

# List of (target, replacement) tuples
REPLACEMENTS = [
    ("DATA_P", "DISCOVERY_DATA_P"),
    ("DATA_RW", "DISCOVERY_DATA_RW"),
    ("DATA_FRAG", "DATA_FRAGMENT"),
    ("DATA_DURABILITY_REPAIR", "DATA_DURABLE_REPAIR"),
]

def process_file(file_path, replacements):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()

        content = content.strip()

        # Apply each replacement
        for target, replacement in replacements:
            content = content.replace(target, replacement)

        with open(os.path.splitext(file_path)[0] + ".flag_enum.txt", 'w', encoding='utf-8') as file:
            file.write(content)

        print(f"✅ Processed: {file_path}")

    except Exception as e:
        print(f"❌ Error processing {file_path}: {e}")

def process_directory(directory_path, replacements):
    for root, _, files in os.walk(directory_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)

            if file_name.endswith('.txt') and not file_name.endswith('.enum_flag.txt'):
                process_file(file_path, replacements)

def main():
    directory_path = TEST_INPUT_FOLDER

    if not os.path.isdir(directory_path):
        print("❌ The directory does not exist.")
        return

    process_directory(directory_path, REPLACEMENTS)

if __name__ == "__main__":
    main()
