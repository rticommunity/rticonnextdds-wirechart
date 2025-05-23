import os
import re

timestamp_regex = re.compile(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} -')
separator_line = "-------------------------"
replacement_line = r"Enter your choice \(0-10\):" + "\n"

def clean_log_file(file_path, overwrite=True):
    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    cleaned_lines = []
    inside_block = False
    first_replacement = True

    for line in lines:
        stripped = line.strip()

        # Skip blank lines
        if not stripped:
            continue

        # Skip timestamped lines
        if timestamp_regex.match(stripped):
            continue

        # Toggle block start/end on separator line
        if stripped == separator_line:
            if inside_block:
                # End of block — insert replacement line
                cleaned_lines.append(replacement_line)
                if first_replacement:
                    cleaned_lines.append(r"Choose option \(a/b\):" + "\n")
                    first_replacement = False
            inside_block = not inside_block
            continue  # Do not include separator lines

        if inside_block:
            continue  # Skip content inside the block

        # Keep normal content
        cleaned_lines.append(line)

    # Save cleaned output
    output_path = file_path if overwrite else f"{os.path.splitext(file_path)[0]}.flag_enum.txt"
    with open(output_path, 'w', encoding='utf-8') as file:
        file.writelines(cleaned_lines)

    print(f"✅ Cleaned: {file_path} → {output_path}")


def clean_all_logs_in_directory(base_path, overwrite=False):
    for root, dirs, files in os.walk(base_path):
        for file_name in files:
            if file_name.endswith(('.log', '.txt')):
                file_path = os.path.join(root, file_name)
                try:
                    clean_log_file(file_path, overwrite=overwrite)
                except Exception as e:
                    print(f"❌ Failed to clean {file_path}: {e}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Clean log/text files by removing timestamps, blank lines, and replacing menu blocks.")
    parser.add_argument("--path", help="Base directory to search for .txt or .log files")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite original files (default: False)")
    args = parser.parse_args()

    if not os.path.isdir(args.path):
        print(f"❌ Error: '{args.path}' is not a valid directory.")
    else:
        clean_all_logs_in_directory(args.path, overwrite=args.overwrite)
