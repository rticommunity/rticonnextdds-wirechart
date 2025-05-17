import os
import glob
from pexpect.popen_spawn import PopenSpawn

PCAP_FOLDER = ".\\pcap"
TEST_INPUT_FOLDER = ".\\test\\test_input"
TEST_OUTPUT_FOLDER = ".\\test\\test_output"


def load_expectations(filepath):
    if not os.path.exists(filepath):
        print(f"⚠️ Expectations file not found: {filepath}")
        return []

    with open(filepath, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]


def validate_output(pcap_path, expectations):
    print(f"\n🔍 Validating {pcap_path}")

    command = f"python wirechart.py --pcap \"{pcap_path}\""
    child = PopenSpawn(command, encoding='utf-8', timeout=20)

    base_name = os.path.basename(pcap_path)
    log_path = os.path.join(TEST_OUTPUT_FOLDER, os.path.splitext(base_name)[0] + ".log")
    os.makedirs(TEST_OUTPUT_FOLDER, exist_ok=True)

    with open(log_path, "w", encoding="utf-8") as log_file:
        child.logfile = log_file

        inputs = ['0', '1', '2', '3', '10']
        input_index = 0

        try:
            for expected in expectations:
                print(f"⏳ Expecting: {expected}")
                child.expect(expected)

                if "Enter your choice" in expected and input_index < len(inputs):
                    print(f"📝 Sending input: {inputs[input_index]}")
                    child.sendline(inputs[input_index])
                    input_index += 1

            print(f"✅ Validation passed for {pcap_path}")
            return True

        except Exception as e:
            print(f"❌ Validation failed for {pcap_path}")
            print(f"🧾 Last output: {child.before.strip()}")
            return False


def main():
    pcap_files = glob.glob(os.path.join(PCAP_FOLDER, "*.pcap")) + \
                 glob.glob(os.path.join(PCAP_FOLDER, "*.pcapng"))

    if not pcap_files:
        print("⚠️ No .pcap or .pcapng files found.")
        return

    for pcap in pcap_files:
        # Generate expectations file path based on pcap filename
        base_name = os.path.basename(pcap)
        expectations_file = os.path.splitext(base_name)[0] + ".txt"
        expectations_path = os.path.join(TEST_INPUT_FOLDER, expectations_file)

        # Load the expectations for the current pcap file (if it exists)
        expectations = load_expectations(expectations_path)

        if expectations:
            validate_output(pcap, expectations)
        else:
            print(f"⚠️ No expectations file found for {base_name}. Skipping validation.")


if __name__ == "__main__":
    main()
