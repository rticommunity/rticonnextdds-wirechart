##############################################################################################
# (c) 2025-2025 Copyright, Real-Time Innovations, Inc. (RTI) All rights reserved.
#
# RTI grants Licensee a license to use, modify, compile, and create derivative works of the
# software solely for use with RTI Connext DDS. Licensee may redistribute copies of the
# software, provided that all such copies are subject to this license. The software is
# provided "as is", with no warranty of any type, including any warranty for fitness for any
# purpose. RTI is under no obligation to maintain or support the software. RTI shall not be
# liable for any incidental or consequential damages arising out of the use or inability to
# use the software.
#
##############################################################################################

# Powershell: <command> | Tee-Object -FilePath "processes.txt"

import os
import glob
from pexpect.popen_spawn import PopenSpawn

PCAP_FOLDER = f"..{os.path.sep}pcap"
TEST_INPUT_FOLDER = f".{os.path.sep}test_input"
TEST_OUTPUT_FOLDER = f".{os.path.sep}test_output"


def load_expectations(filepath):
    if not os.path.exists(filepath):
        # print(f"⚠️ Expectations file not found: {filepath}")
        return []

    with open(filepath, 'r', encoding='utf-8') as f:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except UnicodeDecodeError:
            # print(f"⚠️ UTF-8 decode failed for {filepath}, retrying with 'utf-16'...")
            with open(filepath, 'r', encoding='utf-16') as f:
                return [line.strip() for line in f if line.strip()]


def validate_output(pcap_path, expectations):
    print(f"\n🔍 Validating {pcap_path}")

    command = f"python ..{os.path.sep}wirechart.py --pcap \"{pcap_path}\" --console-log-level ERROR --file-log-level DEBUG"
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
                # print(f"⏳ Expecting: {expected}")
                child.expect(expected)

                if "Enter your choice" in expected and input_index < len(inputs):
                    # print(f"📝 Sending input: {inputs[input_index]}")
                    child.sendline(inputs[input_index])
                    input_index += 1

            print(f"✅ Validation passed for {pcap_path}")
            return True

        except Exception as e:
            print(f"❌ Validation failed for {pcap_path}")
            print(f"🧾 Last output: {child.before.strip()}")
            return False


def main():
    tests_passed, tests_failed, tests_skipped = 0, 0, 0
    failed_tests = []

    pcap_files = glob.glob(os.path.join(PCAP_FOLDER, "*.pcap")) + \
                 glob.glob(os.path.join(PCAP_FOLDER, "*.pcapng"))

    if not pcap_files:
        print("\n⚠️ No .pcap or .pcapng files found.")
        return

    for pcap in pcap_files:
        # Generate expectations file path based on pcap filename
        base_name = os.path.basename(pcap)
        expectations_file = os.path.splitext(base_name)[0] + ".flag_enum.txt"
        expectations_path = os.path.join(TEST_INPUT_FOLDER, expectations_file)

        # Load the expectations for the current pcap file (if it exists)
        expectations = load_expectations(expectations_path)

        if expectations:
            if validate_output(pcap, expectations):
                tests_passed += 1
            else:
                tests_failed += 1
                failed_tests.append(pcap)
        else:
            tests_skipped += 1
            print(f"\n⚠️ No expectations file found for {base_name}. Skipping validation.")

    print(f"\n📝 Summary: {tests_passed} tests passed, {tests_failed} tests failed, {tests_skipped} tests skipped.")
    if tests_failed > 0:
        print(f"❌ Failed tests: {', '.join(failed_tests)}")

if __name__ == "__main__":
    main()
