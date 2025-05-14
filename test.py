import os
import argparse
from pathlib import Path

from src.rtps_capture import RTPSCapture

from src.log_handler import configure_root_logger, logging, ALWAYS
logger = logging.getLogger('test')

# Directory containing your pickled RTPSCapture files
DATA_DIR = os.path.join(os.path.dirname(__file__))

def main():
    configure_root_logger('./test_output/test.log', console_level=ALWAYS, file_level=logging.DEBUG)
    parser = argparse.ArgumentParser(description="Test RTPSCapture pickle and equality.")
    parser.add_argument("--create-test-files", action="store_true", help="Create .pkl test files from .pcap files")
    parser.add_argument("--partial-compare", action="store_true", help="Only compare the dataframe and RS GUIDs")
    args = parser.parse_args()

    test_files = [f for f in (Path(DATA_DIR) / 'pcap').iterdir() if f.is_file()]

    test_failures = []
    for pcap_file in test_files:
        pkl_file = pcap_file.parent.parent / 'pkl' / (pcap_file.stem + '.pkl')

        logger.always(f"Loading {pcap_file} ...")

        if pkl_file.is_file() and args.create_test_files:
            logger.always(f"Test file {pkl_file} already exists. Skipping.")
            continue

        pcap_fields = ['frame.number', 'udp.length',
                    'rtps.guidPrefix.src', 'rtps.sm.wrEntityId',        # Writer GUID
                    'rtps.guidPrefix.dst', 'rtps.sm.rdEntityId',        # Reader GUID
                    'rtps.sm.seqNumber', 'rtps.sm.octetsToNextHeader',
                    'rtps.sm.id', '_ws.col.Info']

        try:
            rtps_frames = RTPSCapture(str(pcap_file), pcap_fields, 'rtps')
            rtps_frames.analyze_capture()  # Analyze the capture
        except Exception as e:
            test_failures.append(pcap_file)
            logger.test_error(f"Error analyzing {pcap_file}: {e}")
            continue

        if args.create_test_files:
            logger.info(f"Creating test file {pkl_file} ...")
            rtps_frames.save(pkl_file)
        else:
            logger.info(f"Testing {pcap_file} ...")
            test_frames = RTPSCapture.load(pkl_file)
            test_result = False
            if args.partial_compare:
                test_result = rtps_frames.partial_eq(test_frames)
            else:
                test_result = rtps_frames == test_frames
            if not test_result:
                test_frames.save_to_excel('base_' + pcap_file.stem, 'test_output')
                rtps_frames.save_to_excel('test_' + pcap_file.stem, 'test_output')
                test_failures.append(pcap_file)
                logger.test_error(f"Test failed: {pcap_file} and {pkl_file} are not equal.")
            else:
                logger.always(f"Test passed: {pcap_file}.")

    logger.always("All tests completed.")
    logger.always(f"Test failures: {len(test_failures)}")
    print("Test failures:", test_failures)

if __name__ == "__main__":
    main()