import os
import pickle

from src.rtps_capture import RTPSCapture

# Directory containing your pickled RTPSCapture files
DATA_DIR = os.path.dirname(__file__)

def main():
    # List all .pkl files in the data directory
    test_files = ['multi_rs.pcapng', '9April_STR_StaleValues.pcap']

    for fname in test_files:
        pkl_file = os.path.join(DATA_DIR, 'pkl', fname.split('.')[0] + '.pkl')
        pcap_file = os.path.join(DATA_DIR, 'pcap', fname)
        print(f"Loading {fname} ...")

        test_frames = RTPSCapture.load(pkl_file)

        pcap_fields = list(['frame.number', 'udp.length',
                    'rtps.guidPrefix.src', 'rtps.sm.wrEntityId',        # Writer GUID
                    'rtps.guidPrefix.dst', 'rtps.sm.rdEntityId',        # Reader GUID
                    'rtps.sm.seqNumber', 'rtps.sm.octetsToNextHeader',
                    'rtps.sm.id', '_ws.col.Info'])

        rtps_frames = RTPSCapture(pcap_file, pcap_fields, 'rtps')
        rtps_frames.analyze_capture()  # Analyze the capture

        print(f"{fname} Equality Test: {test_frames == rtps_frames}")

if __name__ == "__main__":
    main()