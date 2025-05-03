import subprocess
from RTPSFrame import *

from log_handler import logging

logger = logging.getLogger(__name__)

class RTPSCapture:
    """
    Represents a collection of RTPSFrame objects extracted from a PCAP file.
    Provides methods to manage and analyze the captured frames.
    """

    def __init__(self):
        """
        Initializes an empty RTPSCapture object.
        """
        self.frames = []  # List to store RTPSFrame objects
        # TODO: Check for existance of pcap file in the constructor
        # TODO: Call extract_rtps_frames() in the constructor if a pcap file is provided
        # TODO: Add discovery, user_data dataframes
        # TODO: Add input for start and stop frames to tshark

    def add_frame(self, frame):
        """
        Adds an RTPSFrame object to the capture.

        :param frame: An RTPSFrame object to add.
        """
        if isinstance(frame, RTPSFrame):
            self.frames.append(frame)
        else:
            raise TypeError("Only RTPSFrame objects can be added to RTPSCapture.")

    def list_all_topics(self):
        """
        Returns a set of all unique topics across all frames.

        :return: A set of unique topics.
        """
        topics = set()
        for frame in self.frames:
            topics.update(frame.list_topics())
        return topics

    def print_capture_summary(self):
        """
        Prints a summary of the RTPSCapture, including the number of frames and unique topics.
        """
        print(f"Total Frames: {len(self.frames)}")
        print(f"Unique Topics: {len(self.list_all_topics())}")
        print("Topics:")
        for topic in sorted(self.list_all_topics()):
            print(f"  - {topic}")

    def print_all_frames(self):
        """
        Prints the details of all frames in the capture.
        """
        for frame in self.frames:
            print(frame, end="\n\n")

    def extract_rtps_frames(self, pcap_file, fields, display_filter=None, max_frames=None):
        """
        Calls tshark to extract specified fields from a pcap file and returns a list of RTPSFrame objects.

        :param pcap_file: Path to the pcap file
        :param fields: Set of fields to extract (e.g., ['_ws_col_Info', '_ws.col.Protocol'])
        :param display_filter: Optional display filter (e.g., 'http')
        :param max_frames: Optional limit on number of packets
        :return: List of RTPSFrame objects containing the extracted field values
        """
        cmd = ['tshark', '-r', pcap_file, '-T', 'fields']

        # Add each field to the command
        for field in fields:
            cmd.extend(['-e', field])

        if display_filter:
            cmd.extend(['-Y', display_filter])
        if max_frames:
            cmd.extend(['-c', str(max_frames)])

        logger.info(f"Running command: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            frame_data = result.stdout.strip().split('\n')

            if frame_data == ['']:
                logger.error("tshark returned no RTPS frames")
                raise InvalidPCAPDataException("tshark returned no RTPS frames")

            # Split each line into columns and create a list of RTPSFrame objects
            for frame in frame_data:
                values = frame.split('\t')
                frame = {field: value for field, value in zip(fields, values)}
                try:
                    self.add_frame(RTPSFrame(frame))  # Create a RTPSFrame object for each record
                except InvalidPCAPDataException as e:
                    continue
                except KeyError as e:
                    continue
        except subprocess.CalledProcessError as e:
            logger.error("Error running tshark.")
            raise e