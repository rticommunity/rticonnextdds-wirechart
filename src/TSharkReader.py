import os
import subprocess
from src.log_handler import logging

logger = logging.getLogger(__name__)
class TsharkReader:
    """
    A class responsible for reading pcap files using the tshark command.
    """
    @staticmethod
    def get_tshark_version():
        try:
            output = subprocess.check_output(["tshark", "--version"], stderr=subprocess.STDOUT, text=True)
            logger.always(output.splitlines()[0])
        except FileNotFoundError:
            logger.error("Error: tshark is not installed.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running tshark: {e.output.strip()}")
    @staticmethod
    def read_pcap(pcap_file, fields, display_filter=None, start_frame=None, finish_frame=None, max_frames=None):
        """
        Reads a pcap file using the tshark command and returns the raw frame data.

        :param pcap_file: Path to the pcap file
        :param fields: Set of fields to extract (e.g., ['_ws_col_Info', '_ws.col.Protocol'])
        :param display_filter: Optional display filter (e.g., 'http')
        :param start_frame: Optional start frame number
        :param finish_frame: Optional finish frame number
        :param max_frames: Optional limit on number of packets
        :return: List of dictionaries (field, value) pairs for each frame
        """
        if not os.path.exists(pcap_file):
            logger.error(f"PCAP file {pcap_file} does not exist.")
            raise FileNotFoundError(f"PCAP file {pcap_file} does not exist.")

        cmd = ['tshark', '-r', pcap_file, '-T', 'fields']

        # Add each field to the command
        for field in fields:
            cmd.extend(['-e', field])

        filter_parts = []

        if display_filter:
            filter_parts.append(f"({display_filter})")

        if start_frame:
            filter_parts.append(f"(frame.number >= {start_frame})")

        if finish_frame:
            filter_parts.append(f"(frame.number <= {finish_frame})")

        # Join all parts with "&&"
        full_filter = " && ".join(filter_parts)

        if full_filter:
            cmd.extend(['-Y', full_filter])
        if max_frames:
            cmd.extend(['-c', str(max_frames)])

        logger.debug(f"Running command: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            raw_frames = result.stdout.strip().split('\n')
            logger.always(f"tshark returned {len(raw_frames)} frames")

            frame_dict = []
            for raw_frame in raw_frames:
                values = raw_frame.split('\t')
                frame_dict.append({field: value for field, value in zip(fields, values)})
            return frame_dict
        except subprocess.CalledProcessError as e:
            logger.error("Error running tshark.")
            raise e