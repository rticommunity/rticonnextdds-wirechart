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

# Standard Library Imports
import os
import subprocess

# Third-Party Library Imports
import dpkt

# Local Application Imports
from src.log_handler import logging
from src.shared_utils import InvalidPCAPDataException

logger = logging.getLogger(__name__)

class TsharkReader:
    """
    A class responsible for reading pcap files using the tshark command.
    """
    @staticmethod
    def get_version():
        try:
            output = subprocess.check_output(["tshark", "--version"], stderr=subprocess.STDOUT, text=True)
            logger.always(output.splitlines()[0])
        except FileNotFoundError:
            logger.error("Error: tshark is not installed.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running tshark: {e.output.strip()}")

    @staticmethod
    def get_frame_count(pcap_file):
        return TsharkReader._get_stats(pcap_file)[0]

    @staticmethod
    def get_pcap_size_bytes(pcap_file):
        return TsharkReader._get_stats(pcap_file)[1]

    @staticmethod
    def _get_stats(pcap_file):
        """
        Gets the frame count and total captured bytes from a pcap/pcapng file.
        Uses dpkt for fast header-only parsing — no packet dissection.

        :param pcap_file: Path to the pcap file
        :return: Tuple of (frame_count, total_bytes)
        """
        frame_count = 0
        total_bytes = 0
        with open(pcap_file, 'rb') as f:
            try:
                reader = dpkt.pcap.Reader(f)
            except ValueError:
                f.seek(0)
                reader = dpkt.pcapng.Reader(f)
            for _, buf in reader:
                frame_count += 1
                total_bytes += len(buf)
        logger.always(f"Total frames: {frame_count}, Total bytes: {total_bytes}")
        return frame_count, total_bytes

    @staticmethod
    def read_pcap(pcap_file, fields, display_filter=None, start_frame=None, finish_frame=None, max_frames=None):
        """
        Reads a pcap file using the tshark command and yields frame data one frame at a time.

        :param pcap_file: Path to the pcap file
        :param fields: List of fields to extract (e.g., ['frame.number', '_ws.col.Info'])
        :param display_filter: Optional display filter (e.g., 'rtps')
        :param start_frame: Optional start frame number
        :param finish_frame: Optional finish frame number
        :param max_frames: Optional limit on number of packets
        :return: Generator of dictionaries (field, value) pairs for each frame
        """
        fields = list(fields)

        if not os.path.exists(pcap_file):
            logger.error(f"PCAP file {pcap_file} does not exist.")
            raise FileNotFoundError(f"PCAP file {pcap_file} does not exist.")

        # -2 performs a two-pass read of the pcap file, which collects all the discovery data
        # https://www.wireshark.org/docs/man-pages/tshark.html
        cmd = ['tshark', '-2', '-r', pcap_file, '-n', '-T', 'fields']

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

        logger.info(f"Running command: {' '.join(cmd)}")
        frame_count = 0
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            for line in proc.stdout:
                line = line.rstrip('\n')
                if not line:
                    continue
                values = line.split('\t')
                yield {field: value for field, value in zip(fields, values)}
                frame_count += 1
            proc.stdout.close()
            proc.wait()
            if proc.returncode != 0:
                stderr_output = proc.stderr.read()
                logger.error("Error running tshark.")
                raise subprocess.CalledProcessError(proc.returncode, cmd, stderr=stderr_output)
            if frame_count == 0:
                raise InvalidPCAPDataException("No RTPS frames found in the pcap file.", log_level=logging.ERROR)
        finally:
            if not proc.stdout.closed:
                proc.stdout.close()
            if not proc.stderr.closed:
                proc.stderr.close()
            if proc.poll() is None:
                proc.wait()