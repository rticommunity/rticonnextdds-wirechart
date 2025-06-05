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
from enum import Enum

# Third-Party Library Imports
from tqdm import tqdm

# Local Application Imports
from src.log_handler import logging
from src.rtps_frame import RTPSFrame
from src.builders.rtps_frame_builder import RTPSFrameBuilder
from src.shared_utils import DEV_DEBUG, TEST_MODE, InvalidPCAPDataException, NoDiscoveryDataException

logger = logging.getLogger(__name__)

class PlotScale(Enum):
    LINEAR          = 'linear'
    LOGARITHMIC     = 'log'

DISCOVERY_TOPIC = "DISCOVERY"
META_DATA_TOPIC = "META_DATA"

# tshark seems to return commands in a hierarchy, i.e. frame -> udp -> rtps so order matters
PCAP_FIELDS = list(['frame.number', 'frame.len',
                    'ip.src', 'ip.dst',
                    'rtps.guidPrefix.src', 'rtps.sm.wrEntityId',        # Writer GUID
                    'rtps.guidPrefix.dst', 'rtps.sm.rdEntityId',        # Reader GUID
                    'rtps.sm.seqNumber', 'rtps.sm.octetsToNextHeader',
                    'rtps.sm.id', 'rtps.param.service_kind', '_ws.col.Info'])

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

    def __eq__(self, value):
        if isinstance(value, RTPSCapture):
            return (self.frames == value.frames)
        else:
            return False

    def add_frame(self, frame):
        """
        Adds an RTPSFrame object to the capture.

        :param frame: An RTPSFrame object to add.
        """
        if isinstance(frame, RTPSFrame):
            self.frames.append(frame)
        else:
            raise TypeError("Only RTPSFrame objects can be added to RTPSCapture.")

    def extract_rtps_frames(self, read_pcap_method, pcap_file, fields=PCAP_FIELDS , display_filter=None, start_frame=None, finish_frame=None, max_frames=None):
        """
        Extracts RTPS frames from a pcap file by using an injected method to read the data.

        :param read_pcap_method: Callable that reads the pcap file and returns raw frame data
        :param pcap_file: Path to the pcap file
        :param fields: Set of fields to extract
        :param display_filter: Optional display filter
        :param start_frame: Optional start frame number
        :param finish_frame: Optional finish frame number
        :param max_frames: Optional limit on number of packets
        """
        logger.always("Reading data from pcap file using the provided method...")
        frame_dict = read_pcap_method(pcap_file, fields, display_filter, start_frame, finish_frame, max_frames)
        self._process_frames(frame_dict)

    def _process_frames(self, frame_dict):
        """
        Processes frame dictionary list and populates the RTPSCapture object.

        :param frame_data: List of dictionaries containing (field, value) pairs for each frame
        :param fields: Set of fields to extract
        """
        if not frame_dict:
            raise InvalidPCAPDataException("No RTPS frames to process")

        exception_counts = {
            "frame_critical_errors": 0,
            "frame_errors": 0,
            "frame_warnings": 0,
            "discovery_warnings": 0
        }

        for frame in tqdm(frame_dict, disable=TEST_MODE):
            try:
                self.add_frame(RTPSFrameBuilder(frame).build())  # Create a RTPSFrame object for each record
            except InvalidPCAPDataException as e:
                logger.log(e.log_level, f"Frame {int(frame['frame.number']):09d} ignored. Message: {e}")
                if e.log_level == logging.CRITICAL:
                    exception_counts["frame_critical_errors"] += 1
                    if DEV_DEBUG:
                        raise e
                elif e.log_level == logging.ERROR:
                    exception_counts["frame_errors"] += 1
                elif e.log_level == logging.WARNING:
                    exception_counts["frame_warnings"] += 1
                continue
            except NoDiscoveryDataException as e:
                exception_counts["discovery_warnings"] += 1
                logger.warning(f"Frame {int(frame['frame.number']):09d} ignored. Message: {e}")
                continue
            except KeyError as e:
                exception_counts["frame_errors"] += 1
                logger.debug(f"Frame {int(frame['frame.number']):09d} ignored. Message: {e}")
                continue

        logger.always(f"Discovery warnings: {exception_counts['discovery_warnings']} | "
                      f"Critical errors: {exception_counts['frame_critical_errors']} | "
                      f"Frame warnings: {exception_counts['frame_warnings']} | "
                      f"Frame errors: {exception_counts['frame_errors']}")

    def list_all_topics(self):
        """
        Returns a set of all unique topics across all frames.

        :return: A set of unique topics.
        """
        topics = set()
        for frame in self.frames:
            topics.update(frame.list_topics())
        return topics

    def list_repairs(self):
        """
        Returns a list of all repair submessages in the frame.
        """
        repairs = []
        for frame in self.frames:
            for sm in frame.sm_list:
                if sm.is_repair():
                    repairs.append(frame)
                    break
        return repairs

    def list_durable_repairs(self):
        """
        Returns a list of all durable repair submessages in the frame.
        """
        durable_repairs = []
        for frame in self.frames:
            for sm in frame.sm_list:
                if sm.is_durable_repair():
                    durable_repairs.append(frame)
                    break
        return durable_repairs