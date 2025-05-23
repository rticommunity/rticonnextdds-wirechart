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

# Local Application Imports
from src.log_handler import logging
from src.shared_utils import guid_prefix, FrameTypes
from src.rtps_submessage import RTPSSubmessage

logger = logging.getLogger(__name__)

class RTPSFrame:
    """
    Represents a single frame extracted from a PCAP file.
    """

    def __init__(self, frame_number, ip_src, ip_dst, guid_src, guid_dst, frame_type, sm_list):
        self.frame_number = frame_number
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.guid_src = guid_src
        self.guid_dst = guid_dst
        self.frame_type = frame_type
        self.sm_list = sm_list

        logger.debug(self)

    def __iter__(self):
        self._current_index = 0
        return self

    def __next__(self):
        if self._current_index < len(self.sm_list):
            packet = self.sm_list[self._current_index]
            self._current_index += 1
            return packet
        else:
            raise StopIteration

    def __eq__(self, value):
        if isinstance(value, RTPSFrame):
            return (self.frame_number == value.frame_number and
                    self.guid_src == value.guid_src and
                    self.guid_dst == value.guid_dst and
                    self.sm_list == value.sm_list and
                    self.frame_type == value.frame_type)
        return False

    def add_submessage(self, sm):
        """
        Adds an RTPSSubmessage object to the frame.

        :param frame: An RTPSSubmessage object to add.
        """
        if isinstance(sm, RTPSSubmessage):
            self.sm_list.append(sm)
        else:
            logger.error(f"Invalid submessage type: {sm}.")
            raise TypeError("Only RTPSFrame objects can be added to RTPSCapture.")

    def list_topics(self):
        """
        Returns a list of unique topics from the RTPSFrame object.
        """
        if FrameTypes.DISCOVERY not in self.frame_type:
            return set()

        return set(sm.topic for sm in self.sm_list if sm.topic is not None)

    def guid_prefix_and_entity_id(self):
        bitmask_32 = (1 << 32) - 1
        return guid_prefix(self.guid_src), self.guid_src & bitmask_32


    def contains_submessage(self, sm_type):
        """
        Checks if the frame contains a specific submessage type.

        :param sm_type: The submessage type to check for.
        :return: True if the submessage type is present, False otherwise.
        """
        return any(sm.sm_type == sm_type for sm in self.sm_list)

    def __str__(self):
        result = [f"Frame: {self.frame_number:09} GUID_SRC: {guid_prefix(self.guid_src)} Frame Type: {self.frame_type.name}\n{' ' * 2}Submessages ({len(self.sm_list)}):"]
        for i, submessage in enumerate(self.sm_list, start=1):
            result.append(f"{' ' * 4}{i} {str(submessage)}")
        return "\n".join(result) + "\n"