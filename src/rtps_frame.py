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
from enum import IntEnum

# Local Application Imports
from src.log_handler import logging
from src.shared_utils import FrameTypes
from src.rtps_submessage import RTPSSubmessage

logger = logging.getLogger(__name__)

class GUIDEntity(IntEnum):
    GUID_SRC = 0
    GUID_DST = 1

class RTPSFrame:
    """
    Represents a single frame extracted from a PCAP file.
    """

    def __init__(self, frame_number, domain_id, guid_src, guid_dst, frame_type, sm_list):
        self.frame_number = frame_number
        self.domain_id = domain_id
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
                    self.domain_id == value.domain_id and
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

    def get_topic(self):
        """
        Returns the topic of the first submessage in the frame if it exists.
        If no submessage is present, returns None.
        """
        if self.sm_list:
            return self.sm_list[0].topic
        return None
    
    def get_domain_id(self):
        """
        Returns the domain ID of the frame.
        """
        return self.domain_id

    def list_topics(self):
        """
        Returns a list of unique topics from the RTPSFrame object.
        """
        if FrameTypes.DISCOVERY not in self.frame_type:
            return set()

        return set(sm.topic for sm in self.sm_list if sm.topic is not None)

    @staticmethod
    def static_guid_prefix_and_entity_id(guid):
        """
        Extracts the prefix from a GUID.
        :param guid: The GUID to extract the prefix from.
        :return: The prefix of the GUID.
        """
        # GUID is a 128-bit integer and the prefix is the upper 96 bits (12 bytes)
        bitmask_32 = (1 << 32) - 1
        return guid >> 32, guid & bitmask_32

    def guid_prefix_and_entity_id(self, guid_entity=GUIDEntity.GUID_SRC):
        guid = self.guid_src if guid_entity == GUIDEntity.GUID_SRC else self.guid_dst
        if guid is None:
            return None, None
        return RTPSFrame.static_guid_prefix_and_entity_id(guid)


    def contains_submessage(self, sm_type):
        """
        Checks if the frame contains a specific submessage type.

        :param sm_type: The submessage type to check for.
        :return: True if the submessage type is present, False otherwise.
        """
        return any(sm.sm_type == sm_type for sm in self.sm_list)

    def __str__(self):
        result = [f"Frame: {self.frame_number:09} Domain: {self.domain_id} GUID_SRC: {hex(self.guid_prefix_and_entity_id(GUIDEntity.GUID_SRC)[0])} "
                  f"Frame Type: {self.frame_type.name}\n{' ' * 2}Submessages ({len(self.sm_list)}):"]
        for i, submessage in enumerate(self.sm_list, start=1):
            result.append(f"{' ' * 4}{i} {str(submessage)}")
        return "\n".join(result) + "\n"

    def to_dict(self):
        """
        Converts the RTPSFrame object to a dictionary representation.

        :return: Dictionary representation of the RTPSFrame.
        """
        return {
            'frame_number': self.frame_number,
            'domain_id': self.domain_id,
            'guid_src': self.guid_src,
            'guid_dst': self.guid_dst,
            'frame_type': self.frame_type.name,
            'submessages': [sm.to_dict() for sm in self.sm_list]
        }