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
import ipaddress
import re
from enum import Flag

# Local Application Imports
from src.log_handler import logging
from src.shared_utils import InvalidPCAPDataException, guid_prefix
from src.rtps_submessage import RTPSSubmessage, SubmessageTypes

logger = logging.getLogger(__name__)

class FrameTypes(Flag):
    UNSET           = 0b0000
    USER_DATA       = 0b0001
    DISCOVERY       = 0b0010
    ROUTING_SERVICE = 0b0100

class RTPSFrame:
    """
    Represents a single frame extracted from a PCAP file.
    """

    def __init__(self, frame_data):
        """
        Initializes a RTPSFrame object with dynamic attributes.

        :param frame_data: Dictionary containing field names and their values.
        """
        def none_if_zero(value):
            return None if value == 0 else value
        def get_entity_id(entity_id_str):
            match = re.match(r'0x([0-9A-Fa-f]+)', entity_id_str.split(',')[0])
            if match:
                entity_id = match.group(1) or '0'
                return entity_id, int(entity_id, 16)
            else:
                return None, None
        def create_guid(frame_data, sm_id):
            guid_prefix_src = frame_data.get('rtps.guidPrefix.src').split(',')[0]
            guid_prefix_dst = frame_data.get('rtps.guidPrefix.dst').split(',')[0]
            wr_entity_id, _ = get_entity_id(frame_data.get('rtps.sm.wrEntityId'))
            rd_entity_id, _ = get_entity_id(frame_data.get('rtps.sm.rdEntityId'))

            if sm_id & SubmessageTypes.ACKNACK:
                # ACKNACKs reverse the GUID_prefixes but keep the entity IDs constant
                guid_src = guid_prefix_dst + wr_entity_id
                guid_dst = guid_prefix_src + rd_entity_id
            else:
                guid_src = guid_prefix_src + wr_entity_id
                guid_dst = guid_prefix_dst + rd_entity_id
            return none_if_zero(int(guid_src, 16)), none_if_zero(int(guid_dst, 16))

        logger.debug(f"Processing: {frame_data}")
        self.frame_number = int(frame_data.get('frame.number', 0))
        info_column = frame_data.get('_ws.col.Info', '')
        self.sm_list = list()
        self.ip_src, self.ip_dst = None, None
        self.guid_src, self.guid_dst = None, None
        self.frame_type = FrameTypes.UNSET

        if not frame_data.get('rtps.guidPrefix.src', None):
            raise InvalidPCAPDataException(f"No GUID prefix.", logging.INFO)

        if "Malformed Packet" in info_column:
            raise InvalidPCAPDataException(f"Malformed Packet: {info_column}.", log_level=logging.WARNING)

        for attr, key in (('ip_src', 'ip.src'), ('ip_dst', 'ip.dst')):
            try:
                setattr(self, attr, int(ipaddress.ip_address(frame_data.get(key))))
            except ValueError:
                setattr(self, attr, None)


        entity_id_str , entity_id = get_entity_id(frame_data.get('rtps.sm.wrEntityId', None))
        if entity_id is None:
            raise InvalidPCAPDataException(f"Invalid Entity ID: {entity_id_str}", logging.WARNING)
        if entity_id in (0x00020087, 0x00020082):
            raise InvalidPCAPDataException(f"Service Request Frame.", logging.INFO)
        if get_entity_id(frame_data.get('rtps.param.service_kind'))[1] == 0x3:
            self.frame_type |= FrameTypes.ROUTING_SERVICE
            logger.debug(f"Routing service frame.")
        if entity_id in {0x000100c2, 0x000003c2, 0x000004c2, 0xff0003c2, 0xff0004c2}:
            self.frame_type |= FrameTypes.DISCOVERY
        else:
            self.frame_type |= FrameTypes.USER_DATA

        sm_list = [s.strip() for s in info_column.split(',')]
        seq_number_list = list(map(int, frame_data.get('rtps.sm.seqNumber', 0).split(',')))
        sm_len_list = list(map(int, frame_data.get('rtps.sm.octetsToNextHeader', 0).split(',')))
        udp_length = int(frame_data.get('udp.length', 0))

        seq_num_it = iter(seq_number_list)
        for sm, sm_len in zip(sm_list, sm_len_list):
            if sm in ("INFO_TS", "INFO_DST"):  # TODO: Maybe INFO_SRC too?
                continue

            if not self.sm_list:
                # Include full upd_length in the first submessage
                self.add_submessage(RTPSSubmessage(sm, udp_length, seq_num_it, FrameTypes.DISCOVERY in self.frame_type))

            else:
                # Decrease the length of the first submessage by the length of the current submessage
                self.sm_list[0].length -= sm_len
                # Indicate more than one submessage in the frame
                self.sm_list.append(RTPSSubmessage(sm, sm_len, seq_num_it, FrameTypes.DISCOVERY in self.frame_type, True))

        if len(list(seq_num_it)):
            # If SNs remain, they are likely virtual SNs
            # TODO: Handle virtual SNs
            logger.warning(f"Frame {self.frame_number:09}: Unexpected number of sequence numbers: {seq_number_list}.")

        self.guid_src, self.guid_dst = create_guid(frame_data, self.sm_list[-1].sm_type)

        logger.debug(str(self))

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
        result = [f"Frame: {self.frame_number:09} GUID_SRC: {guid_prefix(self.guid_src)} Frame Type: {self.frame_type.name}\n{" " * 2}Submessages ({len(self.sm_list)}):"]
        for i, submessage in enumerate(self.sm_list, start=1):
            result.append(f"{" " * 4}{i} {str(submessage)}")
        return "\n".join(result) + "\n"