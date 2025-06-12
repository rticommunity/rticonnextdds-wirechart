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

# Local Application Imports
from src.log_handler import logging
from src.rtps_frame import RTPSFrame, FrameTypes
from src.shared_utils import InvalidPCAPDataException
from src.rtps_submessage import SubmessageTypes
from src.builders.rtps_submessage_builder import RTPSSubmessageBuilder

logger = logging.getLogger(__name__)

# Useful: https://community.rti.com/static/documentation/wireshark/2020-07/doc/appendix.html
class EntityIds:
    ENTITYID_BUILTIN_SDP_PARTICIPANT_WRITER = 0x000100c2
    ENTITYID_BUILTIN_PUBLICATIONS_WRITER = 0x000003c2
    ENTITYID_BUILTIN_SUBSCRIPTIONS_WRITER = 0x000004c2
    ENTITYID_SEDP_BUILTIN_PUBLICATIONS_SECURE_WRITER = 0xff0003c2
    ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_SECURE_WRITER = 0xff0004c2
    ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER = 0x000200c2
    ENTITYID_RTI_BUILTIN_SERVICE_REQUEST_WRITER = 0x00020082
    ENTITYID_RTI_BUILTIN_SERVICE_REQUEST_READER = 0x00020087

class ServiceKinds:
    ROUTING_SERVICE = 0x3

class RTPSFrameBuilder:
    def __init__(self, frame_data):
        self.frame_data = frame_data

    def build(self):
        logger.debug(f"Processing: {self.frame_data}")

        self._validate_frame_data()

        frame_number = int(self.frame_data.get('frame.number', 0))
        domain_id = int(self.frame_data.get('rtps.domain_id', 0).split(',')[0])
        _ , entity_id = self._parse_entity_id('rtps.sm.wrEntityId')

        if entity_id in (
            EntityIds.ENTITYID_RTI_BUILTIN_SERVICE_REQUEST_WRITER,
            EntityIds.ENTITYID_RTI_BUILTIN_SERVICE_REQUEST_READER,
        ):
            raise InvalidPCAPDataException("Service Request Frame.", logging.INFO)

        frame_type = self._parse_frame_type()
        submessages = self._parse_submessages(frame_type)
        guid_src, guid_dst = self._generate_guids(submessages[-1].sm_type)

        return RTPSFrame(
            frame_number=frame_number,
            domain_id=domain_id,
            guid_src=guid_src,
            guid_dst=guid_dst,
            frame_type=frame_type,
            sm_list=submessages,
        )

    def _validate_frame_data(self):
        if not self.frame_data.get('rtps.guidPrefix.src'):
            raise InvalidPCAPDataException("No GUID prefix.", logging.INFO)

        info_column = self.frame_data.get('_ws.col.Info', '')
        if "Malformed Packet" in info_column:
            raise InvalidPCAPDataException(f"Malformed Packet: {info_column}.", logging.WARNING)

    def _parse_ip(self, key):
        try:
            return int(ipaddress.ip_address(self.frame_data.get(key)))
        except ValueError:
            return None

    def _parse_entity_id(self, key):
        value = self.frame_data.get(key)
        if not value:
            return None, None

        match = re.match(r'0x([0-9A-Fa-f]+)', value.split(',')[0])
        if not match:
            return None, None

        hex_str = match.group(1) or '0'
        return hex_str, int(hex_str, 16)

    def _parse_frame_type(self):
        _, service_kind = self._parse_entity_id('rtps.param.service_kind')
        _, entity_id = self._parse_entity_id('rtps.sm.wrEntityId')

        if entity_id is None:
            raise InvalidPCAPDataException("Invalid Entity ID.", logging.WARNING)

        frame_type = FrameTypes.UNSET
        if service_kind == ServiceKinds.ROUTING_SERVICE:
            frame_type |= FrameTypes.ROUTING_SERVICE

        if entity_id in {
            EntityIds.ENTITYID_BUILTIN_SDP_PARTICIPANT_WRITER,
            EntityIds.ENTITYID_BUILTIN_PUBLICATIONS_WRITER,
            EntityIds.ENTITYID_BUILTIN_SUBSCRIPTIONS_WRITER,
            EntityIds.ENTITYID_SEDP_BUILTIN_PUBLICATIONS_SECURE_WRITER,
            EntityIds.ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_SECURE_WRITER,
        }:
            frame_type |= FrameTypes.DISCOVERY
        elif entity_id == EntityIds.ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER:
            frame_type |= FrameTypes.META_DATA
        else:
            frame_type |= FrameTypes.USER_DATA

        return frame_type

    def _parse_submessages(self, frame_type):
        info_column = self.frame_data.get('_ws.col.Info', '')
        sm_names = [s.strip() for s in info_column.split(',')]
        seq_numbers = list(map(int, self.frame_data.get('rtps.sm.seqNumber', '0').split(',')))
        sm_lengths = list(map(int, self.frame_data.get('rtps.sm.octetsToNextHeader', '0').split(',')))
        frame_length = int(self.frame_data.get('frame.len', 0))

        submessages = []
        seq_it = iter(seq_numbers)

        for name, length in zip(sm_names, sm_lengths):
            if name in ("INFO_DST", "INFO_SRC", "INFO_TS"):
                continue

            if not submessages:
                submessages.append(RTPSSubmessageBuilder(name, frame_length, seq_it, frame_type).build())
            else:
                submessages[0].length -= length
                submessages.append(RTPSSubmessageBuilder(name, length, seq_it, frame_type, True).build())

        remaining = list(seq_it)
        if remaining:
            frame_number = int(self.frame_data.get('frame.number', 0))
            logger.warning(f"Frame {frame_number:09}: Unexpected number of sequence numbers: {remaining}")

        return submessages

    def _generate_guids(self, sm_id):
        prefix_src = self.frame_data.get('rtps.guidPrefix.src', '').split(',')[0]
        prefix_dst = self.frame_data.get('rtps.guidPrefix.dst', '').split(',')[0]

        wr_entity_id, _ = self._parse_entity_id('rtps.sm.wrEntityId')
        rd_entity_id, _ = self._parse_entity_id('rtps.sm.rdEntityId')

        if sm_id & SubmessageTypes.ACKNACK:
            guid_src = prefix_dst + wr_entity_id
            guid_dst = prefix_src + rd_entity_id
        else:
            guid_src = prefix_src + wr_entity_id
            guid_dst = prefix_dst + rd_entity_id

        return self._none_if_zero(int(guid_src, 16)), self._none_if_zero(int(guid_dst, 16))

    def _none_if_zero(self, value):
        return None if value == 0 else value