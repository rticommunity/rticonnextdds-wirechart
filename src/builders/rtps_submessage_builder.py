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
import re

# Local Application Imports
from src.log_handler import logging
from src.rtps_frame import FrameTypes
from src.shared_utils import InvalidPCAPDataException, NoDiscoveryDataException
from src.rtps_submessage import SubmessageTypes, RTPSSubmessage

logger = logging.getLogger(__name__)

class RTPSSubmessageBuilder:
    def __init__(self, sm, length, seq_num_it, instance_it, frame_type, multiple_sm=False):
        self.sm = sm
        self.length = length
        self.seq_num_it = seq_num_it
        self.instance_it = instance_it
        self.frame_type = frame_type
        self.multiple_sm = multiple_sm

    def build(self):
        topic, sm_type_str = self._extract_topic_and_type(self.sm)
        self._validate_submessage(sm_type_str, topic)

        sm_flags = self._parse_submessage_type(sm_type_str)

        seq_num_tuple = self._generate_sequence_numbers(sm_flags)

        instance_id = None
        if sm_flags == SubmessageTypes.DATA:
            instance_id = next(self.instance_it)

        return RTPSSubmessage(
            topic=topic,
            length=self.length,
            sm_type=sm_flags,
            seq_num_tuple=seq_num_tuple,
            instance_id=instance_id
        )

    def _extract_topic_and_type(self, sm):
        match = re.match(r'^(.*?)\s*->\s*(.*)', sm)
        if match:
            return match.group(2).strip(), match.group(1).strip()
        return None, sm.strip()

    def _validate_submessage(self, sm_type, topic):
        if any(term in sm_type.lower() for term in ("port", "ping")):
            raise InvalidPCAPDataException(f"Routing frame: {self.sm}.", logging.INFO)

        if not ((self.frame_type & (FrameTypes.DISCOVERY | FrameTypes.META_DATA)) or topic):
            raise NoDiscoveryDataException("No discovery data.")

    def _parse_submessage_type(self, sm_type):
        flags = SubmessageTypes.DISCOVERY if self.frame_type & FrameTypes.DISCOVERY else SubmessageTypes.UNSET

        if "BATCH" in sm_type:
            flags |= SubmessageTypes.BATCH
        if "FRAG" in sm_type:
            flags |= SubmessageTypes.FRAGMENT
        if "DATA" in sm_type:
            flags |= self._parse_data_flags(sm_type)
        elif "HEARTBEAT" in sm_type:
            flags |= SubmessageTypes.HEARTBEAT
            if self.multiple_sm:
                flags |= SubmessageTypes.PIGGYBACK
        elif sm_type == "ACKNACK":
            flags |= SubmessageTypes.ACKNACK
        elif sm_type == "GAP":
            flags |= SubmessageTypes.GAP

        if flags in {SubmessageTypes.UNSET, SubmessageTypes.DISCOVERY}:
            logger.critical(f"Submessage type not detected: {sm_type}.")
            raise InvalidPCAPDataException(f"Submessage type not detected: {sm_type}.", logging.CRITICAL)

        return flags

    def _parse_data_flags(self, sm_type):
        if sm_type in {"DATA", "DATA_BATCH", "DATA_FRAG"}:
            return SubmessageTypes.DATA
        elif sm_type == "DATA(p)":
            return SubmessageTypes.DATA_P
        elif sm_type in {"DATA(r)", "DATA(w)"}:
            return SubmessageTypes.DATA_RW
        elif re.search(r'DATA\([pwr]\[UD]\)', sm_type):
            return SubmessageTypes.STATE
        elif "([" in sm_type:
            return SubmessageTypes.DATA | SubmessageTypes.STATE
        elif sm_type == "DATA(m)":
            return SubmessageTypes.LIVELINESS
        else:
            return SubmessageTypes.UNSET

    def _generate_sequence_numbers(self, sm_flags):
        count = 1
        if sm_flags & (SubmessageTypes.HEARTBEAT | SubmessageTypes.GAP):
            count *= 2
        if sm_flags & SubmessageTypes.BATCH:
            count *= 2
        return tuple(next(self.seq_num_it) for _ in range(count))
