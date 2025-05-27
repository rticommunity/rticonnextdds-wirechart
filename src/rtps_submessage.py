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
from enum import Flag

# Local Application Imports
from src.log_handler import logging
from src.shared_utils import DEV_DEBUG

logger = logging.getLogger(__name__)

class SubmessageTypes(Flag):
    UNSET           = 0x0000
    DISCOVERY       = 0x0001
    DATA_P          = 0x0002
    DATA_RW         = 0x0004
    DATA            = 0x0008
    PIGGYBACK       = 0x0010
    HEARTBEAT       = 0x0020
    BATCH           = 0x0040
    ACKNACK         = 0x0080
    NACK            = 0x0100
    FRAGMENT        = 0x0200
    DURABLE         = 0x0400
    REPAIR          = 0x0800
    GAP             = 0x1000
    LIVELINESS      = 0x2000
    STATE           = 0x4000

    def __str__(self):
        if self == SubmessageTypes.UNSET:
            return "UNSET"
        return "_".join(flag.name for flag in SubmessageTypes if flag in self and flag != SubmessageTypes.UNSET)

SUBMESSAGE_COMBINATIONS = [
    SubmessageTypes.DISCOVERY | SubmessageTypes.DATA_P,
    SubmessageTypes.DISCOVERY | SubmessageTypes.DATA_RW,
    SubmessageTypes.DISCOVERY | SubmessageTypes.REPAIR,
    SubmessageTypes.DISCOVERY | SubmessageTypes.HEARTBEAT,
    SubmessageTypes.DISCOVERY | SubmessageTypes.PIGGYBACK | SubmessageTypes.HEARTBEAT,
    SubmessageTypes.DISCOVERY | SubmessageTypes.ACKNACK,
    SubmessageTypes.DISCOVERY | SubmessageTypes.GAP,
    SubmessageTypes.DISCOVERY | SubmessageTypes.STATE,
    SubmessageTypes.DATA,
    SubmessageTypes.DATA | SubmessageTypes.FRAGMENT,
    SubmessageTypes.DATA | SubmessageTypes.BATCH,
    SubmessageTypes.DATA | SubmessageTypes.REPAIR,
    SubmessageTypes.DATA | SubmessageTypes.DURABLE | SubmessageTypes.REPAIR,
    SubmessageTypes.DATA | SubmessageTypes.FRAGMENT | SubmessageTypes.REPAIR,
    SubmessageTypes.DATA | SubmessageTypes.FRAGMENT | SubmessageTypes.DURABLE | SubmessageTypes.REPAIR,
    SubmessageTypes.HEARTBEAT,
    SubmessageTypes.HEARTBEAT | SubmessageTypes.BATCH,
    SubmessageTypes.PIGGYBACK | SubmessageTypes.HEARTBEAT,
    SubmessageTypes.PIGGYBACK | SubmessageTypes.HEARTBEAT | SubmessageTypes.BATCH,
    SubmessageTypes.ACKNACK,
    SubmessageTypes.NACK | SubmessageTypes.FRAGMENT,
    SubmessageTypes.GAP,
    SubmessageTypes.LIVELINESS,
    SubmessageTypes.DATA | SubmessageTypes.STATE,
]

def list_combinations_by_flag(flag: SubmessageTypes, combinations=SUBMESSAGE_COMBINATIONS, negate=False) -> list[SubmessageTypes]:
    """
    Return a list of SubmessageTypes combinations that include or exclude the given flag.

    Args:
        flag (SubmessageTypes): The flag to filter by.
        combinations (list[SubmessageTypes], optional): The ordered list to filter from.
        negate (bool): If True, returns combinations where the flag is NOT set.

    Returns:
        list[SubmessageTypes]: Filtered list of combinations.
    """
    if negate:
        result = [combo for combo in combinations if not (combo & flag)]
    else:
        result = [combo for combo in combinations if combo & flag]

    if not result:
        logger.error(f"No combinations found with {'NOT ' if negate else ''}{flag}")

    if DEV_DEBUG:
        for combo in result:
            if combo not in combinations:
                logger.error(f"Combination {combo} not found in the predefined list.")
                raise ValueError(f"Combination {combo} not found in the predefined list.")

    return result

class RTPSSubmessage():
    def __init__(self, topic, length, sm_type, seq_num_tuple):
        self.topic = topic
        self.length = length
        self.sm_type = sm_type
        self.seq_num_tuple = seq_num_tuple

    def __eq__(self, other):
        if isinstance(other, RTPSSubmessage):
            return (self.sm_type == other.sm_type and
                    self.topic == other.topic and
                    self.length == other.length and
                    self.seq_num_tuple == other.seq_num_tuple)
        return False
    
    def __str__(self):
        return (f"Type: {self.sm_type.name}, Topic: {self.topic}, "
                f"Length: {self.length}, Seq Number: {self.seq_num_tuple}")

    def seq_num(self):
        """
        Returns the sequence number of the submessage.
        If the submessage type is GAP, returns None."""
        if SubmessageTypes.GAP & self.sm_type:
            return None

        elif SubmessageTypes.HEARTBEAT & self.sm_type:
            # SN stored as (first available SN, last available SN)
            return self.seq_num_tuple[1]
        else:
            # SN stored as (SN)
            return self.seq_num_tuple[0]

    def first_available_seq_num(self):
        """
        Returns the first available sequence number of the submessage.
        If the submessage type is not HEARTBEAT, returns None."""
        if SubmessageTypes.HEARTBEAT & self.sm_type:
            # SN stored as (first available SN, last available SN)
            return self.seq_num_tuple[0]
        else:
            return None

    def gap(self):
        """
        Returns the gap sequence numbers of the submessage.
        If the submessage type is not GAP, returns None."""
        # GAP sequence numbers stored as (first available SN, last available SN)
        if SubmessageTypes.GAP & self.sm_type:
            return self.seq_num_tuple[0], self.seq_num_tuple[1]
        return None, None