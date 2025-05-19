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
import re

# Local Application Imports
from src.log_handler import logging
from src.shared_utils import InvalidPCAPDataException, NoDiscoveryDataException

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
    STATE           = 0x2000

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
    SubmessageTypes.DATA | SubmessageTypes.STATE,
]

def get_combination_order(smtype_combo):
    try:
        return SUBMESSAGE_COMBINATIONS.index(smtype_combo)
    except ValueError:
        # TODO: Figure out what to do here
        return float('inf')  # or raise an exception or log warning

def list_combinations_by_flag(flag: SubmessageTypes, combinations=SUBMESSAGE_COMBINATIONS, negate=False) -> list[SubmessageTypes]:
    """
    Return a list of SMTypes combinations that include or exclude the given flag.

    Args:
        flag (SMTypes): The flag to filter by.
        combinations (list[SMTypes], optional): The ordered list to filter from.
        negate (bool): If True, returns combinations where the flag is NOT set.

    Returns:
        list[SMTypes]: Filtered list of combinations.
    """
    if negate:
        result = [combo for combo in combinations if not (combo & flag)]
    else:
        result = [combo for combo in combinations if combo & flag]

    if not result:
        logger.error(f"No combinations found with {'NOT ' if negate else ''}{flag}")

    return result

class RTPSSubmessage():
    def __init__(self, sm, length, seq_num_it, discovery_frame, multiple_sm=False):

        matches = re.match(r'^(.*?)\s*->\s*(.*)', sm)
        # If no -> is found, this might be a discovery frame or a user data frame without
        # discovery info (which is handled below)
        sm_type = matches.group(1).strip() if matches else sm
        topic = matches.group(2).strip() if matches else None

        if any(term in sm.lower() for term in ("port", "ping")):
            raise InvalidPCAPDataException(f"Routing frame: {sm}.", logging.INFO)
        if not (discovery_frame or topic):
            raise NoDiscoveryDataException(f"No discovery data.")

        self.topic = topic
        self.length = length
        self.sm_type = SubmessageTypes.DISCOVERY if discovery_frame else SubmessageTypes.UNSET

        #  TODO: Handle user data that doens't have a topic
        # Check for a state submessage type
        if "BATCH" in sm_type:
            self.sm_type |= SubmessageTypes.BATCH
        if "FRAG" in sm_type:
            self.sm_type |= SubmessageTypes.FRAGMENT
        if "DATA" in sm_type:
            if sm_type in ("DATA", "DATA_BATCH", "DATA_FRAG"):
                self.sm_type |= SubmessageTypes.DATA
            elif sm_type == "DATA(p)":
                self.sm_type |= SubmessageTypes.DATA_P
            elif sm_type in ("DATA(r)", "DATA(w)"):
                self.sm_type |= SubmessageTypes.DATA_RW
            elif re.search(r'DATA\([pwr]\[UD]\)', sm_type):
                # Unregister/Dispose for Discovery Data
                self.sm_type |= SubmessageTypes.STATE
            elif "([" in sm_type:
                # Unregister/Dispose for User Data
                self.sm_type |= SubmessageTypes.DATA | SubmessageTypes.STATE
            # else caught below
        elif "HEARTBEAT" in sm_type:
            self.sm_type |= SubmessageTypes.HEARTBEAT
            if multiple_sm:
                self.sm_type |= SubmessageTypes.PIGGYBACK
        elif "ACKNACK" == sm_type:
            self.sm_type |= SubmessageTypes.ACKNACK
        elif "GAP" == sm_type:
            self.sm_type |= SubmessageTypes.GAP

        if self.sm_type in {SubmessageTypes.UNSET, SubmessageTypes.DISCOVERY}:
            # If there are no additional bits set, then an error has occurred, these can't exist alone
            logger.error(f"Submessage type not set: {sm_type}.")
            raise InvalidPCAPDataException(f"Submessage type not set: {sm_type}.", logging.ERROR)

        # All submessages have a at least one sequence number
        seq_num_count = 1
        if self.sm_type & (SubmessageTypes.HEARTBEAT | SubmessageTypes.GAP):
            # HEARTBEAT and GAP have double the sequence numbers
            # TODO: Does GAP_BATCH exist, and do they have 4 sequence numbers?
            seq_num_count *= 2
        if self.sm_type & SubmessageTypes.BATCH:
            # BATCH has double the sequence numbers
            # DATA_BATCH has 2 sequence numbers and HEARTBEAT_BATCH has 4 sequence numbers
            seq_num_count *= 2

        # Create a tuple of sequence numbers based on the count
        self.seq_num_tuple = tuple([next(seq_num_it) for _ in range(seq_num_count)])

    def __eq__(self, other):
        if isinstance(other, RTPSSubmessage):
            return (self.sm_type == other.sm_type and
                    self.topic == other.topic and
                    self.length == other.length and
                    self.seq_num_tuple == other.seq_num_tuple)
        return False

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

    def __str__(self):
        return (f"Type: {self.sm_type.name}, Topic: {self.topic}, "
                f"Length: {self.length}, Seq Number: {self.seq_num_tuple}")