import re
from enum import IntEnum, auto
from log_handler import logging

logger = logging.getLogger(__name__)

# TODO: Add logging for invalid submessage types and other exceptions

class SubmessageTypes(IntEnum):
    def _generate_next_value_(name, start, count, last_values):
        return count  # Start from 0

    DATA_P = auto()
    DATA_RW = auto()
    DISCOVERY_STATE = auto()
    DATA = auto()
    DATA_FRAG = auto()
    DATA_BATCH = auto()
    PIGGYBACK_HEARTBEAT = auto()
    PIGGYBACK_HEARTBEAT_BATCH = auto()
    HEARTBEAT = auto()
    HEARTBEAT_BATCH = auto()
    ACKNACK = auto()
    REPAIR = auto()
    GAP = auto()
    DATA_STATE = auto()

class InvalidPCAPDataException(Exception):
    """Exception raised for invalid PCAP data."""

    def __init__(self, message):
        """
        Initializes the exception with a message and an optional PCAP file.

        :param message: The error message.
        """
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return self.message

class RTPSSubmessage():
    def __init__(self, sm_type, topic, length, seq_number, multiple_sm=False):
        self.sm_type = None
        self.topic = topic
        self.length = length
        self.seq_number = seq_number
        # GAPs announce the next sequence number, so decrement by 1
        if self.sm_type == "GAP":
            self.seq_number -= 1

        # Check for a state submessage type
        try:
            # If this is a HEARTBEAT and there are multiple submessages, this is a PIGGYBACK_HEARTBEAT
            if multiple_sm and "HEARTBEAT" in sm_type:
                self.sm_type = SubmessageTypes["PIGGYBACK_" + sm_type]

            if "DATA" in sm_type:
                if sm_type == "DATA":
                    self.sm_type = SubmessageTypes.DATA
                elif sm_type == "DATA(p)":
                    self.sm_type = SubmessageTypes.DATA_P
                elif sm_type in ("DATA(r)", "DATA(w)"):
                    self.sm_type = SubmessageTypes.DATA_RW
                elif re.search(r'DATA\([pwr]\[UD]\)', sm_type):
                    # Unregister/Dispose for Discovery Data
                    self.sm_type = SubmessageTypes.DISCOVERY_STATE
                elif "([" in sm_type:
                    # Unregister/Dispose for User Data
                    self.sm_type = SubmessageTypes.DATA_STATE
                else:
                    #TODO: Add logging
                    raise InvalidPCAPDataException(f"Invalid submessage type: {sm_type}")
            else:
                self.sm_type = SubmessageTypes[sm_type]
        except KeyError:
            logger.info(f"Invalid submessage type: {sm_type}.  Dumping frame.")
            raise KeyError(f"Invalid submessage: {sm_type}")

        if self.sm_type is None:
            #  TODO: Add logging
            raise InvalidPCAPDataException(f"Invalid submessage type: {sm_type}")

    def __str__(self):
        return (f"Type: {self.sm_type.name}, Topic: {self.topic}, "
                f"Length: {self.length}, Seq Number: {self.seq_number}")

class RTPSFrame:
    """
    Represents a single frame extracted from a PCAP file.
    """

    def __init__(self, frame_data):
        """
        Initializes a RTPSFrame object with dynamic attributes.

        :param frame_data: Dictionary containing field names and their values.
        """
        logger.debug(f"Processing: {frame_data}")
        self.frame_number = int(frame_data.get('frame.number', 0))
        self.sm_list = list()
        self.discovery_frame = False

        guid_prefix = frame_data.get('rtps.guidPrefix.src', None)
        if not guid_prefix:
            # PING frame or something similar
            logger.info(f"Frame {self.frame_number:09}: Dumping for no GUID prefix.")
            raise InvalidPCAPDataException(f"No GUID prefix. Dumping frame {self.frame_number}.")

        wr_entity_id = frame_data.get('rtps.sm.wrEntityId')
        match = re.match(r'0x([0-9A-Fa-f]+)', wr_entity_id)
        self.guid = guid_prefix + match.group(1)
        if int(match.group(1), 16) in {0x000100c2, 0x000003c2, 0x000004c2, 0xff0003c2, 0xff0004c2}:
            self.discovery_frame = True

        sm_list = [s.strip() for s in frame_data.get('_ws.col.Info', '').split(',')]
        seq_number_list = list(map(int, frame_data.get('rtps.sm.seqNumber', 0).split(',')))
        sm_len_list = list(map(int, frame_data.get('rtps.sm.octetsToNextHeader', 0).split(',')))
        udp_length = int(frame_data.get('udp.length', 0))

        seq_number_iterator = iter(seq_number_list)
        for sm, sm_len in zip(sm_list, sm_len_list):
            if sm in ("INFO_TS", "INFO_DST"):  # TODO: Maybe INFO_SRC too?
                continue
            matches = re.match(r'^(.*?)\s*->\s*(.*)', sm)
            sm = matches.group(1).strip() if matches else sm
            sm_topic = matches.group(2).strip() if matches else ''

            if sm in ("HEARTBEAT", "GAP"):
                # HEARTBEAT and GAP have 2 sequence numbers in the list, and we want the second one
                # so throw away the first sequence number.
                next(seq_number_iterator)

            if not self.sm_list:
                # Include full upd_length in the first submessage
                self.sm_list.append(RTPSSubmessage(sm, sm_topic, udp_length, next(seq_number_iterator)))

            else:
                # Decrease the length of the first submessage by the length of the current submessage
                self.sm_list[0].length -= sm_len
                # Indicate more than one submessage in the frame
                self.sm_list.append(RTPSSubmessage(sm, sm_topic, sm_len, next(seq_number_iterator), True))

        logger.debug(str(self))

    def list_topics(self):
        """
        Returns a list of unique topics from the RTPSFrame object.
        """
        if not self.discovery_frame:
            return set()

        return set(submessage.topic for submessage in self.sm_list if submessage.topic)

    def __str__(self):
        result = [f"Frame: {self.frame_number:09} GUID: {self.guid}\n{" " * 2}Submessages ({len(self.sm_list)}):"]
        for i, submessage in enumerate(self.sm_list, start=1):
            result.append(f"{" " * 4}{i} {str(submessage)}")
        return "\n".join(result)
    
    # TODO: Add add_submessage method to add submessages to the list