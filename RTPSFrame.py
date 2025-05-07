import re
from enum import IntEnum, auto
from log_handler import logging

logger = logging.getLogger(__name__)

class SubmessageTypes(IntEnum):
    def _generate_next_value_(name, start, count, last_values):
        return count  # Start from 0

    DATA_P = auto()
    DATA_RW = auto()
    DISCOVERY_REPAIR = auto()
    DISCOVERY_HEARTBEAT = auto()
    DISCOVERY_PIGGYBACK_HEARTBEAT = auto()
    DISCOVERY_ACKNACK = auto()
    DISCOVERY_STATE = auto()
    DATA = auto()
    DATA_FRAG = auto()
    DATA_BATCH = auto()
    DATA_REPAIR = auto()
    DATA_DURABILITY_REPAIR = auto()
    HEARTBEAT = auto()
    HEARTBEAT_BATCH = auto()
    PIGGYBACK_HEARTBEAT = auto()
    PIGGYBACK_HEARTBEAT_BATCH = auto()
    ACKNACK = auto()
    GAP = auto()
    DATA_STATE = auto()

    @classmethod
    def subset(cls, start = DATA_P, end = DATA_STATE):
        """
        Returns a subset of the enum members between start and end.
        """
        return [member for member in cls if start <= member.value <= end]

    @classmethod
    def subset_names(cls, start = DATA_P, end = DATA_STATE):
        """
        Returns a list of names of the enum members between start and end.
        """
        return [member.name for member in cls if start <= member.value <= end]

class InvalidPCAPDataException(Exception):
    """Exception raised for invalid PCAP data."""

    def __init__(self, message, log_level=logging.DEBUG):
        """
        :param message: The error message.
        :param log_level: Logging level from logging module (e.g., logging.WARNING).
        """
        self.message = message
        self.log_level = log_level
        super().__init__(self.message)

    def __str__(self):
        return self.message

class RTPSSubmessage():
    def __init__(self, sm_type, topic, length, seq_number, discovery_frame, multiple_sm=False):
        if any(term in sm_type.lower() for term in ("port", "ping")):
            raise InvalidPCAPDataException(f"Routing frame: {sm_type}.")

        self.topic = topic
        self.length = length
        self.seq_number = seq_number

        #  TODO: Handle user data that doens't have a topic
        # Check for a state submessage type
        try:
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
                # else caught below
            else:
                # If this is a HEARTBEAT and there are multiple submessages, this is a PIGGYBACK_HEARTBEAT
                if multiple_sm and "HEARTBEAT" in sm_type:
                    sm_type = "PIGGYBACK_" + sm_type
                if discovery_frame and ("HEARTBEAT" in sm_type or "ACKNACK" in sm_type):
                    sm_type = "DISCOVERY_" + sm_type

                self.sm_type = SubmessageTypes[sm_type]
        except KeyError:
            logger.error(f"Invalid submessage type: {sm_type}.")
            raise KeyError(f"Invalid submessage: {sm_type}")

        if not isinstance(self.sm_type, SubmessageTypes):
            logger.error(f"Invalid submessage type: {self.sm_type}")
            raise InvalidPCAPDataException(f"Invalid submessage type: {self.sm_type}")

        # GAPs announce the next sequence number, so decrement by 1
        if self.sm_type == SubmessageTypes.GAP:
            self.seq_number -= 1

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
        info_column = frame_data.get('_ws.col.Info', '')
        self.sm_list = list()
        self.guid_src, self.guid_dst, entity = None, None, None
        self.discovery_frame = False

        if "Malformed Packet" in info_column:
            raise InvalidPCAPDataException(f"Malformed Packet: {info_column}.", log_level=logging.WARNING)

        def create_guid(guid_prefix, entity_id_str):
            if not guid_prefix:
                raise InvalidPCAPDataException(f"No GUID prefix.")

            match = re.match(r'0x([0-9A-Fa-f]+)', entity_id_str)
            entity_id = match.group(1)
            guid = guid_prefix + entity_id
            return int(guid, 16), int(entity_id, 16)

        self.guid_src, entity_id = create_guid(frame_data.get('rtps.guidPrefix.src', None), frame_data.get('rtps.sm.wrEntityId', None))
        self.discovery_frame = entity_id in {0x000100c2, 0x000003c2, 0x000004c2, 0xff0003c2, 0xff0004c2}

        sm_list = [s.strip() for s in info_column.split(',')]
        seq_number_list = list(map(int, frame_data.get('rtps.sm.seqNumber', 0).split(',')))
        sm_len_list = list(map(int, frame_data.get('rtps.sm.octetsToNextHeader', 0).split(',')))
        udp_length = int(frame_data.get('udp.length', 0))

        seq_number_iterator = iter(seq_number_list)
        for sm, sm_len in zip(sm_list, sm_len_list):
            if sm in ("INFO_TS", "INFO_DST"):  # TODO: Maybe INFO_SRC too?
                continue
            matches = re.match(r'^(.*?)\s*->\s*(.*)', sm)
            sm = matches.group(1).strip() if matches else sm
            sm_topic = matches.group(2).strip() if matches else None

            if sm in ("HEARTBEAT", "GAP"):
                # HEARTBEAT and GAP have 2 sequence numbers in the list, and we want the second one
                # so throw away the first sequence number.
                next(seq_number_iterator)

            if not self.sm_list:
                # Include full upd_length in the first submessage
                self.add_submessage(RTPSSubmessage(sm, sm_topic, udp_length, next(seq_number_iterator), self.discovery_frame))

            else:
                # Decrease the length of the first submessage by the length of the current submessage
                self.sm_list[0].length -= sm_len
                # Indicate more than one submessage in the frame
                self.sm_list.append(RTPSSubmessage(sm, sm_topic, sm_len, next(seq_number_iterator), self.discovery_frame, True))

        # Heartbeats are always the last submessage
        if self.sm_list[-1] in (SubmessageTypes.DISCOVERY_HEARTBEAT, SubmessageTypes.DISCOVERY_PIGGYBACK_HEARTBEAT,
                    SubmessageTypes.HEARTBEAT, SubmessageTypes.HEARTBEAT_BATCH,
                    SubmessageTypes.PIGGYBACK_HEARTBEAT, SubmessageTypes.PIGGYBACK_HEARTBEAT_BATCH):
            try:
                self.guid_dst, = create_guid(frame_data.get('rtps.guidPrefix.dst', None), frame_data.get('rtps.sm.rdEntityId', None))
            except Exception as e:
                # Shouldn't happen.  Log and raise
                logger.error(f"Error creating destination GUID: {e}")
                raise Exception(e)

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
        if not self.discovery_frame:
            return set()

        return set(sm.topic for sm in self.sm_list if sm.topic is not None)

    def __str__(self):
        result = [f"Frame: {self.frame_number:09} GUID: {self.guid_src} Discovery Frame: {self.discovery_frame}\n{" " * 2}Submessages ({len(self.sm_list)}):"]
        for i, submessage in enumerate(self.sm_list, start=1):
            result.append(f"{" " * 4}{i} {str(submessage)}")
        return "\n".join(result) + "\n"