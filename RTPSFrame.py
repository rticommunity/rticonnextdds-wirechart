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
    def __init__(self, sm_type, topic, length, seq_number_tuple, discovery_frame, multiple_sm=False):
        if any(term in sm_type.lower() for term in ("port", "ping")):
            raise InvalidPCAPDataException(f"Routing frame: {sm_type}.")

        self.topic = topic
        self.length = length
        self.seq_num_tuple = seq_number_tuple

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

        # TODO: Maybe remove this check
        # GAPs announce the next sequence number, so decrement by 1
        # if self.sm_type == SubmessageTypes.GAP:
        #     self.seq_number -= 1

    def __str__(self):
        return (f"Type: {self.sm_type.name}, Topic: {self.topic}, "
                f"Length: {self.length}, Seq Number: {self.seq_num_tuple}")

class RTPSFrame:
    """
    Represents a single frame extracted from a PCAP file.
    """

    def __init__(self, frame_data):
        """
        Initializes a RTPSFrame object with dynamic attributes.

        :param frame_data: Dictionary containing field names and their values.
        """
        def get_entity_id(entity_id_str):
            match = re.match(r'0x([0-9A-Fa-f]+)', entity_id_str)
            entity_id = match.group(1)
            return entity_id, int(entity_id, 16)
        def create_guid(frame_data, sm_id):
            def none_if_zero(value):
                return None if value == 0 else value
            guid_prefix_src = frame_data.get('rtps.guidPrefix.src')
            guid_prefix_dst = frame_data.get('rtps.guidPrefix.dst')
            wr_entity_id, _ = get_entity_id(frame_data.get('rtps.sm.wrEntityId'))
            rd_entity_id, _ = get_entity_id(frame_data.get('rtps.sm.rdEntityId'))

            if sm_id == SubmessageTypes.ACKNACK:
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
        self.guid_src, self.guid_dst, entity = None, None, None
        self.discovery_frame = False

        if not frame_data.get('rtps.guidPrefix.src', None):
                raise InvalidPCAPDataException(f"No GUID prefix.")

        if "Malformed Packet" in info_column:
            raise InvalidPCAPDataException(f"Malformed Packet: {info_column}.", log_level=logging.WARNING)

        _ , entity_id = get_entity_id(frame_data.get('rtps.sm.wrEntityId', None))
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
            seq_num_tuple = ()

            if sm in ("HEARTBEAT", "GAP"):
                # HEARTBEAT and GAP have 2 sequence numbers in the list
                seq_num_tuple = (next(seq_number_iterator), next(seq_number_iterator))
            else:
                # For all other submessages, we only get one sequence number
                seq_num_tuple = (next(seq_number_iterator),)

            if not self.sm_list:
                # Include full upd_length in the first submessage
                self.add_submessage(RTPSSubmessage(sm, sm_topic, udp_length, seq_num_tuple, self.discovery_frame))

            else:
                # Decrease the length of the first submessage by the length of the current submessage
                self.sm_list[0].length -= sm_len
                # Indicate more than one submessage in the frame
                self.sm_list.append(RTPSSubmessage(sm, sm_topic, sm_len, seq_num_tuple, self.discovery_frame, True))

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
        result = [f"Frame: {self.frame_number:09} GUID_SRC: {self.guid_src} GUID_DST: {self.guid_dst} Discovery Frame: {self.discovery_frame}\n{" " * 2}Submessages ({len(self.sm_list)}):"]
        for i, submessage in enumerate(self.sm_list, start=1):
            result.append(f"{" " * 4}{i} {str(submessage)}")
        return "\n".join(result) + "\n"