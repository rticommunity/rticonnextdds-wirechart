import re
from enum import Enum

class SubmessageTypes(Enum):
    DATA_P = "PARTICIPANT_DISCOVERY"
    DATA_RW = "ENDPOINT_DISCOVERY"
    DISCOVERY_STATE = "DISCOVERY_STATE"
    DATA = "DATA"
    DATA_STATE = "DATA_STATE"

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
        self.sm_type = sm_type
        self.topic = topic
        self.length = length
        self.seq_number = seq_number
        self.discovery_frame = False
        # GAPs announce the next sequence number, so decrement by 1
        if self.sm_type == "GAP":
            self.seq_number -= 1

        # If this is a HEARTBEAT and there are multiple submessages, this is a PIGGYBACK_HEARTBEAT
        if multiple_sm and "HEARTBEAT" in self.sm_type:
            self.sm_type = "PIGGYBACK_" + self.sm_type

        # Check for a state submessage type
        if "DATA" in self.sm_type:
            if self.sm_type == "DATA":
                self.sm_type = SubmessageTypes.DATA.value
            elif self.sm_type == "DATA(p)":
                self.discovery_frame = True
                self.sm_type = SubmessageTypes.DATA_P.value
            elif self.sm_type in ("DATA(r)", "DATA(w)"):
                self.discovery_frame = True
                self.sm_type = SubmessageTypes.DATA_RW.value
            elif re.search(r'DATA\([pwr]\[UD]\)', self.sm_type):
                # Unregister/Dispose for Discovery Data
                self.sm_type = SubmessageTypes.DISCOVERY_STATE.value
            elif "([" in self.sm_type:
                # Unregister/Dispose for User Data
                self.sm_type = SubmessageTypes.DATA_STATE.value

class RTPSFrame:
    """
    Represents a single frame extracted from a PCAP file.
    """

    def __init__(self, frame_data):
        """
        Initializes a RTPSFrame object with dynamic attributes.

        :param frame_data: Dictionary containing field names and their values.
        """
        self.frame_number = frame_data.get('frame.number', 0)

        self.sm_list = list()

        guid_prefix = frame_data.get('rtps.guidPrefix.src', None)
        if not guid_prefix:
            # PING frame or something similar
            raise InvalidPCAPDataException(f"No GUID prefix. Dumping frame {self.frame_number}.")

        wr_entity_id = frame_data.get('rtps.sm.wrEntityId')
        match = re.match(r'0x([0-9A-Fa-f]+)', wr_entity_id)
        self.guid = guid_prefix + match.group(1)

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

    def print_frame(self):
        """
        Prints the details of the RTPSFrame object in a readable format.
        """
        print(f"Frame: {self.frame_number} GUID: {self.guid}")
        print(f"{" " * 2}Submessages:")
        for i, submessage in enumerate(self.sm_list, start=1):
            print(f"{" " * 4}{i}. Type: {submessage.sm_type}, Topic: {submessage.topic}, "
                  f"Length: {submessage.length}, Seq Number: {submessage.seq_number}")
        print()

    def list_topics(self):
        """
        Returns a list of unique topics from the RTPSFrame object.
        """
        return set(submessage.topic for submessage in self.sm_list if submessage.topic)

    def __repr__(self):
        """
        Returns a string representation of the RTPSFrame object.
        """
        return f"RTPSFrame({', '.join(f'{key}={value}' for key, value in self.__dict__.items())})"