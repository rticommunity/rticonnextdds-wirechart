import re

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

class PCAPFrame:
    """
    Represents a single frame extracted from a PCAP file.
    """

    def __init__(self, **kwargs):
        """
        Initializes a PCAPFrame object with dynamic attributes.

        :param kwargs: Key-value pairs representing field names and their values.
        """
        for key, value in kwargs.items():
            # Replace dots with underscores in attribute names
            sanitized_key = key.replace('.', '_')
            setattr(self, sanitized_key, value)

        # Example: Accessing dynamic attributes using sanitized names
        guid_prefix = getattr(self, 'rtps_guidPrefix_src', None)
        wr_entity_id = getattr(self, 'rtps_sm_wrEntityId', None)

        if guid_prefix and wr_entity_id:
            match = re.match(r'0x([0-9A-Fa-f]+)', wr_entity_id)
            if match:
                self.guid = guid_prefix + match.group(1)
            else:
                self.guid = None
        else:
            self.guid = None

        # Example: Accessing another dynamic attribute
        seq_number = getattr(self, 'rtps_sm_seqNumber', None)
        if seq_number:
            self.seq_number = list(map(int, seq_number.split(',')))
        else:
            self.seq_number = None

    def __repr__(self):
        """
        Returns a string representation of the PCAPFrame object.
        """
        return f"PCAPFrame({', '.join(f'{key}={value}' for key, value in self.__dict__.items())})"