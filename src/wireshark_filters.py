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


# Third-Party Library Imports


# Local Application Imports
from src.flex_dictionary import FlexDict
from src.log_handler import logging
from src.rtps_frame import RTPSFrame

logger = logging.getLogger(__name__)


class WiresharkFilters:
    """
    A utility class for generating Wireshark filters and printing endpoint information
    based on RTPS (Real-Time Publish-Subscribe) data.

    Attributes:
        endpoints (FlexDict): A dictionary-like object containing endpoint information.
    """

    def __init__(self, endpoints: FlexDict):
        """
        Initializes the WiresharkFilters instance.

        Args:
            endpoints (FlexDict): A dictionary-like object containing endpoint information.

        Raises:
            ValueError: If the endpoints dictionary is empty or None.
        """
        if not endpoints:
            raise ValueError("Endpoints must be a non-empty dictionary.")

        self.endpoints = endpoints

    @staticmethod
    def format_guid_entity_id(guid: int) -> tuple:
        """
        Formats a GUID (Globally Unique Identifier) into a Wireshark-compatible prefix and entity ID.

        Args:
            guid (int): The GUID to format.

        Returns:
            tuple: A tuple containing the formatted prefix (str) and entity ID (str).

        Example:
            Input GUID: 123456789
            Output: ('00:00:00:00:00:00:00:00:00:00:00:00', '0x75bcd15')
        """
        prefix_src, id_src = RTPSFrame.static_guid_prefix_and_entity_id(guid)
        prefix_src = format(prefix_src, '024x')  # 96-bit hex string, no '0x', padded
        prefix_src = ':'.join(prefix_src[i:i+2] for i in range(0, len(prefix_src), 2))
        return prefix_src, hex(id_src)

    def print_all_unique_endpoints(self, topic: str = None, domain: int = None) -> str:
        """
        Lists all unique endpoints (DataWriters and DataReaders) for a given topic and domain.

        Args:
            topic (str, optional): The topic to filter endpoints by. Defaults to None.
            domain (int, optional): The domain to filter endpoints by. Defaults to None.

        Returns:
            str: A formatted string listing all unique DataWriters and DataReaders.

        Example:
            DataWriters
            00:00:00:00:00:00:00:00:00:00:00:01 0x1234
            00:00:00:00:00:00:00:00:00:00:00:02 0x5678

            DataReaders
            00:00:00:00:00:00:00:00:00:00:00:03 0x9abc
        """
        if not self.endpoints.key_present(topic=topic):
            logger.warning(f"No endpoints found for topic '{topic}'")
            return ""

        dw_set = {
            f"{prefix} {id}"
            for guid_src, _ in self.endpoints.get_elements_as_set(topic=topic, domain=domain)
            for prefix, id in [WiresharkFilters.format_guid_entity_id(guid_src)]
        }

        dr_set = {
            f"{prefix} {id}"
            for _, guid_dst in self.endpoints.get_elements_as_set(topic=topic, domain=domain)
            for prefix, id in [WiresharkFilters.format_guid_entity_id(guid_dst)]
        }

        return "\n".join([f"DataWriters ({len(dw_set)})"] + sorted(dw_set) + ["", f"DataReaders ({len(dr_set)})"] + sorted(dr_set))

    def all_endpoints_filter(self, topic: str = None, domain: int = None) -> str:
        """
        Generates a Wireshark filter for all endpoints of a given topic and domain.

        Args:
            topic (str, optional): The topic to filter endpoints by. Defaults to None.
            domain (int, optional): The domain to filter endpoints by. Defaults to None.

        Returns:
            str: A string representing the Wireshark filter.

        Example:
            ((rtps.guidPrefix.src == 00:00:00:00:00:00:00:00:00:00:00:01 &&
              rtps.sm.wrEntityId == 0x1234) &&
             (rtps.guidPrefix.dst == 00:00:00:00:00:00:00:00:00:00:00:02 &&
              rtps.sm.rdEntityId == 0x5678)) || ...
        """
        if not self.endpoints.key_present(topic=topic):
            logger.warning(f"No endpoints found for topic '{topic}'")
            return ""

        endpoint_filters = []
        for guid_src, guid_dst in self.endpoints.get_elements_as_set(topic=topic, domain=domain):
            prefix_src, id_src = WiresharkFilters.format_guid_entity_id(guid_src)
            prefix_dst, id_dst = WiresharkFilters.format_guid_entity_id(guid_dst)
            endpoint_filters.append(f"((rtps.guidPrefix.src == {prefix_src} && rtps.sm.wrEntityId == {id_src})"
                                    f" && (rtps.guidPrefix.dst == {prefix_dst} && rtps.sm.rdEntityId == {id_dst}))")

        return " || ".join(endpoint_filters)