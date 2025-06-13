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
    def __init__(self, endpoints: FlexDict):
        if not endpoints:
            raise ValueError("Endpoints must be a non-empty dictionary.")

        self.endpoints = endpoints

    @staticmethod
    def format_guid_entity_id(guid: int):
        prefix_src, id_src = RTPSFrame.static_guid_prefix_and_entity_id(guid)
        prefix_src = format(prefix_src, '024x')  # 96-bit hex string, no '0x', padded
        prefix_src = ':'.join(prefix_src[i:i+2] for i in range(0, len(prefix_src), 2))
        return prefix_src, hex(id_src)

    def print_all_unique_endpoints(self, topic: str):
        """
        Lists all endpoints for a given topic.

        :param topic: The topic to filter endpoints by.
        """
        if topic not in self.endpoints:
            logger.warning(f"No endpoints found for topic '{topic}'")
            return []

        dw_set = {
            f"{prefix} {id}"
            for guid_src, _ in self.endpoints[topic]
            for prefix, id in [WiresharkFilters.format_guid_entity_id(guid_src)]
        }

        dr_set = {
            f"{prefix} {id}"
            for _, guid_dst in self.endpoints[topic]
            for prefix, id in [WiresharkFilters.format_guid_entity_id(guid_dst)]
        }

        return "\n".join(["DataWriters"] + sorted(dw_set) + ["", "DataReaders"] + sorted(dr_set))

    def all_endpoints_filter(self, topic: str):
        """
        Generates a Wireshark filter for all endpoints of a given topic.

        :param topic: The topic to filter endpoints by.
        :return: A string representing the Wireshark filter.
        """
        if topic not in self.endpoints:
            logger.warning(f"No endpoints found for topic '{topic}'")
            return ""

        endpoint_filters = []
        for guid_src, guid_dst in self.endpoints[topic]:
            prefix_src, id_src = WiresharkFilters.format_guid_entity_id(guid_src)
            prefix_dst, id_dst = WiresharkFilters.format_guid_entity_id(guid_dst)
            endpoint_filters.append(f"((rtps.guidPrefix.src == {prefix_src} && rtps.sm.wrEntityId == {id_src}) && (rtps.guidPrefix.dst == {prefix_dst} && rtps.sm.rdEntityId == {id_dst}))")

        return " || ".join(endpoint_filters)