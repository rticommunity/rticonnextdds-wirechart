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
import os

# Local Application Imports
from src.log_handler import logging

class FrameTypes(Flag):
    UNSET           = 0x0000
    USER_DATA       = 0x0001
    DISCOVERY       = 0x0002
    META_DATA       = 0x0004
    ROUTING_SERVICE = 0x0008

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

class NoDiscoveryDataException(Exception):
    """Exception raised for missing discovery data."""

    def __init__(self, message):
        """
        :param message: The error message.
        """
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return self.message

def create_output_path(pcap_file, output_path, extension, description=None):
    """
    Creates an output path for a file with the specified extension.

    :param pcap_file: The input PCAP file.
    :param output_path: The base output directory.
    :param extension: The file extension (e.g., 'log', 'xlsx').
    :param description: Optional description to include in the filename.
    :return: The full path to the output file.
    """
    if not os.path.exists(output_path):
        os.makedirs(output_path)

    base_name = os.path.splitext(os.path.basename(pcap_file))[0]
    description_part = f"_{description}" if description else ""
    filename = f"{base_name}{description_part}.{extension}"
    return os.path.join(output_path, filename)

def guid_prefix(guid):
    """
    Extracts the prefix from a GUID.
    :param guid: The GUID to extract the prefix from.
    :return: The prefix of the GUID.
    """
    # GUID is a 128-bit integer and the prefix is the upper 96 bits (12 bytes)
    return guid >> 32