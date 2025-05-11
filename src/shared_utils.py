# Standard Library Imports
import os

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