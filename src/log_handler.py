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
import logging
import os

TEST_ERROR = logging.CRITICAL + 10
ALWAYS = TEST_ERROR + 10
NONE = ALWAYS + 10

def get_log_level(level_str: str) -> int:
    """
    Converts a string into a corresponding logging level.

    :param level_str: The log level as a string (e.g., "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL").
    :return: The corresponding logging level (e.g., logging.DEBUG, logging.INFO).
    """
    log_levels = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
        "TEST_ERROR": TEST_ERROR,
        "ALWAYS": ALWAYS,
        "NONE": NONE,
    }

    # Convert the input string to uppercase and return the corresponding log level
    return log_levels.get(level_str.upper(), logging.INFO)  # Default to INFO if invalid

# Add the custom level name to the logging module
logging.addLevelName(TEST_ERROR, "TEST_ERROR")
logging.addLevelName(ALWAYS, "ALWAYS")

# Configure the logger
def configure_root_logger(log_file='output/wirechart.log', console_level=logging.ERROR, file_level=logging.INFO):
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    if not root_logger.handlers:
        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(console_level)

        # File handler
        fh = logging.FileHandler(log_file, mode='w')
        fh.setLevel(file_level)

        # Formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        fh.setFormatter(formatter)

        # Add handlers to root logger
        root_logger.addHandler(ch)
        root_logger.addHandler(fh)

# Define the custom log function
def always(self, message, *args, **kws):
    if self.isEnabledFor(ALWAYS):
        self._log(ALWAYS, message, args, **kws)

# Add the custom function to the Logger class
logging.Logger.always = always

# Define the custom log function
def test_error(self, message, *args, **kws):
    if self.isEnabledFor(TEST_ERROR):
        self._log(TEST_ERROR, message, args, **kws)

# Add the custom function to the Logger class
logging.Logger.test_error = test_error