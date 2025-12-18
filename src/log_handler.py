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
import copy
import logging
import os

LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# Custom logging levels
TEST_ERROR = logging.CRITICAL + 10
ALWAYS = TEST_ERROR + 10
DELAYED = ALWAYS + 10
NONE = DELAYED + 10

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
        "DELAYED": DELAYED,
        "NONE": NONE,
    }

    # Convert the input string to uppercase and return the corresponding log level
    return log_levels.get(level_str.upper(), logging.INFO)  # Default to INFO if invalid

# Add the custom level name to the logging module
logging.addLevelName(TEST_ERROR, "TEST_ERROR")
logging.addLevelName(ALWAYS, "ALWAYS")
logging.addLevelName(DELAYED, "DELAYED")
logging.addLevelName(NONE, "NONE")

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
        formatter = logging.Formatter(LOG_FORMAT)
        ch.setFormatter(formatter)
        fh.setFormatter(formatter)

        # Add handlers to root logger
        root_logger.addHandler(ch)
        root_logger.addHandler(fh)

        # Add filters to exclude custom levels from console and file handlers
        ch.addFilter(ExcludeDelayedFilter())

# Define the custom log function
def always(self, message, *args, **kws):
    if self.isEnabledFor(ALWAYS):
        self._log(ALWAYS, message, args, **kws)

# Add the custom function to the Logger class
logging.Logger.always = always

# Define the custom log function
def delayed(self, message, *args, **kws):
    if self.isEnabledFor(DELAYED):
        self._log(DELAYED, message, args, **kws)

# Add the custom function to the Logger class
logging.Logger.delayed = delayed

# Define the custom log function
def test_error(self, message, *args, **kws):
    if self.isEnabledFor(TEST_ERROR):
        self._log(TEST_ERROR, message, args, **kws)

# Add the custom function to the Logger class
logging.Logger.test_error = test_error

class ExcludeDelayedFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno != DELAYED

class TkinterTextHandler(logging.Handler):
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

    def emit(self, record):
        msg = self.format(record)

        def append():
            if not self.text_widget or not self.text_widget.winfo_exists():
                return
            try:
                self.text_widget.insert("end", msg + "\n")
                self.text_widget.see("end")
            except tk.TclError:
                pass

        self.text_widget.after(0, append)

class DelayedLogHandler(logging.Handler):
    """
    A custom logging handler that delays the emission of log messages until triggered.
    """
    def __init__(self):
        super().__init__()
        self.log_messages = []  # Cache for log messages
        self.triggered = False  # Flag to control when logs are emitted
        self.target_handler = None

    def emit(self, record: logging.LogRecord):
        """
        Caches log messages or emits them if triggered.

        Args:
            record (LogRecord): The log record to handle.
        """
        if self.triggered:
            # Emit the log message immediately
            record = self._rewrite_level(record)
            if self.target_handler:
                self.target_handler.handle(record)
            else:
                # Fallback to print if no target handler is set
                print(self.format(record))
        else:
            # Cache the log message
            self.log_messages.append(record)

    def set_target_handler(self, handler: logging.Handler):
        """
        Sets the target handler where log messages will be emitted when triggered.

        Args:
            handler (logging.Handler): The handler to set as the target.
        """
        self.target_handler = handler

    def trigger(self):
        """
        Triggers the emission of all cached log messages and allows future logs to be emitted immediately.
        """
        self.triggered = True
        for message in self.log_messages:
            message = self._rewrite_level(message)
            if self.target_handler:
                # Emit the cached log message using the target handler
                self.target_handler.handle(message)
            else:
                # Fallback to print if no target handler is set
                print(self.format(message))
        self.log_messages.clear()  # Clear the cache

    def _rewrite_level(self, record: logging.LogRecord) -> logging.LogRecord:
        if record.levelno == DELAYED:
            record = copy.copy(record)
            record.levelno = ALWAYS
            record.levelname = logging.getLevelName(ALWAYS)
        return record

    def clear_cache(self):
        """
        Clears all cached log messages without emitting them.
        """
        self.log_messages.clear()
