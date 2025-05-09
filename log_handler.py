import logging
import os

ALWAYS = logging.CRITICAL + 10

# Add the custom level name to the logging module
logging.addLevelName(ALWAYS, "ALWAYS")

# Configure the logger
def configure_root_logger(log_file='output/wirechart.log'):
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    if not root_logger.handlers:
        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.WARNING)

        # File handler
        fh = logging.FileHandler(log_file, mode='w')
        fh.setLevel(logging.INFO)

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