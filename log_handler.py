import logging
import os

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
        fh.setLevel(logging.DEBUG)

        # Formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - Line %(lineno)04d - %(message)s')
        ch.setFormatter(formatter)
        fh.setFormatter(formatter)

        # Add handlers to root logger
        root_logger.addHandler(ch)
        root_logger.addHandler(fh)