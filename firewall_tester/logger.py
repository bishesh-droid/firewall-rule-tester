# firewall_tester/logger.py

import logging
import os
import sys
from .config import LOG_FILE, LOG_DIR, VERBOSE_CONSOLE_OUTPUT

def setup_logging():
    """
    Configures logging for the Firewall Rule Tester.
    Logs to a file and optionally to the console.
    """
    # Ensure log directory exists
    os.makedirs(LOG_DIR, exist_ok=True)

    # Create a logger
    fw_logger = logging.getLogger('firewall_tester')
    fw_logger.setLevel(logging.INFO)
    fw_logger.propagate = False  # Prevent duplicate messages in console

    # File handler
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    fw_logger.addHandler(file_handler)

    # Console handler
    if VERBOSE_CONSOLE_OUTPUT:
        console_handler = logging.StreamHandler(sys.stdout)
        # Use a formatter that only shows the message for console output
        console_handler.setFormatter(logging.Formatter('%(message)s'))
        fw_logger.addHandler(console_handler)

    return fw_logger

# Initialize logger when module is imported
fw_logger = setup_logging()
