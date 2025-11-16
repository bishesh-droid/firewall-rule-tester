# firewall_tester/config.py

import os

# Path for the Firewall Tester log file
LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs')
LOG_FILE = os.path.join(LOG_DIR, 'firewall_test.log')

# Default timeout for network operations in seconds
DEFAULT_TIMEOUT = 1

# Verbosity level for console output
VERBOSE_CONSOLE_OUTPUT = True
