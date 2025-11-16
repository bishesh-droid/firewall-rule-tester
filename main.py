import sys
from firewall_tester.cli import main

if __name__ == "__main__":
    # Ensure the script can be run with root/administrator privileges if needed
    # This is a placeholder for any platform-specific checks you might want to add
    
    # Example of how you might check for root on Unix-like systems:
    # import os
    # if os.geteuid() != 0:
    #     print("This script requires root privileges to send raw packets.")
    #     print("Please run with sudo.")
    #     sys.exit(1)

    main()
