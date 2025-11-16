# Firewall Rule Tester

This project implements a command-line interface (CLI) tool designed to test and verify firewall rules. It allows network administrators and security analysts to define a set of test cases (specifying source/destination IPs, ports, protocols, and expected outcomes) and then automatically sends crafted packets to determine if the firewall behaves as expected. Any discrepancies between the actual and expected results are reported, helping to identify misconfigurations.

## Features

-   **YAML-based Test Cases:** Define firewall test scenarios in a human-readable YAML format.
-   **TCP & UDP Testing:** Supports testing both TCP and UDP protocols to determine port states (open, closed, filtered).
-   **Expected vs. Actual Results:** Compares the observed network behavior against the predefined expected outcomes for each test case.
-   **Detailed Reporting:** Generates a clear report (console or JSON format) highlighting passed and failed tests, along with recommendations for failed cases.
-   **Scapy Integration:** Leverages Scapy for crafting and sending custom network packets.
-   **Command-Line Interface:** Easy-to-use CLI for executing tests and viewing reports.

## Project Structure

```
.
├── firewall_tester/
│   ├── __init__.py        # Package initialization
│   ├── cli.py             # Command-line interface using Click
│   ├── tester.py          # Core logic for sending packets and analyzing responses
│   ├── rules_parser.py    # Parses test cases from YAML files
│   ├── reporter.py        # Generates test reports
│   ├── logger.py          # Configures logging for the tester
│   └── config.py          # Configuration for logging and default timeouts
├── test_cases/
│   └── example_rules.yaml # Example YAML file defining test cases
├── logs/
│   └── firewall_test.log  # Log file for test results
├── tests/
│   ├── __init__.py
│   └── test_tester.py     # Unit tests for tester and rules_parser logic
├── .env.example           # Example environment variables (not strictly needed for this tool)
├── .gitignore
├── conceptual_analysis.txt
├── README.md
└── requirements.txt
```

## Prerequisites

-   Python 3.7+
-   `pip` for installing dependencies
-   **Scapy dependencies:** Scapy often requires `libpcap` (Linux/macOS) or WinPcap/Npcap (Windows). Ensure these are installed on your system.
    -   **Linux:** `sudo apt-get install libpcap-dev` (Debian/Ubuntu) or `sudo yum install libpcap-devel` (RHEL/CentOS)
    -   **Windows:** Install Npcap (recommended over WinPcap) from [nmap.org/npcap/](https://nmap.org/npcap/)

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/Firewall-Rule-Tester.git
    cd Firewall-Rule-Tester
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

Run the Firewall Rule Tester from the project root directory. **Note:** Sending custom network packets typically requires root/administrator privileges.

```bash
sudo python -m firewall_tester <TEST_CASES_FILE>
```

**`TEST_CASES_FILE`**: Path to a YAML file containing your firewall test cases (e.g., `test_cases.yaml`).

**Examples:**

-   **Run tests from the example rules file:**
    ```bash
    sudo python -m firewall_tester test_cases.yaml
    ```

-   **Run tests and save the report to a JSON file:**
    ```bash
    sudo python -m firewall_tester test_cases.yaml -f json -o firewall_report.json
    ```

**Important Considerations for Testing:**

-   **Target IP:** Ensure the `dest_ip` in your test cases points to a machine *behind* the firewall you intend to test.
-   **Tester Location:** The tool should ideally be run from a machine *outside* the firewall to simulate external traffic.
-   **Backend Services:** For `expected_result: open` tests, ensure the target machine has a service listening on that port to receive the connection.

## Ethical Considerations

-   **Authorization:** Only test firewalls and networks you own or have explicit, written permission to test. Unauthorized testing is illegal and unethical.
-   **Network Impact:** Be mindful of the traffic generated. Aggressive testing can impact network performance or trigger security alerts.
-   **Coordination:** Always coordinate with network administrators when testing production firewalls.
-   **Educational Purpose:** This tool is for educational and research purposes only. It is a simplified implementation and should not be used as a substitute for commercial, production-grade testing solutions.

## Testing

To run the automated tests, execute the following command from the project's root directory:

```bash
python -m unittest discover tests
```

## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.

## License

This project is licensed under the MIT License.