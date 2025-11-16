import socket
import time
from scapy.all import IP, TCP, UDP, ICMP, sr1, sr, RandShort

from .logger import fw_logger
from .config import DEFAULT_TIMEOUT

class FirewallRuleTester:
    """
    Tests firewall rules by sending crafted packets and analyzing responses.
    """
    def __init__(self, test_cases):
        """
        Initializes the FirewallRuleTester.

        Args:
            test_cases (list): A list of test case dictionaries.
        """
        self.test_cases = test_cases
        self.results = []
        fw_logger.info(f"[*] Initialized Firewall Rule Tester with {len(self.test_cases)} test cases.")

    def _test_tcp_port(self, dest_ip, dest_port, timeout=DEFAULT_TIMEOUT):
        """
        Attempts a TCP SYN scan to determine if a TCP port is open, closed, or filtered.
        Returns 'open', 'closed', 'filtered', or 'error'.
        """
        try:
            # Craft SYN packet
            ip_layer = IP(dst=dest_ip)
            tcp_layer = TCP(dport=dest_port, flags="S", seq=RandShort())
            packet = ip_layer / tcp_layer

            # Send packet and wait for response
            resp = sr1(packet, timeout=timeout, verbose=0)

            if resp is None:
                return "filtered"  # No response usually means filtered
            elif resp.haslayer(TCP):
                if resp[TCP].flags == 0x12:  # SYN-ACK (SA)
                    # Send RST to close the connection gracefully
                    sr(IP(dst=dest_ip) / TCP(dport=dest_port, flags="R", seq=resp[TCP].ack), timeout=1, verbose=0)
                    return "open"
                elif resp[TCP].flags == 0x14:  # RST-ACK (RA)
                    return "closed"
            elif resp.haslayer(ICMP):
                # ICMP unreachable error
                if int(resp[ICMP].type) == 3 and int(resp[ICMP].code) in [1, 2, 3, 9, 10, 13]:
                    return "filtered"
            return "filtered"  # Other unexpected responses
        except Exception as e:
            fw_logger.error(f"[ERROR] TCP test for {dest_ip}:{dest_port} failed: {e}")
            return "error"

    def _test_udp_port(self, dest_ip, dest_port, timeout=DEFAULT_TIMEOUT):
        """
        Attempts a UDP scan to determine if a UDP port is open/filtered or closed.
        Returns 'open|filtered', 'closed', or 'error'.
        """
        try:
            # Craft UDP packet
            ip_layer = IP(dst=dest_ip)
            udp_layer = UDP(dport=dest_port)
            packet = ip_layer / udp_layer

            # Send packet and wait for response
            resp = sr1(packet, timeout=timeout, verbose=0)

            if resp is None:
                return "open|filtered"  # No response could mean open or filtered
            elif resp.haslayer(ICMP):
                # ICMP port unreachable indicates a closed port
                if int(resp[ICMP].type) == 3 and int(resp[ICMP].code) == 3:
                    return "closed"
            elif resp.haslayer(UDP):
                # A UDP response means the port is open
                return "open"
            return "open|filtered"
        except Exception as e:
            fw_logger.error(f"[ERROR] UDP test for {dest_ip}:{dest_port} failed: {e}")
            return "error"

    def run_tests(self):
        """
        Executes all defined test cases and stores the results.
        """
        fw_logger.info("[*] Starting firewall rule tests...")
        for i, test_case in enumerate(self.test_cases):
            try:
                test_name = test_case.get('name', f"Test Case {i + 1}")
                dest_ip = test_case['dest_ip']
                dest_port = test_case['dest_port']
                protocol = test_case['protocol'].lower()
                expected_result = test_case['expected_result'].lower()

                fw_logger.info(
                    f"[TEST] Running '{test_name}' (-> {dest_ip}:{dest_port}/{protocol}, Expected: {expected_result})")

                actual_result = "error"
                if protocol == "tcp":
                    actual_result = self._test_tcp_port(dest_ip, dest_port)
                elif protocol == "udp":
                    actual_result = self._test_udp_port(dest_ip, dest_port)
                else:
                    fw_logger.warning(f"[WARNING] Unsupported protocol '{protocol}' for test '{test_name}'. Skipping.")
                    actual_result = "skipped"

                # Determine status
                status = "FAIL"
                if actual_result == expected_result:
                    status = "PASS"
                # Special handling for UDP 'open|filtered'
                elif protocol == "udp" and actual_result == "open|filtered" and expected_result in ["open", "open|filtered"]:
                    status = "PASS"


                if status == "FAIL":
                    fw_logger.warning(f"[FAIL] Test '{test_name}': Expected '{expected_result}', Got '{actual_result}'")
                else:
                    fw_logger.info(f"[PASS] Test '{test_name}': Actual '{actual_result}' matches expected.")

                self.results.append({
                    "name": test_name,
                    "dest_ip": dest_ip,
                    "dest_port": dest_port,
                    "protocol": protocol,
                    "expected_result": expected_result,
                    "actual_result": actual_result,
                    "status": status
                })
            except KeyError as e:
                fw_logger.error(f"[ERROR] Skipping test case {i + 1} due to missing key: {e}")
                continue  # Skip to the next test case
            except Exception as e:
                fw_logger.critical(f"[CRITICAL] An unexpected error occurred during test '{test_case.get('name', i + 1)}': {e}")
                continue

        fw_logger.info("[*] Firewall rule tests finished.")
        return self.results
