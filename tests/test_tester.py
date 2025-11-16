import unittest
from unittest.mock import patch, MagicMock
import os
import yaml

from scapy.all import IP, TCP, UDP, ICMP

from firewall_tester.rules_parser import parse_test_cases
from firewall_tester.tester import FirewallRuleTester

class TestRulesParser(unittest.TestCase):

    def setUp(self):
        self.test_cases_file = "test_cases/temp_rules.yaml"
        # Mock logger
        patch('firewall_tester.rules_parser.fw_logger').start()
        self.addCleanup(patch.stopall)

    def tearDown(self):
        if os.path.exists(self.test_cases_file):
            os.remove(self.test_cases_file)

    def test_parse_valid_yaml(self):
        os.makedirs("test_cases", exist_ok=True)
        yaml_content = """
- name: Test1
  dest_ip: 1.1.1.1
  dest_port: 80
  protocol: tcp
  expected_result: open
- name: Test2
  dest_ip: 2.2.2.2
  dest_port: 53
  protocol: udp
  expected_result: closed
        """
        with open(self.test_cases_file, 'w') as f:
            f.write(yaml_content)
        
        test_cases = parse_test_cases(self.test_cases_file)
        self.assertEqual(len(test_cases), 2)
        self.assertEqual(test_cases[0]['name'], "Test1")
        self.assertEqual(test_cases[1]['protocol'], "udp")

    def test_parse_non_existent_file(self):
        test_cases = parse_test_cases("non_existent_file.yaml")
        self.assertEqual(test_cases, [])

    def test_parse_invalid_yaml(self):
        os.makedirs("test_cases", exist_ok=True)
        invalid_yaml_content = "- name: Test1\n  dest_ip: 1.1.1.1\n  dest_port: 80\n  protocol: tcp\n  expected_result: open\n  - invalid: -"
        with open(self.test_cases_file, 'w') as f:
            f.write(invalid_yaml_content)
        
        test_cases = parse_test_cases(self.test_cases_file)
        self.assertEqual(test_cases, [])

class TestFirewallRuleTester(unittest.TestCase):

    def setUp(self):
        self.mock_logger = MagicMock()
        patch('firewall_tester.tester.fw_logger', self.mock_logger).start()
        self.addCleanup(patch.stopall)

        self.test_cases = [
            {"name": "TCP Open", "dest_ip": "1.1.1.1", "dest_port": 80, "protocol": "tcp", "expected_result": "open"},
            {"name": "TCP Closed", "dest_ip": "1.1.1.1", "dest_port": 22, "protocol": "tcp", "expected_result": "closed"},
            {"name": "TCP Filtered", "dest_ip": "1.1.1.1", "dest_port": 443, "protocol": "tcp", "expected_result": "filtered"},
            {"name": "UDP Open/Filtered", "dest_ip": "1.1.1.1", "dest_port": 53, "protocol": "udp", "expected_result": "open|filtered"},
            {"name": "UDP Closed", "dest_ip": "1.1.1.1", "dest_port": 12345, "protocol": "udp", "expected_result": "closed"},
            {"name": "UDP Open", "dest_ip": "1.1.1.1", "dest_port": 5060, "protocol": "udp", "expected_result": "open"},
        ]
        self.tester = FirewallRuleTester(self.test_cases)

    @patch('firewall_tester.tester.sr1')
    @patch('firewall_tester.tester.sr')
    def test_test_tcp_port_open(self, mock_sr, mock_sr1):
        # Mock SYN-ACK response
        mock_resp = MagicMock()
        mock_resp.haslayer.side_effect = lambda x: x == TCP
        mock_resp[TCP].flags = 0x12
        mock_resp[TCP].seq = 100
        mock_resp[TCP].ack = 200
        mock_sr1.return_value = mock_resp

        result = self.tester._test_tcp_port("1.1.1.1", 80)
        self.assertEqual(result, "open")
        mock_sr1.assert_called_once()
        mock_sr.assert_called_once()

    @patch('firewall_tester.tester.sr1')
    def test_test_tcp_port_closed(self, mock_sr1):
        # Mock RST response
        mock_resp = MagicMock()
        mock_resp.haslayer.side_effect = lambda x: x == TCP
        mock_resp[TCP].flags = 0x14
        mock_sr1.return_value = mock_resp

        result = self.tester._test_tcp_port("1.1.1.1", 22)
        self.assertEqual(result, "closed")
        mock_sr1.assert_called_once()

    @patch('firewall_tester.tester.sr1')
    def test_test_tcp_port_filtered(self, mock_sr1):
        # Mock no response
        mock_sr1.return_value = None

        result = self.tester._test_tcp_port("1.1.1.1", 443)
        self.assertEqual(result, "filtered")
        mock_sr1.assert_called_once()

    @patch('firewall_tester.tester.sr1')
    def test_test_udp_port_open_filtered(self, mock_sr1):
        # Mock no response
        mock_sr1.return_value = None

        result = self.tester._test_udp_port("1.1.1.1", 53)
        self.assertEqual(result, "open|filtered")
        mock_sr1.assert_called_once()

    @patch('firewall_tester.tester.sr1')
    def test_test_udp_port_closed(self, mock_sr1):
        # Mock ICMP port unreachable
        mock_resp = MagicMock()
        mock_resp.haslayer.side_effect = lambda x: x == ICMP
        mock_resp[ICMP].type = 3
        mock_resp[ICMP].code = 3
        mock_sr1.return_value = mock_resp

        result = self.tester._test_udp_port("1.1.1.1", 12345)
        self.assertEqual(result, "closed")
        mock_sr1.assert_called_once()

    def test_run_tests(self):
        with patch.object(self.tester, '_test_tcp_port') as mock_tcp_test, \
             patch.object(self.tester, '_test_udp_port') as mock_udp_test:
            
            mock_tcp_test.side_effect = ["open", "closed", "filtered"]
            mock_udp_test.side_effect = ["open|filtered", "closed", "open"]

            results = self.tester.run_tests()

            self.assertEqual(len(results), len(self.test_cases))

            # Check a passed TCP test
            self.assertEqual(results[0]['status'], "PASS")
            self.assertEqual(results[0]['actual_result'], "open")

            # Check a failed TCP test (expected closed, got open)
            self.assertEqual(results[1]['status'], "PASS")
            self.assertEqual(results[1]['actual_result'], "closed")

            # Check a UDP open|filtered test
            self.assertEqual(results[3]['status'], "PASS")
            self.assertEqual(results[3]['actual_result'], "open|filtered")
            
            # Check a UDP open test
            self.assertEqual(results[5]['status'], "PASS")
            self.assertEqual(results[5]['actual_result'], "open")


if __name__ == '__main__' :
    unittest.main()
