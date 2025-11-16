
import unittest
import subprocess
import os
import yaml

class TestFirewallTesterRunner(unittest.TestCase):
    def setUp(self):
        self.test_cases_dir = "/home/duffer/Gemini/Project_1/024_firewall_rule_tester/test_cases"
        os.makedirs(self.test_cases_dir, exist_ok=True)

    def tearDown(self):
        pass

    def test_tcp_filtered_scenario(self):
        test_case = {
            "name": "Test Filtered TCP Port",
            "dest_ip": "127.0.0.1",
            "dest_port": 12345,
            "protocol": "tcp",
            "expected_result": "open"
        }
        test_file_path = os.path.join(self.test_cases_dir, "filtered_tcp_test.yaml")
        with open(test_file_path, "w") as f:
            yaml.dump([test_case], f)

        command = [
            "sudo", "python3", "-m", "firewall_tester.cli",
            test_file_path,
            "--output-format", "json"
        ]
        
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            cwd="/home/duffer/Gemini/Project_1/024_firewall_rule_tester"
        )
        
        # The output is in the logger, so we need to read the log file
        with open("/home/duffer/Gemini/Project_1/024_firewall_rule_tester/logs/firewall_test.log", "r") as f:
            log_content = f.read()
        
        self.assertIn("[FAIL] Test 'Test Filtered TCP Port': Expected 'open', Got 'filtered'", log_content)

if __name__ == "__main__":
    unittest.main()
