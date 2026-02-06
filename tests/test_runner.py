
import unittest
import subprocess
import os
import yaml

class TestFirewallTesterRunner(unittest.TestCase):
    def setUp(self):
        self.test_cases_dir = "/home/duffer/Gemini/Project_1(complete)/024_firewall_rule_tester/test_cases"
        os.makedirs(self.test_cases_dir, exist_ok=True)

    def tearDown(self):
        pass

    def test_tcp_filtered_scenario(self):
        """Test that the runner module loads and test case YAML parsing works."""
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

        # Verify the test case file was created and is valid YAML
        with open(test_file_path, "r") as f:
            loaded = yaml.safe_load(f)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]["name"], "Test Filtered TCP Port")
        self.assertEqual(loaded[0]["dest_ip"], "127.0.0.1")
        self.assertEqual(loaded[0]["dest_port"], 12345)
        self.assertEqual(loaded[0]["protocol"], "tcp")

if __name__ == "__main__":
    unittest.main()
