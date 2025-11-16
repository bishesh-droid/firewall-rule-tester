import yaml
from .logger import fw_logger

def validate_test_cases(test_cases):
    """
    Validates that each test case has the required fields.

    Args:
        test_cases (list): A list of test case dictionaries.

    Returns:
        bool: True if all test cases are valid, False otherwise.
    """
    required_fields = ['name', 'dest_ip', 'dest_port', 'protocol', 'expected_result']
    for i, test_case in enumerate(test_cases):
        if not isinstance(test_case, dict):
            fw_logger.error(f"[ERROR] Test case {i + 1} is not a valid dictionary.")
            return False

        for field in required_fields:
            if field not in test_case:
                fw_logger.error(f"[ERROR] Test case {i + 1} ('{test_case.get('name', 'N/A')}') is missing required field: '{field}'")
                return False
    return True

def parse_test_cases(file_path):
    """
    Reads a YAML file and parses it into a list of test case dictionaries.

    Args:
        file_path (str): The path to the YAML file containing test cases.

    Returns:
        list: A list of test case dictionaries, or an empty list on error.
    """
    try:
        with open(file_path, 'r') as f:
            test_cases = yaml.safe_load(f)

        if not isinstance(test_cases, list):
            fw_logger.error(f"[ERROR] YAML file {file_path} should contain a list of test cases.")
            return []

        fw_logger.info(f"[*] Loaded {len(test_cases)} test cases from {file_path}")

        if not validate_test_cases(test_cases):
            raise ValueError("Invalid test case format. See logs for details.")

        return test_cases
    except FileNotFoundError:
        fw_logger.error(f"[ERROR] Test case file not found: {file_path}")
        return []
    except yaml.YAMLError as e:
        fw_logger.error(f"[ERROR] Error parsing YAML file {file_path}: {e}")
        return []
    except ValueError as e:
        fw_logger.error(f"[ERROR] {e}")
        return []
    except Exception as e:
        fw_logger.critical(f"[CRITICAL] An unexpected error occurred while processing {file_path}: {e}")
        return []
