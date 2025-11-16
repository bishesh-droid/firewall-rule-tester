import json

def generate_report(test_results, output_format="console"):
    """
    Generates a report from the firewall test results.

    Args:
        test_results (list): A list of test result dictionaries.
        output_format (str): The desired output format ('console' or 'json').

    Returns:
        str: The formatted report.
    """
    if output_format == "json":
        return json.dumps(test_results, indent=4)
    else:
        report_lines = []
        report_lines.append("\n--- Firewall Rule Test Report ---")
        report_lines.append(f"Total test cases run: {len(test_results)}")

        passed_tests = [r for r in test_results if r['status'] == 'PASS']
        failed_tests = [r for r in test_results if r['status'] == 'FAIL']
        skipped_tests = [r for r in test_results if r['actual_result'] == 'skipped']

        report_lines.append(f"Passed: {len(passed_tests)}")
        report_lines.append(f"Failed: {len(failed_tests)}")
        report_lines.append(f"Skipped: {len(skipped_tests)}")

        if failed_tests:
            report_lines.append("\n[!!!] Failed Test Cases:")
            for test in failed_tests:
                report_lines.append(f"  - Name: {test['name']}")
                report_lines.append(f"    Target: {test['dest_ip']}:{test['dest_port']}/{test['protocol']}")
                report_lines.append(f"    Expected: {test['expected_result']}")
                report_lines.append(f"    Actual: {test['actual_result']}")
                report_lines.append("    Recommendation: Review firewall rules for this traffic.")

        if skipped_tests:
            report_lines.append("\n[---] Skipped Test Cases:")
            for test in skipped_tests:
                report_lines.append(f"  - Name: {test['name']}")
                report_lines.append(f"    Reason: Unsupported protocol '{test['protocol']}'.")

        report_lines.append("\n--- End of Report ---")
        return "\n".join(report_lines)
