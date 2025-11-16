import click
import sys
import os

from .tester import FirewallRuleTester
from .rules_parser import parse_test_cases
from .reporter import generate_report
from .logger import fw_logger

@click.command()
@click.argument('test_cases_file', type=click.Path(exists=True))
@click.option('--output-format', '-f', type=click.Choice(['console', 'json'], case_sensitive=False),
default='console', help='Output format for the report.')
@click.option('--output-file', '-o', type=str,
              help='Save report to a file (e.g., report.json or report.txt).')
def main(test_cases_file, output_format, output_file):
    """
    A command-line tool to test firewall rules.

    TEST_CASES_FILE: Path to a YAML file containing firewall test cases.
    """
    try:
        fw_logger.info(f"[*] Starting Firewall Rule Tester with test cases from: {test_cases_file}")

        test_cases = parse_test_cases(test_cases_file)
        if not test_cases:
            fw_logger.error("Error: No test cases loaded. Exiting.")
            sys.exit(1)

        tester = FirewallRuleTester(test_cases=test_cases)

        results = tester.run_tests()
        report = generate_report(results, output_format)

        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(report)
                fw_logger.info(f"[*] Report saved to: {output_file}")
            except IOError as e:
                fw_logger.error(f"Error: Could not write report to file {output_file}: {e}")
        else:
            # Use the logger to print the report to the console
            fw_logger.info(report)

    except Exception as e:
        fw_logger.critical(f"[CRITICAL] An unhandled error occurred: {e}")
        sys.exit(1)

    fw_logger.info("[*] Firewall Rule Tester finished.")

