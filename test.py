#!/usr/bin/env python3
import json
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Dict, Any, Tuple
from datetime import datetime
from contextlib import contextmanager

from kauma import process_testcases
from paddingoracle.server import Server


class TestError(Exception):
    def __init__(self, message: str, details: Dict = None):
        self.message = message
        self.details = details or {}
        self.traceback = traceback.format_exc()
        super().__init__(self.message)


@contextmanager
def timing_context(operation_name: str):
    start_time = time.time()
    try:
        yield
    finally:
        end_time = time.time()
        duration = end_time - start_time
        print(f"{operation_name} took {duration:.2f} seconds")


def load_output_json(file_path: Path) -> Tuple[Dict[str, Any], bool]:
    try:
        with timing_context(f"Loading {file_path.name}"):
            with open(file_path) as f:
                return json.load(f), True
    except json.JSONDecodeError as e:
        error_context = {
            'file': str(file_path),
            'error_type': 'JSONDecodeError',
            'error_msg': str(e),
            'line': e.lineno,
            'column': e.colno
        }
        raise TestError(f"Error parsing JSON file", error_context)
    except Exception as e:
        error_context = {
            'file': str(file_path),
            'error_type': type(e).__name__,
            'error_msg': str(e)
        }
        raise TestError(f"Error loading file", error_context)


def run_kauma(input_file: Path) -> dict:
    try:
        with timing_context(f"Processing {input_file.name}"):
            with open(input_file) as f:
                input_data = json.load(f)

            results = process_testcases(input_data)

            return results

    except Exception as e:
        error_context = {
            'file': str(input_file),
            'error_type': type(e).__name__,
            'error_msg': str(e),
            'traceback': traceback.format_exc()
        }
        raise TestError("Error processing test cases", error_context)


def compare_outputs(actual: dict, expected: dict, test_name: str) -> list[str]:
    differences = []

    actual_responses = actual.get('responses', {})
    expected_responses = expected.get('responses', {})

    actual_keys = set(actual_responses.keys())
    expected_keys = set(expected_responses.keys())

    if missing_keys := expected_keys - actual_keys:
        differences.append(f"Missing test cases: {', '.join(missing_keys)}")

    if extra_keys := actual_keys - expected_keys:
        differences.append(f"Extra test cases: {', '.join(extra_keys)}")

    for test_id in actual_keys & expected_keys:
        if actual_responses[test_id] != expected_responses[test_id]:
            differences.append(f"Test case {test_id} differs:")
            differences.append(f"  Expected: {expected_responses[test_id]}")
            differences.append(f"  Actual:   {actual_responses[test_id]}")

    return differences


def run_json_tests():
    test_dir = Path("testcases")
    if not test_dir.exists():
        raise TestError("Testcases directory not found")

    total_tests = 0
    failed_tests = []
    test_details = []

    print(f"\nStarting JSON tests at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 50)

    for input_file in test_dir.glob("*_input.json"):
        output_file = input_file.parent / input_file.name.replace("_input.json", "_output.json")
        if not output_file.exists():
            print(f"Warning: No output file found for {input_file.name}")
            continue

        total_tests += 1
        test_name = input_file.stem.replace("_input", "")
        print(f"\nTesting {test_name}...")

        try:
            actual_output = run_kauma(input_file)
            expected_output = load_output_json(output_file)[0]

            differences = compare_outputs(actual_output, expected_output, test_name)

            if not differences:
                print(f"✅ {test_name} passed")
                test_details.append({
                    'name': test_name,
                    'status': 'passed',
                    'duration': time.time()
                })
            else:
                print(f"❌ {test_name} failed")
                print("\nDifferences found:")
                for diff in differences:
                    print(f"  {diff}")
                failed_tests.append(test_name)
                test_details.append({
                    'name': test_name,
                    'status': 'failed',
                    'differences': differences
                })

        except TestError as e:
            print(f"❌ {test_name} failed with error:")
            print(f"Error: {e.message}")
            if e.details:
                print("Error details:")
                for key, value in e.details.items():
                    print(f"  {key}: {value}")
            if e.traceback:
                print("\nTraceback:")
                print(e.traceback)
            failed_tests.append(test_name)
            test_details.append({
                'name': test_name,
                'status': 'error',
                'error': e.message,
                'details': e.details
            })

    print("\n" + "=" * 50)
    print(f"JSON Test Summary:")
    print(f"Total tests: {total_tests}")
    print(f"Passed: {total_tests - len(failed_tests)}")
    print(f"Failed: {len(failed_tests)}")

    if failed_tests:
        print("\nFailed tests:")
        for test in failed_tests:
            print(f"- {test}")
            # Print details for failed test
            details = next((t for t in test_details if t['name'] == test), None)
            if details:
                if 'differences' in details:
                    print("  Differences:")
                    for diff in details['differences']:
                        print(f"    {diff}")
                if 'error' in details:
                    print(f"  Error: {details['error']}")
        return False
    return True


def run_server(server):
    try:
        print("Starting server...")
        server.run()
    except Exception as e:
        print(f"Server error: {e}")
        print("Server traceback:")
        traceback.print_exc()


def main():
    # Server for Padding Oracle
    host = 'localhost'
    port = 9999
    key = b'\xeeH\xe0\xf4\xd0c\xeb\xd8\xb87\x16\xd3\t\xfe\x87\xce'

    print(f"Initializing server on {host}:{port}")
    server = Server(host, port, key)

    server_thread = threading.Thread(target=run_server, args=(server,))
    server_thread.daemon = True
    server_thread.start()
    time.sleep(1)

    try:
        print("Running tests...")
        json_tests_passed = run_json_tests()
        if json_tests_passed:
            print("\nAll test suites passed! 🎉")
        else:
            print("\nSome tests failed. Check the output above for details.")
    except Exception as e:
        print("\nCritical error during test execution:")
        print(f"Error type: {type(e).__name__}")
        print(f"Error message: {str(e)}")
        print("\nTraceback:")
        traceback.print_exc()
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
