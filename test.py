#!/usr/bin/env python3
import json
import sys
import threading
import time
from pathlib import Path
from typing import Dict, Any
from datetime import datetime

from kauma import process_testcases
from paddingoracle.server import Server


def load_output_json(file_path: Path) -> Dict[str, Any]:
    try:
        with open(file_path) as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON file {file_path}: {e}")
        sys.exit(1)


def run_kauma(input_file: Path) -> dict:
    try:
        with open(input_file) as f:
            input_data = json.load(f)

        results = process_testcases(input_data)

        return results

    except Exception as e:
        print(f"Unexpected error:")
        print(f"Error type: {type(e).__name__}")
        print(f"Error: {str(e)}")
        sys.exit(1)


def run_json_tests():
    test_dir = Path("testcases")
    if not test_dir.exists():
        print("Error: testcases directory not found")
        sys.exit(1)

    total_tests = 0
    failed_tests = []

    print(f"\nStarting JSON tests at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 50)

    for input_file in test_dir.glob("*_input.json"):
        output_file = input_file.parent / input_file.name.replace("_input.json", "_output.json")
        if not output_file.exists():
            continue

        total_tests += 1
        test_name = input_file.stem.replace("_input", "")
        print(f"\nTesting {test_name}...")

        actual_output = run_kauma(input_file)
        expected_output = load_output_json(output_file)

        if actual_output == expected_output:
            print(f"✅ {test_name} passed")
        else:
            print(f"❌ {test_name} failed")
            print("\nExpected output:")
            print(json.dumps(expected_output, indent=2))
            print("\nActual output:")
            print(json.dumps(actual_output, indent=2))
            failed_tests.append(test_name)

    print("\n" + "=" * 50)
    print(f"JSON Test Summary:")
    print(f"Total tests: {total_tests}")
    print(f"Passed: {total_tests - len(failed_tests)}")
    print(f"Failed: {len(failed_tests)}")

    if failed_tests:
        print("\nFailed tests:")
        for test in failed_tests:
            print(f"- {test}")
        return False
    return True


def run_server(server):
    try:
        server.run()
    except Exception as e:
        print(f"Server error: {e}")


def main():
    host = 'localhost'
    port = 9999
    key = b'\xeeH\xe0\xf4\xd0c\xeb\xd8\xb87\x16\xd3\t\xfe\x87\xce'

    server = Server(host, port, key)

    server_thread = threading.Thread(target=run_server, args=(server,))
    server_thread.daemon = True
    server_thread.start()

    time.sleep(1)

    json_tests_passed = run_json_tests()
    if json_tests_passed:
        print("\nAll test suites passed! 🎉")

    sys.exit(0)


if __name__ == "__main__":
    main()
