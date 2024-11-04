#!/usr/bin/env python3
import json
import sys
from pathlib import Path
from typing import Dict, Any
import subprocess
from datetime import datetime
import pytest


def load_output_json(file_path: Path) -> Dict[str, Any]:
    try:
        with open(file_path) as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON file {file_path}: {e}")
        sys.exit(1)


def run_kauma(input_file: Path) -> dict:
    try:
        cmd = ['./kauma', str(input_file)]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False
        )

        return json.loads(result.stdout)

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


def run_randomized_tests():
    print(f"\nStarting randomized tests at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 50)

    result = pytest.main(['-v', 'randomized_test.py'])

    return result == 0


def main():
    json_tests_passed = run_json_tests()
    pytest_tests_passed = run_randomized_tests()

    if not (json_tests_passed and pytest_tests_passed):
        sys.exit(1)

    print("\nAll test suites passed! 🎉")
    sys.exit(0)


if __name__ == "__main__":
    main()