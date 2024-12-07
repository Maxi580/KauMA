import json
from typing import Dict


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def save_test_cases(input_cases: Dict, expected_outputs: Dict,
                    input_file: str = "generated_input.json",
                    output_file: str = "generated__output.json"):
    with open(input_file, 'w') as f:
        json.dump(input_cases, f, indent=2)

    with open(output_file, 'w') as f:
        json.dump(expected_outputs, f, indent=2)
