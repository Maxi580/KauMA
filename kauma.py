import json
import sys
from pathlib import Path
from typing import Dict, Any

from block_poly.b64_block import B64Block
from block_poly.block import Block
from block_poly.coefficients import Coefficients

from gfmul import gfmul
from sea128 import sea_encrypt, sea_decrypt
from fde import encrypt_fde, decrypt_fde


def poly2block(arguments: Dict[str, Any]) -> Dict[str, Any]:
    coefficients = arguments["coefficients"]
    result = Coefficients(coefficients)
    return {"block": result.get_b64_block()}


def block2poly(arguments: Dict[str, Any]) -> Dict[str, Any]:
    block = arguments["block"]
    result = B64Block(block)
    return {"coefficients": result.get_coefficients()}


def gfmul_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    a = arguments["a"]
    b = arguments["b"]

    a_block = B64Block(a).get_block()
    b_block = B64Block(b).get_block()

    result = gfmul(a_block, b_block)

    return {"product": Block(result).get_b64_block()}


def sea128_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Handle SEA-128 encryption/decryption"""
    mode = arguments["mode"]
    key = B64Block(arguments["key"]).get_block()
    input_data = B64Block(arguments["input"]).get_block()

    if mode == "encrypt":
        result = sea_encrypt(key, input_data)
    elif mode == "decrypt":
        result = sea_decrypt(key, input_data)
    else:
        raise ValueError(f"Unknown SEA-128 mode: {mode}")

    return {"output": Block(result).get_b64_block()}


def xex_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    mode = arguments["mode"]
    key = B64Block(arguments["key"]).get_block()
    tweak = B64Block(arguments["tweak"]).get_block()
    input_data = B64Block(arguments["input"]).get_block()

    if mode == "encrypt":
        result = encrypt_fde(key, tweak, input_data)
    elif mode == "decrypt":
        result = decrypt_fde(key, tweak, input_data)
    else:
        raise ValueError(f"Unknown XEX mode: {mode}")

    return {"output": Block(result).get_b64_block()}


ACTION_PROCESSORS = {
    "poly2block": poly2block,
    "block2poly": block2poly,
    "gfmul": gfmul_action,
    "sea128": sea128_action,
    "xex": xex_action
}


def process_testcases(input_json):
    """Process all test cases and return results"""
    responses = {}

    for test_id, test_data in input_json["testcases"].items():
        action = test_data["action"]
        arguments = test_data["arguments"]

        if action in ACTION_PROCESSORS:
            func = ACTION_PROCESSORS[action]
            responses[test_id] = func(arguments)

    return {"responses": responses}


def main():
    if len(sys.argv) != 2:
        print("Usage: ./kauma <test_file.json>", file=sys.stderr)
        sys.exit(1)

    test_file = Path(sys.argv[1])

    if not test_file.exists():
        raise f"Error: File {test_file} does not exist"

    try:
        with open(test_file) as f:
            input_data = json.load(f)

        results = process_testcases(input_data)

        print(json.dumps(results))

    except Exception as e:
        raise f"Error: {e}"


if __name__ == "__main__":
    main()