import json
import sys
from pathlib import Path
from typing import Dict, Any

from block_poly.b64_block import B64Block
from block_poly.block import Block
from block_poly.gcm_coefficients import GCM_Coefficients
from block_poly.xex_coefficients import XEX_Coefficients

from gfmul import xex_gfmul, gcm_gfmul
from sea128 import sea_encrypt, sea_decrypt, aes_decrypt, aes_encrypt
from xex import encrypt_xex, decrypt_xex
from gcm import gcm_encrypt, gcm_decrypt
from paddingoracle.paddingOracle import get_plaintext

ENCRYPT_MODE = "encrypt"
DECRYPT_MODE = "decrypt"
AES_128_ALGORITHM = "aes128"
XEX_SEMANTIC = "xex"


def poly2block_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    coefficients = arguments["coefficients"]
    semantic = arguments["semantic"]

    if semantic == XEX_SEMANTIC:
        result = XEX_Coefficients(coefficients)
    else:
        result = GCM_Coefficients(coefficients)
    return {"block": result.b64_block}


def block2poly_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    block = arguments["block"]
    semantic = arguments["semantic"]

    if semantic == XEX_SEMANTIC:
        result = B64Block(block).xex_coefficients
    else:
        result = B64Block(block).gcm_coefficients

    return {"coefficients": result}


def gfmul_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    a = arguments["a"]
    b = arguments["b"]
    semantic = arguments["semantic"]

    a_block = B64Block(a).block
    b_block = B64Block(b).block

    if semantic == XEX_SEMANTIC:
        result = xex_gfmul(a_block, b_block)
    else:
        result = gcm_gfmul(a_block, b_block)

    return {"product": Block(result).b64_block}


def sea128_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    mode = arguments["mode"]
    key = B64Block(arguments["key"]).block
    input_data = B64Block(arguments["input"]).block

    if mode == ENCRYPT_MODE:
        result = sea_encrypt(key, input_data)
    elif mode == DECRYPT_MODE:
        result = sea_decrypt(key, input_data)
    else:
        raise ValueError(f"Unknown SEA-128 mode: {mode}")

    return {"output": Block(result).b64_block}


def xex_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    mode = arguments["mode"]
    key = B64Block(arguments["key"]).block
    tweak = B64Block(arguments["tweak"]).block
    input_data = B64Block(arguments["input"]).block

    if mode == ENCRYPT_MODE:
        result = encrypt_xex(key, tweak, input_data)
    elif mode == DECRYPT_MODE:
        result = decrypt_xex(key, tweak, input_data)
    else:
        raise ValueError(f"Unknown XEX mode: {mode}")

    return {"output": Block(result).b64_block}


def gcm_encrypt_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    algorithm = arguments["algorithm"]
    nonce = B64Block(arguments["nonce"]).block
    key = B64Block(arguments["key"]).block
    plaintext = B64Block(arguments["plaintext"]).block
    ad = B64Block(arguments["ad"]).block

    encrypt_function = aes_encrypt if algorithm == AES_128_ALGORITHM else sea_encrypt

    ciphertext, tag, L, H = gcm_encrypt(nonce, key, plaintext, ad, encrypt_function)

    return {"ciphertext": Block(ciphertext).b64_block, "tag": Block(tag).b64_block, "L": Block(L).b64_block,
            "H": Block(H).b64_block}


def gcm_decrypt_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    algorithm = arguments["algorithm"]
    nonce = B64Block(arguments["nonce"]).block
    key = B64Block(arguments["key"]).block
    ciphertext = B64Block(arguments["ciphertext"]).block
    ad = B64Block(arguments["ad"]).block
    tag = B64Block(arguments["tag"]).block

    encrypt_function = aes_encrypt if algorithm == AES_128_ALGORITHM else sea_encrypt

    plaintext, authentic = gcm_decrypt(nonce, key, ciphertext, ad, tag, encrypt_function)

    return {"plaintext": Block(plaintext).b64_block, "authentic": authentic}


def padding_oracle_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    hostname = arguments["hostname"]
    port = arguments["port"]
    iv = B64Block(arguments["iv"]).block
    ciphertext = B64Block(arguments["ciphertext"]).block

    plaintext = get_plaintext(ciphertext, iv, hostname, port)

    return {"plaintext": Block(plaintext).b64_block}


ACTION_PROCESSORS = {
    "poly2block": poly2block_action,
    "block2poly": block2poly_action,
    "gfmul": gfmul_action,
    "sea128": sea128_action,
    "xex": xex_action,
    "gcm_encrypt": gcm_encrypt_action,
    "gcm_decrypt": gcm_decrypt_action,
    "padding_oracle": padding_oracle_action
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
