import json
import sys
from pathlib import Path
from typing import Dict, Any

from block_poly.b64_block import B64Block
from block_poly.block import Block
from block_poly.coefficients import Coefficients
from block_poly.poly import Poly

from galoisfield.galoisfieldelement import GaloisFieldElement
from crypto_algorithms.sea128 import sea_encrypt, sea_decrypt, aes_encrypt
from crypto_algorithms.xex import encrypt_xex, decrypt_xex
from crypto_algorithms.gcm import gcm_encrypt, gcm_decrypt
from galoisfield.galoisfieldpoly import GaloisFieldPolynomial
from paddingoracle.paddingOracle import padding_oracle_attack

ENCRYPT_MODE = "encrypt"
DECRYPT_MODE = "decrypt"
AES_128_ALGORITHM = "aes128"
XEX_SEMANTIC = "xex"


def poly2block_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    coefficients = arguments["coefficients"]
    semantic = arguments["semantic"]

    result = Coefficients.from_xex_semantic(coefficients) if semantic == XEX_SEMANTIC else (
        Coefficients.from_gcm_semantic(coefficients))

    return {"block": result.b64_block}


def block2poly_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    block = arguments["block"]
    semantic = arguments["semantic"]

    result = B64Block(block).xex_coefficients if semantic == XEX_SEMANTIC else B64Block(block).gcm_coefficients

    return {"coefficients": result}


def gfmul_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    a = arguments["a"]
    b = arguments["b"]
    semantic = arguments["semantic"]

    a_poly = B64Block(a).xex_poly if semantic == XEX_SEMANTIC else B64Block(a).gcm_poly
    b_poly = B64Block(b).xex_poly if semantic == XEX_SEMANTIC else B64Block(b).gcm_poly

    int_result = int(GaloisFieldElement(a_poly) * GaloisFieldElement(b_poly))
    b64_result = Poly.from_xex_semantic(int_result).b64_block if semantic == XEX_SEMANTIC else (
        Poly.from_gcm_semantic(int_result).b64_block)

    return {"product": b64_result}


def sea128_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    mode = arguments["mode"]
    key = B64Block(arguments["key"]).block
    input_data = B64Block(arguments["input"]).block

    result = sea_encrypt(key, input_data) if mode == ENCRYPT_MODE else sea_decrypt(key, input_data)

    return {"output": Block(result).b64_block}


def xex_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    mode = arguments["mode"]
    key = B64Block(arguments["key"]).block
    tweak = B64Block(arguments["tweak"]).block
    input_data = B64Block(arguments["input"]).block

    result = encrypt_xex(key, tweak, input_data) if mode == ENCRYPT_MODE else decrypt_xex(key, tweak, input_data)

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

    plaintext = padding_oracle_attack(ciphertext, iv, hostname, port)

    return {"plaintext": Block(plaintext).b64_block}


def gfpoly_add_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    A = arguments["A"]
    B = arguments["B"]

    gfp_a = GaloisFieldPolynomial.from_b64_gcm(A)
    gfp_b = GaloisFieldPolynomial.from_b64_gcm(B)

    S = gfp_a + gfp_b

    return {"S": S.to_b64_list_gcm()}


def gfpoly_mul_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    A = arguments["A"]
    B = arguments["B"]

    gfp_a = GaloisFieldPolynomial.from_b64_gcm(A)
    gfp_b = GaloisFieldPolynomial.from_b64_gcm(B)

    S = gfp_a * gfp_b

    return {"P": S.to_b64_list_gcm()}


def gfpoly_pow_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    A = arguments["A"]
    k = arguments["k"]

    gfp_a = GaloisFieldPolynomial.from_b64_gcm(A)

    Z = gfp_a ** k

    return {"Z": Z.to_b64_list_gcm()}


def gfdiv_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    a = B64Block(arguments["a"]).gcm_poly
    b = B64Block(arguments["b"]).gcm_poly

    q = int(GaloisFieldElement(a) / GaloisFieldElement(b))

    return {"q": Poly.from_gcm_semantic(q).b64_block}


ACTION_PROCESSORS = {
    "poly2block": poly2block_action,
    "block2poly": block2poly_action,
    "gfmul": gfmul_action,
    "sea128": sea128_action,
    "xex": xex_action,
    "gcm_encrypt": gcm_encrypt_action,
    "gcm_decrypt": gcm_decrypt_action,
    "padding_oracle": padding_oracle_action,
    "gfpoly_add": gfpoly_add_action,
    "gfpoly_mul": gfpoly_mul_action,
    "gfpoly_pow": gfpoly_pow_action,
    "gfdiv": gfdiv_action,
}


def process_testcases(input_json):
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
