import json
import sys
from pathlib import Path
from typing import Dict, Any

from block_poly.b64_block import B64Block
from block_poly.block import Block
from block_poly.coefficients import Coefficients
from block_poly.poly import Poly
from crypto_algorithms.sea128 import sea_encrypt, sea_decrypt, aes_encrypt
from crypto_algorithms.fde import encrypt_fde, decrypt_fde
from crypto_algorithms.gcm import gcm_encrypt, gcm_decrypt
from paddingoracle.paddingOracle import padding_oracle_attack
from galoisfield.galoisfieldelement import GaloisFieldElement
from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial
from gcm_crack.sff import sff
from gcm_crack.ddf import ddf
from gcm_crack.edf import edf
from gcm_crack.gcm_crack import gcm_crack, json_to_gcm_message

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

    result = encrypt_fde(key, tweak, input_data) if mode == ENCRYPT_MODE else decrypt_fde(key, tweak, input_data)

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
    A = GaloisFieldPolynomial.from_b64_gcm(arguments["A"])
    B = GaloisFieldPolynomial.from_b64_gcm(arguments["B"])

    S = A + B

    return {"S": S.to_b64_gcm()}


def gfpoly_mul_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    A = GaloisFieldPolynomial.from_b64_gcm(arguments["A"])
    B = GaloisFieldPolynomial.from_b64_gcm(arguments["B"])

    S = A * B

    return {"P": S.to_b64_gcm()}


def gfpoly_pow_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    k = arguments["k"]
    A = GaloisFieldPolynomial.from_b64_gcm(arguments["A"])

    Z = A ** k

    return {"Z": Z.to_b64_gcm()}


def gfdiv_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    a = B64Block(arguments["a"]).gcm_poly
    b = B64Block(arguments["b"]).gcm_poly

    q = int(GaloisFieldElement(a) / GaloisFieldElement(b))

    return {"q": Poly.from_gcm_semantic(q).b64_block}


def gfpoly_divmod_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    a = GaloisFieldPolynomial.from_b64_gcm(arguments["A"])
    b = GaloisFieldPolynomial.from_b64_gcm(arguments["B"])

    Q, R = divmod(a, b)

    return {"Q": Q.to_b64_gcm(), "R": R.to_b64_gcm()}


def gfpoly_powmod_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    A = arguments["A"]
    M = arguments["M"]
    k = arguments["k"]

    gfp_a = GaloisFieldPolynomial.from_b64_gcm(A)
    gfp_m = GaloisFieldPolynomial.from_b64_gcm(M)

    Z = pow(gfp_a, k, gfp_m)

    return {"Z": Z.to_b64_gcm()}


def gfpoly_sort_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    b64_polys = arguments["polys"]
    polys = [GaloisFieldPolynomial.from_b64_gcm(b64_poly) for b64_poly in b64_polys]

    sorted_polys = sorted(polys)

    b64_sorted_polys = [poly.to_b64_gcm() for poly in sorted_polys]

    return {"sorted_polys": b64_sorted_polys}


def gfpoly_make_monic_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    A = GaloisFieldPolynomial.from_b64_gcm(arguments["A"])

    A.make_monic()

    return {"A*": A.to_b64_gcm()}


def gfpoly_sqrt_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    Q = GaloisFieldPolynomial.from_b64_gcm(arguments["Q"])

    sqrt_Q = Q.sqrt()

    return {"S": sqrt_Q.to_b64_gcm()}


def gfpoly_diff_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    F = GaloisFieldPolynomial.from_b64_gcm(arguments["F"])

    derived_F = F.diff()

    return {"F'": derived_F.to_b64_gcm()}


def gfpoly_gcd_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    A = GaloisFieldPolynomial.from_b64_gcm(arguments["A"])
    B = GaloisFieldPolynomial.from_b64_gcm(arguments["B"])

    result = GaloisFieldPolynomial.gcd(A, B)

    return {"G": result.to_b64_gcm()}


def gfpoly_factor_sff_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    F = GaloisFieldPolynomial.from_b64_gcm(arguments["F"])

    result = sff(F)

    return {"factors": [{"factor": result[i][0].to_b64_gcm(), "exponent": result[i][1]} for i in range(len(result))]}


def gfpoly_factor_ddf_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    F = GaloisFieldPolynomial.from_b64_gcm(arguments["F"])

    result = ddf(F)

    return {"factors": [{"factor": result[i][0].to_b64_gcm(), "degree": result[i][1]} for i in range(len(result))]}


def gfpoly_factor_edf_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    F = GaloisFieldPolynomial.from_b64_gcm(arguments["F"])
    d = arguments["d"]

    result = edf(F, d)

    return {"factors": [result[i].to_b64_gcm() for i in range(len(result))]}


def gcm_crack_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    nonce = B64Block(arguments["nonce"]).block

    m1 = json_to_gcm_message(arguments["m1"])
    m2 = json_to_gcm_message(arguments["m2"])
    m3 = json_to_gcm_message(arguments["m3"])

    forgery_data = arguments["forgery"]
    forgery_ciphertext = B64Block(forgery_data["ciphertext"]).block
    forgery_ad = B64Block(forgery_data["associated_data"]).block

    result = gcm_crack(nonce, m1, m2, m3, forgery_ciphertext, forgery_ad)

    return {"WIP": result}


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
    "gfpoly_divmod": gfpoly_divmod_action,
    "gfpoly_powmod": gfpoly_powmod_action,
    "gfpoly_sort": gfpoly_sort_action,
    "gfpoly_make_monic": gfpoly_make_monic_action,
    "gfpoly_sqrt": gfpoly_sqrt_action,
    "gfpoly_diff": gfpoly_diff_action,
    "gfpoly_gcd": gfpoly_gcd_action,
    "gfpoly_factor_sff": gfpoly_factor_sff_action,
    "gfpoly_factor_ddf": gfpoly_factor_ddf_action,
    "gfpoly_factor_edf": gfpoly_factor_edf_action,
    "gcm_crack": gcm_crack_action,
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
