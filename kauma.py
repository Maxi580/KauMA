import json
import sys
from pathlib import Path
from typing import Dict, Any

from block_poly.b64 import B64
from block_poly.block import Block
from block_poly.coefficients import Coefficients
from block_poly.poly import Poly
from crypto_algorithms.sea128 import sea_encrypt, sea_decrypt, aes_encrypt
from crypto_algorithms.fde import encrypt_fde, decrypt_fde
from crypto_algorithms.gcm import gcm_encrypt, gcm_decrypt
from paddingoracle.paddingOracle import padding_oracle_attack
from galoisfield.galoisfieldelement import GaloisFieldElement
from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial
from gcm_crack.recover_h import sff, ddf, edf
from gcm_crack.gcm_types import json_to_gcm_message, json_forgery_to_gcm_message
from gcm_crack.gcm_crack import gcm_crack
from rsa_backdoor.glasskey import Glasskey

ENCRYPT_MODE = "encrypt"
DECRYPT_MODE = "decrypt"
AES_128_ALGORITHM = "aes128"
XEX_SEMANTIC = "xex"


def poly2block_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    coefficients = arguments["coefficients"]
    semantic = arguments["semantic"]

    result = Coefficients.from_xex_semantic(coefficients) if semantic == XEX_SEMANTIC else (
        Coefficients.from_gcm_semantic(coefficients))

    return {"block": result.b64}


def block2poly_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    block = arguments["block"]
    semantic = arguments["semantic"]

    result = B64(block).xex_coefficients if semantic == XEX_SEMANTIC else B64(block).gcm_coefficients

    return {"coefficients": result}


def gfmul_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    a = arguments["a"]
    b = arguments["b"]
    semantic = arguments["semantic"]

    a_poly = B64(a).xex_poly if semantic == XEX_SEMANTIC else B64(a).gcm_poly
    b_poly = B64(b).xex_poly if semantic == XEX_SEMANTIC else B64(b).gcm_poly

    int_result = int(GaloisFieldElement(a_poly) * GaloisFieldElement(b_poly))
    b64_result = Poly.from_xex_semantic(int_result).b64 if semantic == XEX_SEMANTIC else (
        Poly.from_gcm_semantic(int_result).b64)

    return {"product": b64_result}


def sea128_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    mode = arguments["mode"]
    key = B64(arguments["key"]).block
    input_data = B64(arguments["input"]).block

    result = sea_encrypt(key, input_data) if mode == ENCRYPT_MODE else sea_decrypt(key, input_data)

    return {"output": Block(result).b64}


def xex_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    mode = arguments["mode"]
    key = B64(arguments["key"]).block
    tweak = B64(arguments["tweak"]).block
    input_data = B64(arguments["input"]).block

    result = encrypt_fde(key, tweak, input_data) if mode == ENCRYPT_MODE else decrypt_fde(key, tweak, input_data)

    return {"output": Block(result).b64}


def gcm_encrypt_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    algorithm = arguments["algorithm"]
    nonce = B64(arguments["nonce"]).block
    key = B64(arguments["key"]).block
    plaintext = B64(arguments["plaintext"]).block
    ad = B64(arguments["ad"]).block

    encryption_algorithm = aes_encrypt if algorithm == AES_128_ALGORITHM else sea_encrypt

    ciphertext, tag, l, auth_key = gcm_encrypt(encryption_algorithm, nonce, key, plaintext, ad)

    return {"ciphertext": Block(ciphertext).b64, "tag": Block(tag).b64, "L": Block(l).b64,
            "H": Block(auth_key).b64}


def gcm_decrypt_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    algorithm = arguments["algorithm"]
    nonce = B64(arguments["nonce"]).block
    key = B64(arguments["key"]).block
    ciphertext = B64(arguments["ciphertext"]).block
    ad = B64(arguments["ad"]).block
    tag = B64(arguments["tag"]).block

    encrypt_function = aes_encrypt if algorithm == AES_128_ALGORITHM else sea_encrypt

    authentic, plaintext = gcm_decrypt(nonce, key, ciphertext, ad, tag, encrypt_function)

    return {"authentic": authentic, "plaintext": Block(plaintext).b64}


def padding_oracle_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    hostname = arguments["hostname"]
    port = arguments["port"]
    iv = B64(arguments["iv"]).block
    ciphertext = B64(arguments["ciphertext"]).block

    plaintext = padding_oracle_attack(ciphertext, iv, hostname, port)

    return {"plaintext": Block(plaintext).b64}


def gfpoly_add_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    A = GaloisFieldPolynomial.from_b64(arguments["A"])
    B = GaloisFieldPolynomial.from_b64(arguments["B"])

    S = A + B

    return {"S": S.to_b64()}


def gfpoly_mul_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    A = GaloisFieldPolynomial.from_b64(arguments["A"])
    B = GaloisFieldPolynomial.from_b64(arguments["B"])

    S = A * B

    return {"P": S.to_b64()}


def gfpoly_pow_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    k = arguments["k"]
    A = GaloisFieldPolynomial.from_b64(arguments["A"])

    Z = A ** k

    return {"Z": Z.to_b64()}


def gfdiv_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    a = B64(arguments["a"]).gcm_poly
    b = B64(arguments["b"]).gcm_poly

    q = int(GaloisFieldElement(a) / GaloisFieldElement(b))

    return {"q": Poly.from_gcm_semantic(q).b64}


def gfpoly_divmod_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    a = GaloisFieldPolynomial.from_b64(arguments["A"])
    b = GaloisFieldPolynomial.from_b64(arguments["B"])

    Q, R = divmod(a, b)

    return {"Q": Q.to_b64(), "R": R.to_b64()}


def gfpoly_powmod_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    A = arguments["A"]
    M = arguments["M"]
    k = arguments["k"]

    gfp_a = GaloisFieldPolynomial.from_b64(A)
    gfp_m = GaloisFieldPolynomial.from_b64(M)

    Z = pow(gfp_a, k, gfp_m)

    return {"Z": Z.to_b64()}


def gfpoly_sort_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    b64_polys = arguments["polys"]
    polys = [GaloisFieldPolynomial.from_b64(b64_poly) for b64_poly in b64_polys]

    sorted_polys = sorted(polys)

    b64_sorted_polys = [poly.to_b64() for poly in sorted_polys]

    return {"sorted_polys": b64_sorted_polys}


def gfpoly_make_monic_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    A = GaloisFieldPolynomial.from_b64(arguments["A"])

    A.make_monic()

    return {"A*": A.to_b64()}


def gfpoly_sqrt_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    Q = GaloisFieldPolynomial.from_b64(arguments["Q"])

    sqrt_Q = Q.sqrt()

    return {"S": sqrt_Q.to_b64()}


def gfpoly_diff_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    F = GaloisFieldPolynomial.from_b64(arguments["F"])

    derived_F = F.diff()

    return {"F'": derived_F.to_b64()}


def gfpoly_gcd_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    A = GaloisFieldPolynomial.from_b64(arguments["A"])
    B = GaloisFieldPolynomial.from_b64(arguments["B"])

    result = A.gcd(B)

    return {"G": result.to_b64()}


def gfpoly_factor_sff_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    F = GaloisFieldPolynomial.from_b64(arguments["F"])

    result = sff(F)

    return {"factors": [{"factor": result[i][0].to_b64(), "exponent": result[i][1]} for i in range(len(result))]}


def gfpoly_factor_ddf_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    F = GaloisFieldPolynomial.from_b64(arguments["F"])

    result = ddf(F)

    return {"factors": [{"factor": result[i][0].to_b64(), "degree": result[i][1]} for i in range(len(result))]}


def gfpoly_factor_edf_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    F = GaloisFieldPolynomial.from_b64(arguments["F"])
    d = arguments["d"]

    result = edf(F, d)

    return {"factors": [result[i].to_b64() for i in range(len(result))]}


def gcm_crack_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    # nonce = B64(arguments["nonce"]).block

    m1 = json_to_gcm_message(arguments["m1"])
    m2 = json_to_gcm_message(arguments["m2"])
    m3 = json_to_gcm_message(arguments["m3"])

    forgery = json_forgery_to_gcm_message(arguments["forgery"])

    tag, H, mask = gcm_crack(m1, m2, m3, forgery)

    return {"tag": tag.to_b64_gcm(), "H": H.to_b64_gcm(), "mask": mask.to_b64_gcm()}


def gcm_glasskey_prng_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    agency_key = B64(arguments["agency_key"]).block
    seed = B64(arguments["seed"]).block
    lengths = arguments["lengths"]

    gk = Glasskey(agency_key, seed)
    blocks = [gk.prng(length) for length in lengths]
    b64_blocks = [Block(block).b64 for block in blocks]

    return {"blocks": b64_blocks}


def gcm_prng_int_bits_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    agency_key = B64(arguments["agency_key"]).block
    seed = B64(arguments["seed"]).block
    bit_lengths = arguments["bit_lengths"]

    gk = Glasskey(agency_key, seed)
    ints = [gk.prng_int_bits(bit_length) for bit_length in bit_lengths]

    return {"ints": ints}


def glasskey_prng_int_min_max_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    agency_key = B64(arguments["agency_key"]).block
    seed = B64(arguments["seed"]).block
    specification = [(pair["min"], pair["max"]) for pair in arguments["specification"]]

    gk = Glasskey(agency_key, seed)
    ints = [gk.prng_int_min_max(m, M) for [m, M] in specification]

    return {"ints": ints}


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
    "glasskey_prng": gcm_glasskey_prng_action,
    "glasskey_prng_int_bits": gcm_prng_int_bits_action,
    "glasskey_prng_int_min_max": glasskey_prng_int_min_max_action
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
