import json
import sys
from pathlib import Path

from actions.poly2block_action import poly2block_action
from actions.block2poly_action import block2poly_action
from actions.gfmul_action import gfmul_action
from actions.sea128_action import sea128_action
from actions.fde_action import fde_action
from actions.gcm_crypto_action import gcm_encrypt_action, gcm_decrypt_action
from actions.padding_oracle_action import padding_oracle_action
from actions.gfpoly_action import (
    gfpoly_add_action,
    gfpoly_mul_action,
    gfpoly_pow_action,
    gfdiv_action,
    gfpoly_divmod_action,
    gfpoly_powmod_action,
    gfpoly_sort_action,
    gfpoly_make_monic_action,
    gfpoly_sqrt_action,
    gfpoly_diff_action,
    gfpoly_gcd_action,
    gfpoly_factor_sff_action,
    gfpoly_factor_ddf_action,
    gfpoly_factor_edf_action
)
from actions.gcm_crack_action import gcm_crack_action
from actions.glasskey_action import (
    gcm_glasskey_prng_action,
    gcm_prng_int_bits_action,
    glasskey_prng_int_min_max_action,
    glasskey_genkey_action,
    glasskey_break_action
)


ACTION_PROCESSORS = {
    "poly2block": poly2block_action,
    "block2poly": block2poly_action,
    "gfmul": gfmul_action,
    "sea128": sea128_action,
    "xex": fde_action,
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
    "glasskey_prng_int_min_max": glasskey_prng_int_min_max_action,
    "glasskey_genkey": glasskey_genkey_action,
    "glasskey_break": glasskey_break_action
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
