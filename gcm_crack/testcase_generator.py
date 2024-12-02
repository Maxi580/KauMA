import time
from typing import Dict, Tuple
import uuid
import json

from block_poly.block import Block
from crypto_algorithms.gcm import gcm_encrypt, get_eky0, get_auth_key
from crypto_algorithms.sea128 import aes_encrypt, sea_encrypt
from gcm_types import GCMMessage
from galoisfield.galoisfieldelement import GaloisFieldElement
from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial
import random
import secrets


def randomize_test_data(encryption_algorithm, reused_nonce, key):
    plaintext_len = random.randint(1, 48)
    plaintext = secrets.token_bytes(plaintext_len)
    ad_len = random.randint(1, 32)
    ad = secrets.token_bytes(ad_len)
    ciphertext, tag, _, _ = gcm_encrypt(encryption_algorithm, reused_nonce, key, plaintext, ad)

    return ciphertext, ad, tag, plaintext

def save_test_cases(input_cases: Dict, expected_outputs: Dict,
                    input_file: str = "generated_gcm_crack_input.json",
                    output_file: str = "generated_gcm_crack_output.json"):
    with open(input_file, 'w') as f:
        json.dump(input_cases, f, indent=2)

    with open(output_file, 'w') as f:
        json.dump(expected_outputs, f, indent=2)

def generate_test_case():
    reused_nonce = secrets.token_bytes(12)
    key = secrets.token_bytes(16)
    encryption_algorithm = random.choice([aes_encrypt, sea_encrypt])

    ciphertext, ad, tag, _ = randomize_test_data(encryption_algorithm, reused_nonce, key)
    m1 = GCMMessage(
        ciphertext=GaloisFieldPolynomial.from_block(ciphertext),
        associated_data=GaloisFieldPolynomial.from_block(ad),
        tag=GaloisFieldElement.from_block_gcm(tag),
        ciphertext_bytes=ciphertext,
        ad_bytes=ad
    )

    ciphertext, ad, tag, _ = randomize_test_data(encryption_algorithm, reused_nonce, key)
    m2 = GCMMessage(
        ciphertext=GaloisFieldPolynomial.from_block(ciphertext),
        associated_data=GaloisFieldPolynomial.from_block(ad),
        tag=GaloisFieldElement.from_block_gcm(tag),
        ciphertext_bytes=ciphertext,
        ad_bytes=ad
    )

    ciphertext, ad, tag, _ = randomize_test_data(encryption_algorithm, reused_nonce, key)
    m3 = GCMMessage(
        ciphertext=GaloisFieldPolynomial.from_block(ciphertext),
        associated_data=GaloisFieldPolynomial.from_block(ad),
        tag=GaloisFieldElement.from_block_gcm(tag),
        ciphertext_bytes=ciphertext,
        ad_bytes=ad
    )

    forgery_ciphertext, forgery_ad, forgery_tag, plaintext = randomize_test_data(encryption_algorithm, reused_nonce, key)
    forgery = GCMMessage(
        ciphertext=GaloisFieldPolynomial.from_block(forgery_ciphertext),
        associated_data=GaloisFieldPolynomial.from_block(forgery_ad),
        tag=None,
        ciphertext_bytes=forgery_ciphertext,
        ad_bytes=forgery_ad
    )

    test_uuid = str(uuid.uuid4())
    test_name = f"gcm-crack-{test_uuid}"

    input_case = {
        test_name: {
            "action": "gcm_crack",
            "arguments": {
                "nonce": Block(reused_nonce).b64,
                "m1": {
                "ciphertext": Block(m1.ciphertext_bytes).b64,
                "associated_data": Block(m1.ad_bytes).b64,
                "tag": m1.tag.to_b64_gcm()
                },
                "m2": {
                "ciphertext": Block(m2.ciphertext_bytes).b64,
                "associated_data": Block(m2.ad_bytes).b64,
                "tag": m2.tag.to_b64_gcm()
                },
                "m3": {
                "ciphertext": Block(m3.ciphertext_bytes).b64,
                "associated_data": Block(m3.ad_bytes).b64,
                "tag": m3.tag.to_b64_gcm()
                },
                "forgery": {
                "ciphertext": Block(forgery.ciphertext_bytes).b64,
                "associated_data": Block(forgery.ad_bytes).b64
                }
            }
        }
    }

    expected_case = {
        test_name: {
            "tag": Block(forgery_tag).b64,
            "H": get_auth_key(key, encryption_algorithm).to_b64_gcm(),
            "mask": get_eky0(key, reused_nonce, encryption_algorithm).to_b64_gcm()
        }
    }

    return input_case, expected_case


if __name__ == '__main__':
    all_input_cases = {}
    all_expected_outputs = {}

    for i in range(250):
        input_case, expected_output = generate_test_case()
        all_input_cases.update(input_case)
        all_expected_outputs.update(expected_output)

    save_test_cases(all_input_cases, all_expected_outputs)
