from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets
import random
import uuid
from typing import Dict, Tuple
import json
from block_poly.block import Block


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding


def generate_test_case():
    plaintext_len = random.randint(1, 70)
    plaintext = pkcs7_pad(secrets.token_bytes(plaintext_len))

    key = b'\xeeH\xe0\xf4\xd0c\xeb\xd8\xb87\x16\xd3\t\xfe\x87\xce'
    iv = secrets.token_bytes(16)

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    test_uuid = str(uuid.uuid4())
    test_name = f"padding-oracle-{test_uuid}"

    input_case = {
        test_name: {
            "action": "padding_oracle",
            "arguments": {
                "hostname": "localhost",
                "port": 9999,
                "iv": Block(iv).b64,
                "ciphertext": Block(ciphertext).b64
            }
        }
    }

    expected_output = {
        test_name: {
            "plaintext": Block(plaintext).b64
        }
    }

    return input_case, expected_output


def save_test_cases(input_cases: Dict, expected_outputs: Dict,
                    input_file: str = "generated_padding_oracle_input.json",
                    output_file: str = "generated_padding_oracle_output.json"):
    with open(input_file, 'w') as f:
        json.dump(input_cases, f, indent=2)

    with open(output_file, 'w') as f:
        json.dump(expected_outputs, f, indent=2)


if __name__ == '__main__':

    all_input_cases = {}
    all_expected_outputs = {}

    for i in range(100):
        input_case, expected_output = generate_test_case()
        all_input_cases.update(input_case)
        all_expected_outputs.update(expected_output)

    save_test_cases(all_input_cases, all_expected_outputs)