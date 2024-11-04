import threading
import time
import pytest
import secrets
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from paddingoracle.paddingOracle import get_plaintext
from paddingoracle.server import Server

BLOCK_SIZE = 16


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding


def pkcs7_unpad(padded_data: bytes) -> bytes:
    padding_length = padded_data[-1]
    return padded_data[:-padding_length]


def test_padding_oracle():
    port = 9999
    host = 'localhost'

    key = secrets.token_bytes(BLOCK_SIZE)
    server = Server(host, port, key)

    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()

    time.sleep(0.5)

    try:
        cntr = 0
        while cntr < 1000:
            plaintext_length = random.randint(1, 100)
            plaintext = secrets.token_bytes(plaintext_length)

            padded_plaintext = pkcs7_pad(plaintext, BLOCK_SIZE)

            iv = secrets.token_bytes(BLOCK_SIZE)

            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )

            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

            padded_result = get_plaintext(ciphertext, iv, host, port)
            plaintext_result = pkcs7_unpad(padded_result)
            assert plaintext_result == plaintext

            cntr += 1

    finally:
        server.timeout = 0
        if server_thread.is_alive():
            server_thread.join(timeout=1.0)
