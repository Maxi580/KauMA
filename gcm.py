from typing import Protocol

from block_poly.b64_block import B64Block
from block_poly.block import Block
from gfmul import gcm_gfmul
from sea128 import aes_encrypt


class EncryptionStrategy(Protocol):
    def __call__(self, key: bytes, data: bytes) -> bytes:
        ...


BLOCK_SIZE = 16


def apply_key_stream(nonce: bytes, key: bytes, plaintext: bytes, encryption_function: EncryptionStrategy) -> bytes:
    ciphertext = bytearray()

    ctr = 2
    for i in range(0, len(plaintext), BLOCK_SIZE):
        yi = nonce + ctr.to_bytes(4, byteorder='big')

        encrypted_y = encryption_function(key, yi)

        plaintext_block = plaintext[i:i + BLOCK_SIZE]

        ciphertext.extend(bytes(x ^ y for x, y in zip(encrypted_y, plaintext_block)))

        ctr += 1

    return ciphertext


def get_auth_key(key: bytes, encryption_function: EncryptionStrategy):
    zero_block = bytes(BLOCK_SIZE)

    return encryption_function(key, zero_block)


def get_j(key: bytes, nonce: bytes, encryption_function: EncryptionStrategy) -> bytes:
    ctr = 1
    y0 = nonce + ctr.to_bytes(4, byteorder='big')

    return encryption_function(key, y0)


def get_l(ad: bytes, ciphertext: bytes):
    ad_length = len(ad) * 8
    cipher_length = len(ciphertext) * 8

    L = ad_length.to_bytes(8, byteorder='big') + cipher_length.to_bytes(8, byteorder='big')

    return L


def get_ghash(associated_data: bytes, ciphertext: bytes, auth_key: bytes, L: bytes) -> bytes:
    X = bytes(BLOCK_SIZE)

    for i in range(0, len(associated_data), BLOCK_SIZE):
        ad_block = associated_data[i:i + BLOCK_SIZE]

        X = bytes(x ^ y for x, y in zip(X, ad_block))

        X = gcm_gfmul(X, auth_key)

    for i in range(0, len(ciphertext), BLOCK_SIZE):
        ciphertext_block = ciphertext[i:i + BLOCK_SIZE]

        X = bytes(x ^ y for x, y in zip(X, ciphertext_block))

        X = gcm_gfmul(X, auth_key)

    X = bytes(x ^ y for x, y in zip(X, L))

    return gcm_gfmul(X, auth_key)


def get_auth_tag(j: bytes, ghash: bytes):
    return bytes(x ^ y for x, y in zip(j, ghash))


def gcm_encrypt(nonce: bytes, key: bytes, plaintext: bytes, ad: bytes, encryption_function: EncryptionStrategy):
    ciphertext = apply_key_stream(nonce, key, plaintext, encryption_function)

    auth_key = get_auth_key(key, encryption_function)
    L = get_l(ad, ciphertext)
    j = get_j(key, nonce, encryption_function)
    ghash = get_ghash(ad, ciphertext, auth_key, L)
    auth_tag = get_auth_tag(j, ghash)

    return ciphertext, auth_tag, L, auth_key


def gcm_decrypt(nonce: bytes, key: bytes, ciphertext: bytes, ad: bytes, tag: bytes,
                encryption_function: EncryptionStrategy):
    plaintext = apply_key_stream(nonce, key, ciphertext, encryption_function)


    auth_key = get_auth_key(key, encryption_function)
    L = get_l(ad, ciphertext)
    j = get_j(key, nonce, encryption_function)
    ghash = get_ghash(ad, ciphertext, auth_key, L)
    calculated_auth_tag = get_auth_tag(j, ghash)
    authentic = calculated_auth_tag == tag

    return plaintext, authentic
