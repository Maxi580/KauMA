from typing import Protocol

from block_poly.b64_block import B64Block
from block_poly.block import Block
from gfmul import gcm_gfmul
from sea128 import aes_encrypt


class EncryptionStrategy(Protocol):
    def __call__(self, key: bytes, data: bytes) -> bytes:
        ...


BLOCK_SIZE = 16


def _apply_key_stream(nonce: bytes, key: bytes, xor_data: bytes, encryption_function: EncryptionStrategy) -> bytes:
    """Encrypts/ Decrypts"""
    result = bytearray()

    ctr = 2
    for i in range(0, len(xor_data), BLOCK_SIZE):
        yi = nonce[-12:] + ctr.to_bytes(4, byteorder='big')

        encrypted_y = encryption_function(key, yi)

        plaintext_block = xor_data[i:i + BLOCK_SIZE]

        result.extend(bytes(x ^ y for x, y in zip(encrypted_y[:len(plaintext_block)], plaintext_block)))

        ctr += 1

    return result


def _get_auth_key(key: bytes, encryption_function: EncryptionStrategy):
    zero_block = bytes(BLOCK_SIZE)

    return encryption_function(key, zero_block)


def _get_j(key: bytes, nonce: bytes, encryption_function: EncryptionStrategy) -> bytes:
    ctr = 1
    y0 = nonce[-12:] + ctr.to_bytes(4, byteorder='big')

    return encryption_function(key, y0)


def _get_l(ad: bytes, ciphertext: bytes):
    ad_length = len(ad) * 8
    cipher_length = len(ciphertext) * 8

    L = ad_length.to_bytes(8, byteorder='big') + cipher_length.to_bytes(8, byteorder='big')

    return L


def _pad_to_block(data: bytes) -> bytes:
    if len(data) % BLOCK_SIZE == 0:
        return data
    padding_length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes(padding_length)


def _get_ghash(associated_data: bytes, ciphertext: bytes, auth_key: bytes, L: bytes) -> bytes:
    X = bytes(BLOCK_SIZE)

    padded_associated_data = _pad_to_block(associated_data)
    padded_ciphertext = _pad_to_block(ciphertext)
    for i in range(0, len(padded_associated_data), BLOCK_SIZE):
        ad_block = padded_associated_data[i:i + BLOCK_SIZE]

        X = bytes(x ^ y for x, y in zip(X, ad_block))

        X = gcm_gfmul(X, auth_key)

    for i in range(0, len(padded_ciphertext), BLOCK_SIZE):
        ciphertext_block = padded_ciphertext[i:i + BLOCK_SIZE]

        X = bytes(x ^ y for x, y in zip(X, ciphertext_block))

        X = gcm_gfmul(X, auth_key)

    X = bytes(x ^ y for x, y in zip(X, L))

    return gcm_gfmul(X, auth_key)


def get_auth_tag(j: bytes, ghash: bytes):
    return bytes(x ^ y for x, y in zip(j, ghash))


def gcm_encrypt(nonce: bytes, key: bytes, plaintext: bytes, ad: bytes, encryption_function: EncryptionStrategy):
    ciphertext = _apply_key_stream(nonce, key, plaintext, encryption_function)

    auth_key = _get_auth_key(key, encryption_function)
    L = _get_l(ad, ciphertext)
    j = _get_j(key, nonce, encryption_function)
    ghash = _get_ghash(ad, ciphertext, auth_key, L)
    auth_tag = get_auth_tag(j, ghash)

    return ciphertext, auth_tag, L, auth_key


def gcm_decrypt(nonce: bytes, key: bytes, ciphertext: bytes, ad: bytes, tag: bytes,
                encryption_function: EncryptionStrategy):
    plaintext = _apply_key_stream(nonce, key, ciphertext, encryption_function)

    auth_key = _get_auth_key(key, encryption_function)
    L = _get_l(ad, ciphertext)
    j = _get_j(key, nonce, encryption_function)
    ghash = _get_ghash(ad, ciphertext, auth_key, L)
    calculated_auth_tag = get_auth_tag(j, ghash)
    authentic = calculated_auth_tag == tag

    return plaintext, authentic
