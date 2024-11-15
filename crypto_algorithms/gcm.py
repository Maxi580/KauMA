from typing import Protocol
from galoisfield.galoisfieldelement import GaloisFieldElement
from utils import xor_bytes


class EncryptionStrategy(Protocol):
    """Interface for passed encryption functions"""

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

        result.extend(xor_bytes(encrypted_y[:len(plaintext_block)], plaintext_block))

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


def _process_blocks(X: GaloisFieldElement, data: bytes, auth_key: GaloisFieldElement) -> GaloisFieldElement:
    for i in range(0, len(data), BLOCK_SIZE):
        ad_block = GaloisFieldElement.from_block_gcm(data[i:i + BLOCK_SIZE])

        X = X ^ ad_block

        X = X * auth_key
    return X


def _get_ghash(associated_data: bytes, ciphertext: bytes, auth_key: bytes, L: bytes) -> bytes:
    X = GaloisFieldElement(0)
    auth_key = GaloisFieldElement.from_block_gcm(auth_key)
    L = GaloisFieldElement.from_block_gcm(L)

    padded_associated_data = _pad_to_block(associated_data)
    padded_ciphertext = _pad_to_block(ciphertext)

    X = _process_blocks(X, padded_associated_data, auth_key)

    X = _process_blocks(X, padded_ciphertext, auth_key)

    X = X ^ L

    return (X * auth_key).to_block_gcm()


def _get_auth_tag(j: bytes, ghash: bytes):
    return xor_bytes(j, ghash)


def _compute_gcm_auth_parameters(nonce: bytes, key: bytes, ciphertext: bytes, ad: bytes,
                                 encryption_function: EncryptionStrategy):
    auth_key = _get_auth_key(key, encryption_function)
    L = _get_l(ad, ciphertext)
    j = _get_j(key, nonce, encryption_function)
    ghash = _get_ghash(ad, ciphertext, auth_key, L)
    auth_tag = _get_auth_tag(j, ghash)

    return auth_tag, L, auth_key


def gcm_encrypt(nonce: bytes, key: bytes, plaintext: bytes, ad: bytes, encryption_function: EncryptionStrategy):
    ciphertext = _apply_key_stream(nonce, key, plaintext, encryption_function)

    auth_tag, L, auth_key = _compute_gcm_auth_parameters(nonce, key, ciphertext, ad, encryption_function)

    return ciphertext, auth_tag, L, auth_key


def gcm_decrypt(nonce: bytes, key: bytes, ciphertext: bytes, ad: bytes, provided_auth_tag: bytes,
                encryption_function: EncryptionStrategy):
    plaintext = _apply_key_stream(nonce, key, ciphertext, encryption_function)

    calculated_auth_tag, _, _ = _compute_gcm_auth_parameters(nonce, key, ciphertext, ad, encryption_function)

    authentic = calculated_auth_tag == provided_auth_tag
    return plaintext, authentic
