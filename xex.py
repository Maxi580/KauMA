from sea128 import sea_encrypt, sea_decrypt
from gfmul import xex_gfmul

from block_poly.xex_poly import XEX_Poly


def split_key(key: bytes) -> (bytes, bytes):
    assert len(key) % 2 != 0, "Key length must be even"

    middle = len(key) // 2
    return key[:middle], key[middle:]


def encrypt_xex(key: bytes, tweak: bytes, plaintext: bytes):
    key1, key2 = split_key(key)

    xor = sea_encrypt(key2, tweak)
    alpha = XEX_Poly(1 << 1).block

    ciphertext = bytearray()
    for i in range(0, len(plaintext), 16):
        plaintext_block = plaintext[i:i + 16]

        xor_plaintext_block = bytes(x ^ y for x, y in zip(plaintext_block, xor))

        encrypted_block = sea_encrypt(key1, xor_plaintext_block)

        xor_ciphertext_block = bytes(x ^ y for x, y in zip(encrypted_block, xor))

        ciphertext.extend(xor_ciphertext_block)

        xor = xex_gfmul(alpha, xor)

    return bytes(ciphertext)


def decrypt_xex(key: bytes, tweak: bytes, ciphertext: bytes):
    key1, key2 = split_key(key)

    xor = sea_encrypt(key2, tweak)
    alpha = XEX_Poly(1 << 1).block

    plaintext = bytearray()
    for i in range(0, len(ciphertext), 16):
        ciphertext_block = ciphertext[i:i + 16]

        xor_ciphertext_block = bytes(x ^ y for x, y in zip(ciphertext_block, xor))

        decrypted_block = sea_decrypt(key1, xor_ciphertext_block)

        xor_plaintext_block = bytes(x ^ y for x, y in zip(decrypted_block, xor))

        plaintext.extend(xor_plaintext_block)

        xor = xex_gfmul(alpha, xor)

    return bytes(plaintext)
