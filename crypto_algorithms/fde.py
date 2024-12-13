from crypto_algorithms.sea128 import sea_encrypt, sea_decrypt
from block_poly.poly import Poly
from galoisfield.galoisfieldelement import GaloisFieldElement
from utils import xor_bytes


def split_key(key: bytes) -> (bytes, bytes):
    middle = len(key) // 2
    return key[:middle], key[middle:]


def encrypt_fde(key: bytes, tweak: bytes, plaintext: bytes) -> bytes:
    key1, key2 = split_key(key)

    xor = sea_encrypt(key2, tweak)
    alpha = Poly.from_xex_semantic(1 << 1).block

    ciphertext = bytearray()
    for i in range(0, len(plaintext), 16):
        plaintext_block = plaintext[i:i + 16]
        xor_plaintext_block = xor_bytes(plaintext_block, xor)
        encrypted_block = sea_encrypt(key1, xor_plaintext_block)
        xor_ciphertext_block = xor_bytes(encrypted_block, xor)
        ciphertext.extend(xor_ciphertext_block)
        xor = (GaloisFieldElement.from_block_xex(alpha) * GaloisFieldElement.from_block_xex(xor)).to_block_xex()

    return bytes(ciphertext)


def decrypt_fde(key: bytes, tweak: bytes, ciphertext: bytes) -> bytes:
    key1, key2 = split_key(key)

    xor = sea_encrypt(key2, tweak)
    alpha = Poly.from_xex_semantic(1 << 1).block

    plaintext = bytearray()
    for i in range(0, len(ciphertext), 16):
        ciphertext_block = ciphertext[i:i + 16]
        xor_ciphertext_block = xor_bytes(ciphertext_block, xor)
        decrypted_block = sea_decrypt(key1, xor_ciphertext_block)
        xor_plaintext_block = xor_bytes(decrypted_block, xor)
        plaintext.extend(xor_plaintext_block)
        xor = (GaloisFieldElement.from_block_xex(alpha) * GaloisFieldElement.from_block_xex(xor)).to_block_xex()

    return bytes(plaintext)
