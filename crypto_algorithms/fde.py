from typing import Callable

from crypto_algorithms.sea128 import sea_encrypt, sea_decrypt
from block_poly.poly import Poly
from galoisfield.galoisfieldelement import GaloisFieldElement
from utils import xor_bytes


def split_key(key: bytes) -> (bytes, bytes):
    middle = len(key) // 2
    return key[:middle], key[middle:]


def apply_fde(key: bytes, tweak: bytes, text: bytes, encrypt: bool) -> bytes:
    """Does fde encryption and decryption. Mode depending on encrypt boolean."""
    key1, key2 = split_key(key)

    xor = sea_encrypt(key2, tweak)
    alpha = Poly.from_xex_semantic(1 << 1).block

    result = bytearray()
    for i in range(0, len(text), 16):
        text_block = text[i:i + 16]
        xor_text_block = xor_bytes(text_block, xor)
        encrypted_block = sea_encrypt(key1, xor_text_block) if encrypt else sea_decrypt(key1, xor_text_block)
        xor_result_block = xor_bytes(encrypted_block, xor)
        result.extend(xor_result_block)
        xor = (GaloisFieldElement.from_block_xex(alpha) * GaloisFieldElement.from_block_xex(xor)).to_block_xex()

    return bytes(result)
