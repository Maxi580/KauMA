import hashlib
import hmac
from block_poly.b64 import B64
from block_poly.block import Block


def _glasskey_prng_block(k: bytes, s: bytes, i: int) -> bytes:
    i_bytes = int.to_bytes(i, 8, byteorder='little')

    k_hash = hashlib.sha256(k).digest()
    s_hash = hashlib.sha256(s).digest()
    k_star = k_hash + s_hash

    return hmac.new(k_star, i_bytes, hashlib.sha256).digest()


def glasskey_prng(agency_key: bytes, seed: bytes, lengths: list[int]) -> list[bytes]:
    """ 1. Generate 32 Byte Block
        2. Extract request Byte length from block, increase position
        3. If original Block is exhausted generate new one
        4. Continue until every length block is satisfied"""

    results = []
    current_pos = 0
    current_block = None
    i = 0

    for length in lengths:
        output = bytearray()
        bytes_needed = length

        while bytes_needed > 0:
            if current_block is None or current_pos >= len(current_block):
                current_block = _glasskey_prng_block(agency_key, seed, i)
                current_pos = 0
                i += 1

            bytes_to_take = min(bytes_needed, len(current_block) - current_pos)
            output.extend(current_block[current_pos:current_pos + bytes_to_take])

            current_pos += bytes_to_take
            bytes_needed -= bytes_to_take

        results.append(output)

    return results
