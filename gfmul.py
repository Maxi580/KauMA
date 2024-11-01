from block_poly.b64_block import B64Block
from block_poly.block import Block
from block_poly.gcm_poly import GCM_Poly
from block_poly.xex_poly import XEX_Poly

FIELD_SIZE = 128
REDUCTION_POLYNOM = (1 << 128) | (1 << 7) | (1 << 2) | (1 << 1) | 1


def _gfmul(a_poly: int, b_poly: int) -> int:
    """Does bit multiplication, but reduces carry if it is bigger than the Reduction Polynom of gf128, so that
       the result can never be bigger than the Reduction Polynom."""
    if not (0 <= a_poly < (1 << FIELD_SIZE)) or not (0 <= b_poly < (1 << FIELD_SIZE)):
        raise ValueError(f"Inputs must be non-negative integers less than 2^{FIELD_SIZE}")

    result = 0

    for i in range(b_poly.bit_length()):
        if b_poly & (1 << i):
            result ^= a_poly

        if a_poly & (1 << (FIELD_SIZE - 1)):
            a_poly = (a_poly << 1) ^ REDUCTION_POLYNOM
        else:
            a_poly <<= 1

    if not (0 <= result < (1 << FIELD_SIZE)):
        raise ValueError(f"Result must be non-negative integers less than 2^{FIELD_SIZE}")

    return result


def xex_gfmul(a_block: bytes, b_block: bytes) -> bytes:
    a_poly = Block(a_block).xex_poly
    b_poly = Block(b_block).xex_poly

    result = _gfmul(a_poly, b_poly)

    return XEX_Poly(result).block


def gcm_gfmul(a_block: bytes, b_block: bytes) -> bytes:
    a_poly = Block(a_block).gcm_poly
    b_poly = Block(b_block).gcm_poly

    result = _gfmul(a_poly, b_poly)

    return GCM_Poly(result).block

