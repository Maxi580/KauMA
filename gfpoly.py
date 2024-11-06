from block_poly.b64_block import B64Block
from block_poly.block import Block
from block_poly.gcm_poly import GCM_Poly
from gfmul import gcm_gfmul

FIELD_SIZE = 128


def gfpoly_add(a: list[bytes], b: list[bytes]) -> list[bytes]:
    max_len = max(len(a), len(b))
    result = []

    for i in range(max_len):
        if i < len(a) and i < len(b):
            summed = bytes(x ^ y for x, y in zip(a[i], b[i]))
        elif i < len(a):
            summed = a[i]
        else:
            summed = b[i]

        result.append(summed)

    return result


def gfpoly_mul(a: list[bytes], b: list[bytes]) -> list[bytes]:
    result_len = len(a) + len(b) - 1
    result = [bytes(16) for _ in range(result_len)]

    for i in range(len(a)):
        for j in range(len(b)):
            prod = gcm_gfmul(a[i], b[j])

            result[i + j] = bytes(x ^ y for x, y in zip(result[i + j], prod))

    return result


def gfpoly_pow(a: list[bytes], k: int) -> list[bytes]:
    if k == 0:
        return [GCM_Poly(1).block]

    half = gfpoly_pow(a, k // 2)
    squared = gfpoly_mul(half, half)

    if k % 2 == 1:
        return gfpoly_mul(squared, a)
    else:
        return squared


def gfdiv(a: bytes, b: bytes) -> bytes:
    """Math Summary: Fermat: b^(2^128 - 1) = 1 => b * b^(2^128 - 2) = 1 => Inverse of b is b^(2^128 - 2)
       q = a/b => q * b = a => b^-1 * b * q = a * b^-1 => q = a * b^-1
       Therefore we calculate inverse of b and multiply it with a"""

    power = (1 << FIELD_SIZE) - 2

    b_inv = gfpoly_pow([b], power)

    q = gcm_gfmul(a, b_inv[0])
    return q

