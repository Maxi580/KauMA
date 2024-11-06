from block_poly.b64_block import B64Block
from block_poly.block import Block
from gfmul import gcm_gfmul


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

