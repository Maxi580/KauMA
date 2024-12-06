import random


def _get_deterministic_bases(n: int) -> list[int]:
    """source: https://de.wikipedia.org/wiki/Miller-Rabin-Test"""
    base = []

    if n < 2_047:
        base = [2]
    elif n < 1_373_653:
        base = [2, 3]
    elif n < 9_080_191:
        base = [31, 73]
    elif n < 4_759_123_141:
        base = [2, 7, 61]
    elif n < 2_152_302_898_747:
        base = [2, 3, 5, 7, 11]
    elif n < 3_474_749_660_383:
        base = [2, 3, 5, 7, 11, 13]
    elif n < 341_550_071_728_321:
        base = [2, 3, 5, 7, 11, 13, 17]
    elif n < 3_825_123_056_546_413_051:
        base = [2, 3, 5, 7, 11, 13, 17, 19, 23]
    elif n < 318_665_857_834_031_151_167_461:
        base = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    elif n < 3_317_044_064_679_887_385_961_981:
        base = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41]

    return [k for k in base if k < n]


def _miller_rabin_witness(n: int, a: int) -> bool:
    """Perform single miller rabin test on n with base a"""
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    x = pow(a, s, n)
    if x == 1 or x == n - 1:
        return True

    for _ in range(r - 1):
        x = pow(x, 2, n)
        if x == n - 1:
            return True
        if x == 1:
            return False
    return False


def is_prime(num: int, k: int = 40) -> bool:
    if num <= 1:
        return False
    elif num <= 3:
        return True
    elif num % 2 == 0:
        return False

    bases = _get_deterministic_bases(num)

    if bases:
        return all(_miller_rabin_witness(num, a) for a in bases)
    # If there are no deterministic Bases defined, choose k random ones
    return all(_miller_rabin_witness(num, random.randrange(2, num - 1)) for _ in range(k))
