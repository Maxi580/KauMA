import hashlib
import hmac
import math
import random

NUMBER_OF_ROUNDS = 20


def is_prime(n: int) -> bool:
    """Performs a Miller Rabin Test"""
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(NUMBER_OF_ROUNDS):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


class Glasskey:
    def __init__(self, agency_key: bytes, seed: bytes):
        self.agency_key = agency_key
        self.seed = seed

        self.prng_position = 0
        self.prng_block = None
        self.prng_i = 0

    def _generate_new_prng_block(self, i: int) -> bytes:
        i_bytes = int.to_bytes(i, 8, byteorder='little')

        k_hash = hashlib.sha256(self.agency_key).digest()
        s_hash = hashlib.sha256(self.seed).digest()
        k_star = k_hash + s_hash

        return hmac.new(k_star, i_bytes, hashlib.sha256).digest()

    def prng(self, bytes_needed: int) -> bytes:
        """ 1. Generate 32 Byte Block
            2. Extract request Byte length from block, increase position
            3. If original Block is exhausted generate new one
            4. Continue until length bytes are provided."""
        result = bytearray()

        while bytes_needed > 0:
            if self.prng_block is None or self.prng_position >= len(self.prng_block):
                self.prng_block = self._generate_new_prng_block(self.prng_i)
                self.prng_position = 0
                self.prng_i += 1

            bytes_to_take = min(bytes_needed, len(self.prng_block) - self.prng_position)
            result.extend(self.prng_block[self.prng_position:self.prng_position + bytes_to_take])

            self.prng_position += bytes_to_take
            bytes_needed -= bytes_to_take

        return result

    def prng_int_bits(self, b: int) -> int:
        """Extracts the b lowest bits from data stream"""
        length = math.ceil(b / 8)
        s = self.prng(length)
        s_star = int.from_bytes(s, byteorder='little')
        mask = (1 << b) - 1
        return s_star & mask

    def prng_int_min_max(self, m: int, M: int) -> int:
        assert m <= M, "min is bigger than Max"
        s = M - m + 1
        assert s >= 0, "s must be positive"
        b = s.bit_length()

        while True:
            r = self.prng_int_bits(b)
            if r < s:
                return r + m

    def genkey(self, l: int):
        lp = math.floor(l / 2)
        print(f"lp: {lp}")
        p = self.prng_int_bits(lp)
        print(f"Bitlength: {p.bit_length()}")
        print(f"Before p bit set: {bin(p)}")
        p |= 1 | 3 << (lp - 2)
        print(f"After p bit set: {bin(p)}")
        while not is_prime(p):
            p += 2
        print(f"p is found {p}")

        r_power = 1 << (l - 64)
        nl = int.from_bytes(self.seed, "little") * r_power
        nh = nl + (r_power - 1)
        assert nl < nh, "nl is bigger than nh"
        print(f"nl: {nl} \nnh: {nh}")

        ql = math.floor(nl / p)
        qh = math.floor(nh / p)

        print(f"ql: {ql} \n qh: {qh}")

        print("Reached int_min_max")
        assert ql <= qh, "ql is bigger than qh"
        q = self.prng_int_min_max(ql, qh)
        print(f"Int_min_max found: {q}")
        print(f"Before q bit set: {bin(q)}")
        q |= 1
        print(f"After q bit set: {bin(q)}")

        print(f"Searching for q")
        while not is_prime(q):
            q += 2
        print(f"q found: {q}")

        print(f"returned p, q {p, q}")

        return p, q
