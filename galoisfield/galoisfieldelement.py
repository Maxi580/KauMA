from block_poly.block import Block
from block_poly.poly import Poly


class GaloisFieldElement:
    FIELD_SIZE = 128
    REDUCTION_POLYNOM = (1 << 128) | (1 << 7) | (1 << 2) | (1 << 1) | 1
    INVERSE_POWER = (1 << FIELD_SIZE) - 2
    SQRT_POWER = 1 << FIELD_SIZE

    def __init__(self, int_value: int):
        self._int_value = int_value

    @classmethod
    def from_block_xex(cls, xex_block: bytes):
        return cls(Block(xex_block).xex_poly)

    @classmethod
    def from_block_gcm(cls, gcm_block: bytes):
        return cls(Block(gcm_block).gcm_poly)

    def to_block_gcm(self) -> bytes:
        return Poly.from_gcm_semantic(self._int_value).block

    def to_block_xex(self) -> bytes:
        return Poly.from_xex_semantic(self._int_value).block

    def __int__(self) -> int:
        return self._int_value

    def __add__(self, other: 'GaloisFieldElement') -> 'GaloisFieldElement':
        return GaloisFieldElement(self._int_value ^ other._int_value)

    def __mul__(self, other: 'GaloisFieldElement') -> 'GaloisFieldElement':
        a_poly = int(self)
        b_poly = int(other)

        assert (0 <= a_poly < (1 << self.FIELD_SIZE)) or not (0 <= b_poly < (1 << self.FIELD_SIZE)), \
            "Inputs must be non-negative integers less than 2^{FIELD_SIZE}"

        result = 0

        for i in range(b_poly.bit_length()):
            if b_poly & (1 << i):
                result ^= a_poly

            if a_poly & (1 << (self.FIELD_SIZE - 1)):
                a_poly = (a_poly << 1) ^ self.REDUCTION_POLYNOM
            else:
                a_poly <<= 1

        assert (0 <= result < (1 << self.FIELD_SIZE)), "Result must be non-negative integers less than 2^{FIELD_SIZE}"

        return GaloisFieldElement(result)

    def __pow__(self, power: int) -> 'GaloisFieldElement':
        result = GaloisFieldElement(1)

        if power == 0:
            return result
        elif int(self) == 0 or int(self) == 1:
            return self

        factor = self

        while power > 0:
            if power & 1:
                result = factor * result
            factor = factor * factor
            power >>= 1

        return result

    def extended_gcd(self, a: int) -> int:
        """We are starting from a * g1 + REDUCTION_POLYNOM * g2 = u
           1. We always swap u and v so that u is the bigger value, just like in gcd
              (# gcd(54, 888) => 54 = 0 * 888 + 54 => 888 = 54 * ...)
           2. then we divide e.g. in the first step REDUCTION_POLY (u) / a (v),
              u gets set to the remainder of the division, hence we increase the coefficient of a:
               REDUCTION_POLYNOM * 1 + a * 0 = REDUCTION_POLYNOM
               REDUCTION_POLYNOM = a * (shift_factor) + remainder
               remainder = REDUCTION_POLYNOM - a * (shift_factor)
               REDUCTION_POLYNOM * 1 + a * (shift_factor) = remainder

           3. Then we swap and repeat again until u is 1 and we have found the inverse
              (Note that just like in gcd we are continuing calculations with the remainders, which however preserve
               the relationship: 888 = 54(16) + 24 => 54 = 24(2) + 6 .... 6 = 54 - 23 * 2 .....).
               or remainder = REDUCTION_POLYNOM - a * (shift_factor)"""

        u = a
        v = self.REDUCTION_POLYNOM

        g1 = 1
        g2 = 0

        while u != 1:
            # Division Step
            while u.bit_length() >= v.bit_length():
                j = u.bit_length() - v.bit_length()

                u ^= (v << j)  # Essentially this is euclid, u becomes the remainder of the division
                g1 ^= (g2 << j)  # Keep track of coefficients/ formula, for inverse calculation

            if u == 1:  # achieved: a * g1 + REDUCTION_POLYNOM * g2 = 1
                break

            # Rotate numbers just like in gcd
            if v.bit_length() > u.bit_length():
                u, v = v, u
                g1, g2 = g2, g1

        return g1

    def __truediv__(self, other: 'GaloisFieldElement') -> 'GaloisFieldElement':
        inverse = self.extended_gcd(int(other))

        return self * GaloisFieldElement(inverse)

    def sqrt(self) -> 'GaloisFieldElement':
        return self ** self.SQRT_POWER
