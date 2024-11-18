from block_poly.block import Block
from block_poly.poly import Poly


def extended_gcd(a: 'GaloisFieldElement', b: 'GaloisFieldElement'):
    if int(b) == 0:
        return a, GaloisFieldElement(1), GaloisFieldElement(0)
    gcd, x_prev, y_prev = extended_gcd(b, a % b)
    x = y_prev
    y = x_prev + (a // b) * y_prev  # Subtraction is same as addition in GF2^n
    return gcd, x, y


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

        result = 0

        for i in range(b_poly.bit_length()):
            if b_poly & (1 << i):
                result ^= a_poly

            if a_poly & (1 << (self.FIELD_SIZE - 1)):
                a_poly = (a_poly << 1) ^ self.REDUCTION_POLYNOM
            else:
                a_poly <<= 1

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

    def __truediv__(self, other: 'GaloisFieldElement') -> 'GaloisFieldElement':
        _, inverse, _ = extended_gcd(other, GaloisFieldElement(self.REDUCTION_POLYNOM))

        return self * inverse

    def __divmod__(self, other: 'GaloisFieldElement') -> tuple['GaloisFieldElement', 'GaloisFieldElement']:
        dividend = int(self)
        divisor = int(other)

        quotient = 0
        remainder = dividend

        while remainder.bit_length() >= divisor.bit_length():
            degree_diff = remainder.bit_length() - divisor.bit_length()

            quotient ^= (1 << degree_diff)

            remainder ^= (divisor << degree_diff)

        return GaloisFieldElement(quotient), GaloisFieldElement(remainder)

    def __floordiv__(self, other: 'GaloisFieldElement') -> 'GaloisFieldElement':
        quotient, _ = divmod(self, other)
        return quotient

    def __mod__(self, other: 'GaloisFieldElement') -> 'GaloisFieldElement':
        _, remainder = divmod(self, other)
        return remainder

    def __lt__(self, other: 'GaloisFieldElement') -> bool:
        return int(self) < int(other)

    def __eq__(self, other: 'GaloisFieldElement') -> bool:
        return int(self) == int(other)

