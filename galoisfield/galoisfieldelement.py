from typing import Final
from copy import copy

from block_poly.block import Block
from block_poly.poly import Poly
from galoisfield.gfmul_lib import load_library


class GaloisFieldElement:
    FIELD_SIZE: Final[int] = 128
    REDUCTION_POLYNOM: Final[int] = (1 << 128) | (1 << 7) | (1 << 2) | (1 << 1) | 1
    SQRT_POWER: Final[int] = 1 << (FIELD_SIZE - 1)

    def __init__(self, int_value: int):
        self._int_value = int_value

    @classmethod
    def from_block_xex(cls, xex_block: bytes) -> 'GaloisFieldElement':
        return cls(Block(xex_block).xex_poly)

    @classmethod
    def from_block_gcm(cls, gcm_block: bytes) -> 'GaloisFieldElement':
        return cls(Block(gcm_block).gcm_poly)

    @classmethod
    def zero(cls) -> 'GaloisFieldElement':
        return cls(0)

    @classmethod
    def one(cls) -> 'GaloisFieldElement':
        return cls(1)

    def to_block_gcm(self) -> bytes:
        return Poly.from_gcm_semantic(self._int_value).block

    def to_block_xex(self) -> bytes:
        return Poly.from_xex_semantic(self._int_value).block

    def to_b64_gcm(self) -> str:
        return Poly.from_gcm_semantic(self._int_value).b64

    def __int__(self) -> int:
        return self._int_value

    def __copy__(self) -> 'GaloisFieldElement':
        return GaloisFieldElement(self._int_value)

    def __add__(self, other: 'GaloisFieldElement') -> 'GaloisFieldElement':
        return GaloisFieldElement(self._int_value ^ other._int_value)

    def __sub__(self, other: 'GaloisFieldElement') -> 'GaloisFieldElement':
        return self + other

    def __mul__(self, other: 'GaloisFieldElement') -> 'GaloisFieldElement':
        return copy(self).__imul__(other)

    def __imul__(self, other: 'GaloisFieldElement') -> 'GaloisFieldElement':
        """ Used intel algorithm from:
            https://www.intel.com/content/dam/develop/external/us/en/documents/clmul-wp-rev-2-02-2014-04-20.pdf
            needs __m128i, which can be seen as two 64bit values (cant pass __m128i directly)
            For efficiency, we don't want to create a new instance on every mul"""
        library = load_library()  # Library is cached
        a, b = int(self), int(other)

        a_low = a & ((1 << 64) - 1)
        a_high = a >> 64
        b_low = b & ((1 << 64) - 1)
        b_high = b >> 64
        m128i_result = library.gfmul(a_low, a_high, b_low, b_high)
        result = (m128i_result.high << 64) + m128i_result.low

        assert result < (1 << 128), "Gfmul result is bigger than field size"

        self._int_value = result
        return self

    def __pow__(self, power: int) -> 'GaloisFieldElement':
        result = GaloisFieldElement(1)

        if power == 0:
            return result
        elif int(self) == 0 or int(self) == 1:
            return self

        factor = self

        while power > 0:
            if power & 1:
                result *= factor
            factor *= factor
            power >>= 1

        return result

    def __truediv__(self, other: 'GaloisFieldElement') -> 'GaloisFieldElement':
        assert int(other) != 0, "Dividing FieldElement through 0"
        _, inverse, _ = other.extended_gcd(GaloisFieldElement(self.REDUCTION_POLYNOM))

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

    def sqrt(self):
        self._int_value = int(self ** self.SQRT_POWER)

    def extended_gcd(self, other: 'GaloisFieldElement') \
            -> tuple['GaloisFieldElement', 'GaloisFieldElement', 'GaloisFieldElement']:
        if int(other) == 0:
            return self, GaloisFieldElement(1), GaloisFieldElement(0)
        gcd, x_prev, y_prev = other.extended_gcd(self % other)
        x = y_prev
        y = x_prev - (self // other) * y_prev
        return gcd, x, y
