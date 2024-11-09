from block_poly.block import Block
from block_poly.poly import Poly


class GaloisFieldElement:
    FIELD_SIZE = 128
    REDUCTION_POLYNOM = (1 << 128) | (1 << 7) | (1 << 2) | (1 << 1) | 1
    INVERSE_POWER = (1 << FIELD_SIZE) - 2

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

    def __xor__(self, other: 'GaloisFieldElement') -> 'GaloisFieldElement':
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
        factor = self
        result = GaloisFieldElement(1)

        while power > 0:
            if power & 1:
                result = factor * result
            factor = factor * factor
            power >>= 1

        return result

    def __truediv__(self, other: 'GaloisFieldElement') -> 'GaloisFieldElement':
        other_inverse = other ** self.INVERSE_POWER

        return self * other_inverse
