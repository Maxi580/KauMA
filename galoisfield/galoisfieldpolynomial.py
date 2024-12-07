from typing import Optional, Union
from copy import copy

from block_poly.b64 import B64
from block_poly.block import Block
from constants import BLOCK_SIZE
from galoisfield.galoisfieldelement import GaloisFieldElement


class GaloisFieldPolynomial:
    def __init__(self, poly: list[GaloisFieldElement]):
        self._gfe_list = poly

    @classmethod
    def from_b64(cls, b64_list: list[str]) -> 'GaloisFieldPolynomial':
        return cls([GaloisFieldElement(B64(poly).gcm_poly) for poly in b64_list])

    @classmethod
    def from_block(cls, block: bytes) -> 'GaloisFieldPolynomial':
        """Splits the bytes into 16 Byte/ Block Size blocks and turns each of them into a gfe and then all into gfp"""

        return cls([GaloisFieldElement.from_block_gcm(block[i: i + BLOCK_SIZE])
                    for i in range(0, len(block), BLOCK_SIZE)])

    @classmethod
    def one(cls):
        return cls([GaloisFieldElement.one()])

    @classmethod
    def x(cls):
        return cls([GaloisFieldElement.zero(), GaloisFieldElement.one()])

    @property
    def degree(self) -> int:
        return len(self) - 1

    def to_b64(self) -> list[str]:
        # Uses GCM Semantic
        return [Block(gfe.to_block_gcm()).b64 for gfe in self._gfe_list]

    def remove_leading_zero(self) -> 'GaloisFieldPolynomial':
        while len(self) > 1 and int(self[-1]) == 0:
            self._gfe_list.pop()
        return self

    def add_elements(self, elements: Union[GaloisFieldElement, list[GaloisFieldElement]]) -> 'GaloisFieldPolynomial':
        if type(elements) is GaloisFieldElement:
            self._gfe_list.append(elements)
        else:
            self._gfe_list.extend(elements)
        return self

    def pop(self, index: int = -1):
        self._gfe_list.pop(index)

    def is_zero(self) -> bool:
        return all(int(self[i]) == 0 for i in range(len(self)))

    def __getitem__(self, index: int) -> GaloisFieldElement:
        return self._gfe_list[index]

    def __setitem__(self, index: int, value: GaloisFieldElement):
        self._gfe_list[index] = value

    def __iter__(self):
        return iter(self._gfe_list)

    def __len__(self) -> int:
        return len(self._gfe_list)

    def __copy__(self) -> 'GaloisFieldPolynomial':
        return GaloisFieldPolynomial(self._gfe_list.copy())

    def __add__(self, other: 'GaloisFieldPolynomial') -> 'GaloisFieldPolynomial':
        max_len = max(len(self), len(other))

        padded_self = copy(self).add_elements([GaloisFieldElement.zero()] * (max_len - len(self)))
        padded_other = copy(other).add_elements([GaloisFieldElement.zero()] * (max_len - len(other)))

        return GaloisFieldPolynomial(
            [gfe_a + gfe_b for gfe_a, gfe_b in zip(padded_self, padded_other)]).remove_leading_zero()

    def __sub__(self, other: 'GaloisFieldPolynomial'):
        return self + other

    def __mul__(self, other: 'GaloisFieldPolynomial') -> 'GaloisFieldPolynomial':
        result_len = len(self) + len(other) - 1

        result = [GaloisFieldElement.zero() for _ in range(result_len)]

        for i in range(len(self)):
            for j in range(len(other)):
                prod = self[i] * other[j]

                result[i + j] = result[i + j] + prod

        return GaloisFieldPolynomial(result).remove_leading_zero()

    def __pow__(self, k: int, modulo: Optional['GaloisFieldPolynomial'] = None) -> 'GaloisFieldPolynomial':
        result = GaloisFieldPolynomial([GaloisFieldElement.one()])

        if k == 0:
            return result
        elif len(self) == 1:
            if int(self[0]) == 0 or int(self[0]) == 1:
                return self % modulo if modulo else self

        base = self % modulo if modulo else self

        while k > 0:
            if k & 1:
                result = (result * base) % modulo if modulo else result * base
            k >>= 1
            if k > 0:
                base = (base * base) % modulo if modulo else base * base

        return result.remove_leading_zero()

    def __divmod__(self, other: 'GaloisFieldPolynomial') -> ('GaloisFieldPolynomial', 'GaloisFieldPolynomial'):
        assert not other.is_zero(), "Dividing FieldPoly through 0"

        q = []

        r = copy(self).remove_leading_zero()
        b = copy(other).remove_leading_zero()

        if r.degree < b.degree:
            return GaloisFieldPolynomial([GaloisFieldElement.zero()]), r

        while r.degree >= b.degree:
            deg_diff = r.degree - b.degree

            quotient_coeff = r[-1] / b[-1]

            # Increase Quotient
            while len(q) <= deg_diff:
                q.append(GaloisFieldElement.zero())
            q[deg_diff] = quotient_coeff

            # Reduce Remainder
            for idx, gfe in enumerate(b):
                pos = deg_diff + idx
                prod = quotient_coeff * gfe

                r[pos] = r[pos] + prod

            r.remove_leading_zero()
            # If remainder is 0, the len would still be 1 => endless loop
            if int(r[-1]) == 0:
                break

        return GaloisFieldPolynomial(q).remove_leading_zero(), r

    def __floordiv__(self, other):
        quotient, _ = divmod(self, other)
        return quotient

    def __mod__(self, other: 'GaloisFieldPolynomial') -> 'GaloisFieldPolynomial':
        _, remainder = divmod(self, other)
        return remainder

    def __lt__(self, other: 'GaloisFieldPolynomial') -> bool:
        if self.degree != other.degree:
            return self.degree < other.degree

        for gfe_self, gfe_other in zip(reversed(self), reversed(other)):
            if gfe_self != gfe_other:
                return gfe_self < gfe_other

        return False

    def __eq__(self, other: 'GaloisFieldPolynomial') -> bool:
        if self.degree != other.degree:
            return False

        for gfe_self, gfe_other in zip(reversed(self), reversed(other)):
            if gfe_self != gfe_other:
                return False

        return True

    def make_monic(self):
        for i in range(len(self) - 1):
            self[i] /= self[-1]

        self[-1] = GaloisFieldElement.one()
        return self

    def sqrt(self) -> 'GaloisFieldPolynomial':
        """Len of GFP always has to be odd since, only even GFE do not equal 0.
           => there are len(self)//2 odd gfe´s that need to be popped
           => take sqrt of even, pop the odd one behind until the last one as there is no odd behind."""
        sqrt_poly = copy(self)

        odd_poly_cntr = len(sqrt_poly) // 2
        for i in range(odd_poly_cntr):
            sqrt_poly[i].sqrt()
            sqrt_poly.pop(i + 1)

        sqrt_poly[-1].sqrt()
        sqrt_poly.remove_leading_zero()  # In case last gfe turns 0 on sqrt

        return sqrt_poly

    def diff(self) -> 'GaloisFieldPolynomial':
        derived_poly = copy(self)

        if len(derived_poly) == 1:
            derived_poly[0] = GaloisFieldElement.zero()

        else:
            derived_poly.pop(0)

            for i in range(1, len(derived_poly), 2):
                derived_poly[i] = GaloisFieldElement.zero()

            derived_poly.remove_leading_zero()

        return derived_poly

    def gcd(self, other: 'GaloisFieldPolynomial') -> 'GaloisFieldPolynomial':
        a = copy(self).remove_leading_zero()
        b = copy(other).remove_leading_zero()

        if a.is_zero():
            return b.make_monic()

        if b.is_zero():
            return a.make_monic()

        while not b.is_zero():
            temp = a % b
            a = b
            b = temp

        return a.make_monic()
