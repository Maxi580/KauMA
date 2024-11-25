import time
from typing import Optional, Union

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

    @property
    def degree(self) -> int:
        return len(self) - 1

    def to_b64(self) -> list[str]:
        # Uses GCM Semantic
        return [Block(gfe.to_block_gcm()).b64 for gfe in self._gfe_list]

    def _remove_leading_zero(self) -> 'GaloisFieldPolynomial':
        while len(self) > 1 and int(self[-1]) == 0:
            self._gfe_list.pop()
        return self

    def add_elements(self, elements: Union[GaloisFieldElement, list[GaloisFieldElement]]) -> 'GaloisFieldPolynomial':
        if isinstance(elements, GaloisFieldElement):
            self._gfe_list.append(elements)
        else:
            self._gfe_list.extend(elements)
        return self

    def pop(self, index: int = -1):
        self._gfe_list.pop(index)

    def copy(self) -> 'GaloisFieldPolynomial':
        return GaloisFieldPolynomial(self._gfe_list.copy())

    def __getitem__(self, index: int) -> GaloisFieldElement:
        return self._gfe_list[index]

    def __setitem__(self, index: int, value: GaloisFieldElement):
        self._gfe_list[index] = value

    def __iter__(self):
        return iter(self._gfe_list)

    def __len__(self) -> int:
        return len(self._gfe_list)

    def __add__(self, other: 'GaloisFieldPolynomial') -> 'GaloisFieldPolynomial':
        max_len = max(len(self), len(other))

        padded_self = self.copy().add_elements([GaloisFieldElement(0)] * (max_len - len(self)))
        padded_other = other.copy().add_elements([GaloisFieldElement(0)] * (max_len - len(other)))

        return GaloisFieldPolynomial(
            [gfe_a + gfe_b for gfe_a, gfe_b in zip(padded_self, padded_other)])._remove_leading_zero()

    def __sub__(self, other: 'GaloisFieldPolynomial'):
        return self + other

    def __mul__(self, other: 'GaloisFieldPolynomial') -> 'GaloisFieldPolynomial':
        result_len = len(self) + len(other) - 1

        result = [GaloisFieldElement(0) for _ in range(result_len)]

        for i in range(len(self)):
            for j in range(len(other)):
                prod = self[i] * other[j]

                result[i + j] = result[i + j] + prod

        return GaloisFieldPolynomial(result)._remove_leading_zero()

    def __pow__(self, k: int, modulo: Optional['GaloisFieldPolynomial'] = None) -> 'GaloisFieldPolynomial':
        result = GaloisFieldPolynomial([GaloisFieldElement(1)])

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

        return result._remove_leading_zero()

    def __divmod__(self, other: 'GaloisFieldPolynomial') -> ('GaloisFieldPolynomial', 'GaloisFieldPolynomial'):
        q = []
        r = self.copy()._remove_leading_zero()
        b = other.copy()._remove_leading_zero()

        if len(r) < len(b):
            return GaloisFieldPolynomial([GaloisFieldElement(0)]), r

        while len(r) >= len(b):
            deg_diff = r.degree - b.degree

            quotient_coeff = r[-1] / b[-1]

            # Increase Quotient
            while len(q) <= deg_diff:
                q.append(GaloisFieldElement(0))
            q[deg_diff] = quotient_coeff

            # Reduce Remainder
            for idx, gfe in enumerate(b):
                pos = deg_diff + idx
                prod = quotient_coeff * gfe

                r[pos] = r[pos] + prod

            r._remove_leading_zero()
            # If remainder is 0, the len would still be 1 => endless loop
            if int(r[-1]) == 0:
                break

        return GaloisFieldPolynomial(q)._remove_leading_zero(), r

    def __floordiv__(self, other):
        quotient, _ = self.__divmod__(other)
        return quotient

    def __mod__(self, other: 'GaloisFieldPolynomial') -> 'GaloisFieldPolynomial':
        _, remainder = self.__divmod__(other)
        return remainder

    def __lt__(self, other: 'GaloisFieldPolynomial') -> bool:
        if len(self) != len(other):
            return len(self) < len(other)

        for gfe_self, gfe_other in zip(reversed(self), reversed(other)):
            if gfe_self != gfe_other:
                return gfe_self < gfe_other

        return False

    def __eq__(self, other: 'GaloisFieldPolynomial') -> bool:
        if len(self) != len(other):
            return False

        for gfe_self, gfe_other in zip(reversed(self), reversed(other)):
            if gfe_self != gfe_other:
                return False

        return True

    def make_monic(self):
        for i in range(len(self) - 1):
            self[i] /= self[-1]

        self[-1] = GaloisFieldElement(1)

    def sqrt(self) -> 'GaloisFieldPolynomial':
        """Len of GFP always has to be odd since, only even GFE do not equal 0.
           => there are len(self)//2 odd gfe´s that need to be popped
           => take sqrt of even, pop the odd one behind until the last one as there is no odd behind."""
        sqrt_poly = self.copy()

        odd_poly_cntr = len(sqrt_poly) // 2
        for i in range(odd_poly_cntr):
            sqrt_poly[i].sqrt()
            sqrt_poly.pop(i + 1)

        sqrt_poly[-1].sqrt()
        sqrt_poly._remove_leading_zero()  # In case last gfe turns 0 on sqrt

        return sqrt_poly

    def diff(self) -> 'GaloisFieldPolynomial':
        derived_poly = self.copy()

        if len(derived_poly) == 1:
            derived_poly[0] = GaloisFieldElement(0)

        else:
            derived_poly.pop(0)

            for i in range(1, len(derived_poly), 2):
                derived_poly[i] = GaloisFieldElement(0)

            derived_poly._remove_leading_zero()

        return derived_poly

    def gcd(self, other: 'GaloisFieldPolynomial') -> 'GaloisFieldPolynomial':
        a = self.copy()
        b = other.copy()

        while b != GaloisFieldPolynomial([GaloisFieldElement(0)]):
            temp = b
            b = a % b
            a = temp

        a.make_monic()
        return a
