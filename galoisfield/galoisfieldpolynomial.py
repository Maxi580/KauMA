from block_poly.b64_block import B64Block
from block_poly.block import Block
from galoisfield.galoisfieldelement import GaloisFieldElement
from typing import Optional


class GaloisFieldPolynomial:
    def __init__(self, poly: list[GaloisFieldElement]):
        self._gfe_list = poly

    @classmethod
    def from_b64_gcm(cls, b64_gcm: list[str]) -> 'GaloisFieldPolynomial':
        return cls([GaloisFieldElement(B64Block(poly).gcm_poly) for poly in b64_gcm])

    @staticmethod
    def gcd(a: 'GaloisFieldPolynomial', b: 'GaloisFieldPolynomial') -> 'GaloisFieldPolynomial':
        while not all(int(gfe) == 0 for gfe in b):
            temp = b
            b = a % b
            a = temp

        a.make_monic()
        return a

    def to_b64_gcm(self) -> list[str]:
        return [Block(gfe.to_block_gcm()).b64_block for gfe in self._gfe_list]

    def _remove_leading_zero(self) -> 'GaloisFieldPolynomial':
        while len(self) > 1 and int(self[-1]) == 0:
            self._gfe_list.pop()
        return self

    def append(self, elements: list[GaloisFieldElement]) -> 'GaloisFieldPolynomial':
        return GaloisFieldPolynomial(list(self) + elements)

    def pop(self, index: int = -1):
        self._gfe_list.pop(index)

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
        padded_self = self.append([GaloisFieldElement(0)] * (max_len - len(self)))
        padded_other = other.append([GaloisFieldElement(0)] * (max_len - len(other)))

        return GaloisFieldPolynomial(
            [gfe_a + gfe_b for gfe_a, gfe_b in zip(padded_self, padded_other)])._remove_leading_zero()

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

    def __divmod__(self, b: 'GaloisFieldPolynomial') -> ('GaloisFieldPolynomial', 'GaloisFieldPolynomial'):
        q = []
        r = GaloisFieldPolynomial(self._gfe_list.copy())._remove_leading_zero()
        b_copy = GaloisFieldPolynomial(b._gfe_list.copy())._remove_leading_zero()

        if len(r) < len(b_copy):
            return GaloisFieldPolynomial([GaloisFieldElement(0)]), r

        while len(r) >= len(b_copy):
            r_deg = len(r) - 1
            b_deg = len(b_copy) - 1
            deg_diff = r_deg - b_deg

            quotient_coeff = r[-1] / b_copy[-1]

            # Increase Quotient
            while len(q) <= deg_diff:
                q.append(GaloisFieldElement(0))
            q[deg_diff] = quotient_coeff

            # Reduce Remainder
            for idx, gfe in enumerate(b_copy):
                pos = deg_diff + idx
                prod = quotient_coeff * gfe

                r[pos] = r[pos] + prod

            r._remove_leading_zero()
            # If remainder is 0, the len would still be 1 => endless loop
            if int(r[-1]) == 0:
                break

        return GaloisFieldPolynomial(q)._remove_leading_zero(), r

    def __truediv__(self, other):
        quotient, remainder = divmod(self, other)
        return quotient + remainder

    def __mod__(self, other: 'GaloisFieldPolynomial') -> 'GaloisFieldPolynomial':
        _, remainder = divmod(self, other)
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
        sqrt_poly = GaloisFieldPolynomial(self._gfe_list.copy())

        odd_poly_cntr = len(sqrt_poly) // 2
        for i in range(odd_poly_cntr):
            sqrt_poly[i].sqrt()
            sqrt_poly.pop(i + 1)

        sqrt_poly[-1].sqrt()
        sqrt_poly._remove_leading_zero()  # In case last gfe turns 0 on sqrt

        return sqrt_poly

    def diff(self) -> 'GaloisFieldPolynomial':
        derived_poly = GaloisFieldPolynomial(self._gfe_list.copy())

        if len(derived_poly) == 1:
            derived_poly[0] = GaloisFieldElement(0)

        else:
            derived_poly.pop(0)

            for i in range(1, len(derived_poly), 2):
                derived_poly[i] = GaloisFieldElement(0)

            derived_poly._remove_leading_zero()

        return derived_poly
