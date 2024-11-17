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

    def to_b64_list_gcm(self) -> list[str]:
        return [Block(gfe.to_block_gcm()).b64_block for gfe in self._gfe_list]

    def _remove_leading_zero(self) -> 'GaloisFieldPolynomial':
        while len(self) > 1 and int(self[-1]) == 0:
            self._gfe_list.pop()
        return self

    def append(self, elements: list[GaloisFieldElement]) -> 'GaloisFieldPolynomial':
        return GaloisFieldPolynomial(list(self) + elements)

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
                return self

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

    def __mod__(self, other: 'GaloisFieldPolynomial') -> 'GaloisFieldPolynomial':
        _, remainder = self.__divmod__(other)
        return remainder
