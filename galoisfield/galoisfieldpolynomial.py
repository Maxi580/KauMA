from block_poly.b64_block import B64Block
from block_poly.block import Block
from galoisfield.galoisfieldelement import GaloisFieldElement


class GaloisFieldPolynomial:
    def __init__(self, poly: list[GaloisFieldElement]):
        self._gfe_list = poly

    @classmethod
    def from_b64_gcm(cls, b64_gcm: list[str]) -> 'GaloisFieldPolynomial':
        return cls([GaloisFieldElement(B64Block(poly).gcm_poly) for poly in b64_gcm])

    def to_gfe_list(self) -> list[GaloisFieldElement]:
        return self._gfe_list

    def to_int_list_gcm(self) -> list[int]:
        return [int(gfe) for gfe in self._gfe_list]

    def to_b64_list_gcm(self) -> list[str]:
        return [Block(gfe.to_block_gcm()).b64_block for gfe in self._gfe_list]

    def _remove_leading_zero(self):
        while len(self) > 0 and int(self[-1]) == 0:
            self._gfe_list.pop()

    def __getitem__(self, index: int) -> GaloisFieldElement:
        return self._gfe_list[index]

    def __setitem__(self, index: int, value: GaloisFieldElement):
        self._gfe_list[index] = value

    def __iter__(self):
        return iter(self._gfe_list)

    def __len__(self) -> int:
        return len(self._gfe_list)

    def __xor__(self, other: 'GaloisFieldPolynomial') -> 'GaloisFieldPolynomial':
        return GaloisFieldPolynomial([x ^ y for x, y in zip(self, other)])

    def __add__(self, other: 'GaloisFieldPolynomial') -> 'GaloisFieldPolynomial':
        max_len = max(len(self), len(other))
        result = []

        for i in range(max_len):
            if i < len(self) and i < len(other):
                summed = self.to_gfe_list()[i] ^ other.to_gfe_list()[i]
            elif i < len(self):
                summed = self.to_gfe_list()[i]
            else:
                summed = other.to_gfe_list()[i]

            result.append(summed)

        return GaloisFieldPolynomial(result)

    def __mul__(self, other: 'GaloisFieldPolynomial') -> 'GaloisFieldPolynomial':
        result_len = len(self) + len(other) - 1

        result = [GaloisFieldElement(0) for _ in range(result_len)]

        for i in range(len(self)):
            for j in range(len(other)):
                prod = self.to_gfe_list()[i] * other.to_gfe_list()[j]

                result[i + j] = result[i + j] ^ prod

        return GaloisFieldPolynomial(result)

    def __pow__(self, k: int) -> 'GaloisFieldPolynomial':
        if k == 0:
            return GaloisFieldPolynomial([GaloisFieldElement(1)])

        half = self ** (k // 2)
        squared = half * half

        if k % 2 == 1:
            return squared * self
        else:
            return squared

    def __divmod__(self, b: 'GaloisFieldPolynomial'):
        q = []
        r = GaloisFieldPolynomial(self._gfe_list.copy())
        b_copy = GaloisFieldPolynomial(b._gfe_list.copy())

        b_copy._remove_leading_zero()
        r._remove_leading_zero()

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

                r[pos] = r[pos] ^ prod

            r._remove_leading_zero()

        return GaloisFieldPolynomial(q), r

    def __mod__(self, other: 'GaloisFieldPolynomial') -> 'GaloisFieldPolynomial':
        _, remainder = self.__divmod__(other)
        return remainder

    def powmod(self, k: int, m: 'GaloisFieldPolynomial') -> 'GaloisFieldPolynomial':
        result = GaloisFieldPolynomial([GaloisFieldElement(1)])

        if k == 0:
            return result

        base = self % m

        while k > 0:
            if k & 1:
                result = (result * base) % m
            k >>= 1
            if k > 0:
                base = (base * base) % m

        return result
