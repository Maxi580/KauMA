from block_poly.b64_block import B64Block
from block_poly.block import Block
from galoisfield.galoisfieldelement import GaloisFieldElement


class GaloisFieldPolynomial:
    def __init__(self, poly: list[GaloisFieldElement]):
        self._poly = poly

    @classmethod
    def from_b64_gcm(cls, b64_gcm: list[str]) -> 'GaloisFieldPolynomial':
        return cls([GaloisFieldElement(B64Block(poly).gcm_poly) for poly in b64_gcm])

    def to_gfe_list(self) -> list[GaloisFieldElement]:
        return self._poly

    def to_b64_list_gcm(self) -> list[str]:
        return [Block(gfe.to_block_gcm()).b64_block for gfe in self._poly]

    def __len__(self) -> int:
        return len(self._poly)

    def __xor__(self, other: 'GaloisFieldPolynomial') -> 'GaloisFieldPolynomial':
        return GaloisFieldPolynomial([x ^ y for x, y in zip(self.to_gfe_list(), other.to_gfe_list())])

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
