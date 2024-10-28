from block_poly.base import Base
import base64
from functools import cached_property


class Coefficients(Base):
    def __init__(self, coefficients: list[int]):
        self._coefficients: list[int] = coefficients

    def _calculate_poly(self) -> int:
        poly = 0
        for coefficient in self.coefficients:
            poly |= 1 << coefficient
        return poly

    @property
    def coefficients(self) -> list[int]:
        return self._coefficients

    @cached_property
    def poly(self) -> int:
        return self._calculate_poly()

    @cached_property
    def block(self) -> bytes:
        return self.poly.to_bytes(self.BYTE_LEN, byteorder='little')

    @cached_property
    def b64_block(self) -> str:
        return base64.b64encode(self.block).decode()
