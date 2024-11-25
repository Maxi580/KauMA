import base64
from functools import cached_property

from constants import BLOCK_SIZE
from block_poly.base import Base


class Coefficients(Base):
    def __init__(self, xex_coefficients: list[int], gcm_coefficients: list[int]):
        self._gcm_coefficients: list[int] = gcm_coefficients
        self._xex_coefficients: list[int] = xex_coefficients

    @classmethod
    def from_xex_semantic(cls, coefficients: list[int]):
        return cls(coefficients, cls._gcm_coefficient_inverse(coefficients))

    @classmethod
    def from_gcm_semantic(cls, coefficients: list[int]):
        return cls(cls._gcm_coefficient_inverse(coefficients), coefficients)

    @property
    def gcm_coefficients(self) -> list[int]:
        return self._gcm_coefficients

    @property
    def xex_coefficients(self) -> list[int]:
        return self._xex_coefficients

    @cached_property
    def xex_poly(self) -> int:
        return self._calculate_poly_from_coefficients(self.xex_coefficients)

    @cached_property
    def gcm_poly(self) -> int:
        return self._calculate_poly_from_coefficients(self.gcm_coefficients)

    @cached_property
    def block(self) -> bytes:
        return self.xex_poly.to_bytes(BLOCK_SIZE, byteorder='little')

    @cached_property
    def b64(self) -> str:
        return base64.b64encode(self.block).decode()
