import base64
from functools import cached_property
from typing import Optional

from constants import BLOCK_SIZE
from block_poly.base import Base


class Coefficients(Base):
    """Gets passed Coefficients in one semantic"""
    def __init__(self, xex_coefficients: Optional[list[int]] = None, gcm_coefficients: Optional[list[int]] = None):
        assert xex_coefficients is not None or gcm_coefficients is not None, \
            "Cant create a Coefficients if both base values are None"
        self._gcm_coefficients: list[int] = gcm_coefficients
        self._xex_coefficients: list[int] = xex_coefficients

    @classmethod
    def from_xex_semantic(cls, coefficients: list[int]) -> 'Coefficients':
        return cls(xex_coefficients=coefficients)

    @classmethod
    def from_gcm_semantic(cls, coefficients: list[int]) -> 'Coefficients':
        return cls(gcm_coefficients=coefficients)

    @property
    def gcm_coefficients(self) -> list[int]:
        if self._gcm_coefficients is None:
            assert self._xex_coefficients is not None, "If one coefficients is not defined the other must be"
            return self.inverse_coefficients(self._xex_coefficients)
        return self._gcm_coefficients

    @property
    def xex_coefficients(self) -> list[int]:
        if self._xex_coefficients is None:
            assert self._gcm_coefficients is not None, "If one coefficients is not defined the other must be"
            return self.inverse_coefficients(self._gcm_coefficients)
        return self._xex_coefficients

    @cached_property
    def xex_poly(self) -> int:
        return self.coefficients_to_poly(self.xex_coefficients)

    @cached_property
    def gcm_poly(self) -> int:
        return self.coefficients_to_poly(self.gcm_coefficients)

    @cached_property
    def block(self) -> bytes:
        return self.xex_poly.to_bytes(BLOCK_SIZE, byteorder='little')

    @cached_property
    def b64(self) -> str:
        return base64.b64encode(self.block).decode()
