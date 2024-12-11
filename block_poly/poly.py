import base64
from functools import cached_property
from typing import Optional

from constants import BLOCK_SIZE
from block_poly.base import Base


class Poly(Base):
    """Gets passed Coefficients in one semantic"""
    def __init__(self, xex_poly: Optional[int] = None, gcm_poly: Optional[int] = None):
        assert xex_poly is not None or gcm_poly is not None, "Cant create a poly if both base values are None"
        self._xex_poly: Optional[int] = xex_poly
        self._gcm_poly: Optional[int] = gcm_poly

    @classmethod
    def from_xex_semantic(cls, xex_poly: int):
        return cls(xex_poly=xex_poly)

    @classmethod
    def from_gcm_semantic(cls, gcm_poly: int):
        return cls(gcm_poly=gcm_poly)

    @property
    def gcm_poly(self) -> int:
        if self._gcm_poly is None:
            assert self._xex_poly is not None, "If one poly is not defined the other must be"
            self._gcm_poly = self.inverse_bits(self.xex_poly)
        return self._gcm_poly

    @property
    def xex_poly(self) -> int:
        if self._xex_poly is None:
            assert self._gcm_poly is not None, "If one poly is not defined the other must be"
            self._xex_poly = self.inverse_bits(self.gcm_poly)
        return self._xex_poly

    @cached_property
    def xex_coefficients(self) -> list[int]:
        return self.poly_to_coefficients(self.xex_poly)

    @cached_property
    def gcm_coefficients(self) -> list[int]:
        return self.poly_to_coefficients(self.gcm_poly)

    @cached_property
    def block(self) -> bytes:
        return self.xex_poly.to_bytes(BLOCK_SIZE, byteorder='little')

    @cached_property
    def b64(self) -> str:
        return base64.b64encode(self.block).decode()
