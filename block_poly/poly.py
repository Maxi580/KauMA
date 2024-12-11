import base64
from functools import cached_property
from typing import Optional

from constants import BLOCK_SIZE
from block_poly.base import Base


class Poly(Base):
    """Gets passed Coefficients in one semantic.Calculating every derived value if needed,
       not using cached_properties for efficiency"""
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
            self._gcm_poly = self._bit_inverse(self.xex_poly)
        return self._gcm_poly

    @property
    def xex_poly(self) -> int:
        if self._xex_poly is None:
            assert self._gcm_poly is not None, "If one poly is not defined the other must be"
            self._xex_poly = self._bit_inverse(self.gcm_poly)
        return self._xex_poly

    @property
    def xex_coefficients(self) -> list[int]:
        return [i for i in range(self.xex_poly.bit_length()) if self.xex_poly & (1 << i)]

    @property
    def gcm_coefficients(self) -> list[int]:
        return [i for i in range(self.gcm_poly.bit_length()) if self.gcm_poly & (1 << i)]

    @property
    def block(self) -> bytes:
        return self.xex_poly.to_bytes(BLOCK_SIZE, byteorder='little')

    @property
    def b64(self) -> str:
        return base64.b64encode(self.block).decode()
