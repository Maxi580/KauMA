from block_poly.base import Base
import base64
from functools import cached_property


class Poly(Base):
    def __init__(self, xex_poly: int, gcm_poly: int):
        self._xex_poly: int = xex_poly
        self._gcm_poly: int = gcm_poly

    @classmethod
    def from_xex_semantic(cls, xex_poly: int):
        return cls(xex_poly, cls._gcm_bit_inverse(xex_poly))

    @classmethod
    def from_gcm_semantic(cls, gcm_poly: int):
        return cls(cls._gcm_bit_inverse(gcm_poly), gcm_poly)

    @property
    def gcm_poly(self) -> int:
        return self._gcm_poly

    @property
    def xex_poly(self) -> int:
        return self._xex_poly

    @cached_property
    def xex_coefficients(self) -> list[int]:
        return [i for i in range(self.xex_poly.bit_length()) if self.xex_poly & (1 << i)]

    @cached_property
    def gcm_coefficients(self) -> list[int]:
        return [i for i in range(self.gcm_poly.bit_length()) if self.gcm_poly & (1 << i)]

    @cached_property
    def block(self) -> bytes:
        return self.xex_poly.to_bytes(self.BYTE_LEN, byteorder='little')

    @cached_property
    def b64_block(self) -> str:
        return base64.b64encode(self.block).decode()
