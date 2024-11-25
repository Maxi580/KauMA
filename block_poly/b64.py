from block_poly.base import Base
import base64
from functools import cached_property


class B64(Base):
    def __init__(self, b64: str):
        self._b64 = b64

    @property
    def b64(self) -> str:
        return self._b64

    @cached_property
    def block(self) -> bytes:
        return base64.b64decode(self.b64)

    @cached_property
    def xex_poly(self) -> int:
        return int.from_bytes(self.block, byteorder='little')

    @cached_property
    def gcm_poly(self) -> int:
        return self._gcm_bit_inverse(self.xex_poly)

    @cached_property
    def xex_coefficients(self) -> list[int]:
        return [i for i in range(self.xex_poly.bit_length()) if self.xex_poly & (1 << i)]

    @cached_property
    def gcm_coefficients(self) -> list[int]:
        return [i for i in range(self.gcm_poly.bit_length()) if self.gcm_poly & (1 << i)]
