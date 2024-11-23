from block_poly.base import Base
import base64
from functools import cached_property


class B64(Base):
    def __init__(self, b64_block: str):
        self._b64_block = b64_block

    @property
    def b64_block(self) -> str:
        return self._b64_block

    @cached_property
    def block(self) -> bytes:
        return base64.b64decode(self.b64_block)

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
