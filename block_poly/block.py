from block_poly.base import Base
import base64
from functools import cached_property


class Block(Base):
    def __init__(self, block: bytes):
        self._block: bytes = block

    @property
    def block(self) -> bytes:
        return self._block

    @cached_property
    def b64(self) -> str:
        return base64.b64encode(self.block).decode()

    @cached_property
    def xex_poly(self) -> int:
        return int.from_bytes(self.block, byteorder='little')

    @cached_property
    def gcm_poly(self) -> int:
        return self.inverse_bits(self.xex_poly)

    @cached_property
    def xex_coefficients(self) -> list[int]:
        return self.poly_to_coefficients(self.xex_poly)

    @cached_property
    def gcm_coefficients(self) -> list[int]:
        return self.poly_to_coefficients(self.gcm_poly)
