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
    def b64_block(self) -> str:
        return base64.b64encode(self.block).decode()

    @cached_property
    def poly(self) -> int:
        return int.from_bytes(self.block, byteorder='little')

    @cached_property
    def coefficients(self) -> list[int]:
        return [i for i in range(self.poly.bit_length()) if self.poly & (1 << i)]
