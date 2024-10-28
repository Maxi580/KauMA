from block_poly.base import Base
import base64
from functools import cached_property


class B64Block(Base):
    def __init__(self, b64_block: str):
        self._b64_block = b64_block

    @property
    def b64_block(self) -> str:
        return self._b64_block

    @cached_property
    def block(self) -> bytes:
        return base64.b64decode(self.b64_block)

    @cached_property
    def poly(self) -> int:
        return int.from_bytes(self.block, byteorder='little')

    @cached_property
    def coefficients(self) -> list[int]:
        return [i for i in range(self.poly.bit_length()) if self.poly & (1 << i)]
