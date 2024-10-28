from block_poly.base import Base
import base64
from functools import cached_property


class Poly(Base):
    """Takes in a Poly and calculates every derived property"""

    def __init__(self, poly: int):
        self._poly: int = poly

    @property
    def poly(self) -> int:
        return self._poly

    @cached_property
    def coefficients(self) -> list[int]:
        return [i for i in range(self.poly.bit_length()) if self.poly & (1 << i)]

    @cached_property
    def block(self) -> bytes:
        return self.poly.to_bytes(self.BYTE_LEN, byteorder='little')

    @cached_property
    def b64_block(self) -> str:
        return base64.b64encode(self.block).decode()
