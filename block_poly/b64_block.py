from block_poly.base import Base
import base64


class B64Block(Base):
    """Takes in a B64 Block and calculates every derived property"""

    def __init__(self, b64_block: str):
        self._b64_block: str = b64_block
        self._block: bytes = base64.b64decode(self._b64_block)
        self._poly: int = int.from_bytes(self._block, byteorder='little')
        self._coefficients: list[int] = [i for i in range(self._poly.bit_length()) if self._poly & (1 << i)]

    def get_b64_block(self) -> str:
        return self._b64_block

    def get_block(self) -> bytes:
        return self._block

    def get_poly(self) -> int:
        return self._poly

    def get_coefficients(self) -> list[int]:
        return self._coefficients
