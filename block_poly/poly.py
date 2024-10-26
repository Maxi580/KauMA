from block_poly.base import Base
import base64


class Poly(Base):
    """Takes in a Poly and calculates every derived property"""
    def __init__(self, poly: int):
        self._poly: int = poly
        self._coefficients: list[int] = [i for i in range(self._poly.bit_length()) if self._poly & (1 << i)]
        self._block: bytes = self._poly.to_bytes(self.BYTE_LEN, byteorder='little')
        self._b64_block: str = base64.b64encode(self._block).decode()

    def get_poly(self) -> int:
        return self._poly

    def get_b64_block(self) -> str:
        return self._b64_block

    def get_block(self) -> bytes:
        return self._block

    def get_coefficients(self) -> list[int]:
        return self._coefficients
