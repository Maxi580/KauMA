from block_poly.base import Base
import base64
from functools import cached_property


class B64(Base):
    """Calculating every derived value if needed,
       not using cached_properties for efficiency"""
    def __init__(self, b64: str):
        self._b64 = b64

    @property
    def b64(self) -> str:
        return self._b64

    @property
    def block(self) -> bytes:
        return base64.b64decode(self.b64)

    @property
    def xex_poly(self) -> int:
        return int.from_bytes(self.block, byteorder='little')

    @property
    def gcm_poly(self) -> int:
        return self._bit_inverse(self.xex_poly)

    @property
    def xex_coefficients(self) -> list[int]:
        return [i for i in range(self.xex_poly.bit_length()) if self.xex_poly & (1 << i)]

    @property
    def gcm_coefficients(self) -> list[int]:
        return [i for i in range(self.gcm_poly.bit_length()) if self.gcm_poly & (1 << i)]
