from block_poly.base import Base
import base64
from functools import cached_property


class GCM_Coefficients(Base):
    def __init__(self, coefficients: list[int]):
        self._gcm_coefficients: list[int] = coefficients

    @property
    def gcm_coefficients(self) -> list[int]:
        return self._gcm_coefficients

    @cached_property
    def xex_coefficients(self) -> list[int]:
        return self._gcm_coefficient_inverse(self.gcm_coefficients)

    @cached_property
    def xex_poly(self) -> int:
        return (
            self._calculate_poly_from_coefficients(self.xex_coefficients))

    @cached_property
    def gcm_poly(self) -> int:
        return self._calculate_poly_from_coefficients(self.gcm_coefficients)

    @cached_property
    def block(self) -> bytes:
        return self.xex_poly.to_bytes(self.BYTE_LEN, byteorder='little')

    @cached_property
    def b64_block(self) -> str:
        return base64.b64encode(self.block).decode()
