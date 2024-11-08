from abc import ABC, abstractmethod


class Base(ABC):
    BYTE_LEN = 16

    @staticmethod
    def _gcm_bit_inverse(poly: int) -> int:
        result = 0
        for i in range(poly.bit_length()):
            if poly & (1 << i):
                byte_pos = i // 8
                bit_pos = i % 8

                byte_offset = 1 << (byte_pos * 8)
                result |= byte_offset << (7 - bit_pos)
        return result

    @staticmethod
    def _gcm_coefficient_inverse(coefficients: list[int]) -> list[int]:
        reversed_coefficients = []
        for coefficient in coefficients:
            byte_pos = coefficient // 8
            bit_pos = coefficient % 8

            reversed_coefficients.append(byte_pos * 8 + (7 - bit_pos))
        return reversed_coefficients

    @staticmethod
    def _calculate_poly_from_coefficients(coefficients) -> int:
        poly = 0
        for coefficient in coefficients:
            poly |= 1 << coefficient

        return poly

    @abstractmethod
    def xex_coefficients(self) -> list[int]:
        pass

    @abstractmethod
    def gcm_coefficients(self) -> list[int]:
        pass

    @abstractmethod
    def xex_poly(self) -> int:
        pass

    @abstractmethod
    def gcm_poly(self) -> int:
        pass

    @abstractmethod
    def block(self) -> bytes:
        pass

    @abstractmethod
    def b64_block(self) -> str:
        pass
