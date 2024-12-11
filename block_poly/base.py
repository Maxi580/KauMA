from abc import ABC, abstractmethod


class Base(ABC):
    @staticmethod
    def inverse_bits(poly: int) -> int:
        """Inverses Poly bits to get from xex => gcm or gcm => xex semantic"""
        result = 0
        while poly:
            # Go from left to right until poly is 0
            pos = poly.bit_length() - 1
            byte_pos = pos // 8
            bit_pos = pos % 8

            # Calculate int based on byte pos and inverse bit pos
            byte_offset = 1 << (byte_pos * 8)
            result |= byte_offset << (7 - bit_pos)

            # Clear highest bit
            poly &= ~(1 << pos)
        return result

    @staticmethod
    def inverse_coefficients(coefficients: list[int]) -> list[int]:
        """Inverses Coefficients to get from xex => gcm or gcm => xex semantic"""
        reversed_coefficients = []
        for coefficient in coefficients:
            # For every coefficient calculate its byte and bit pos
            byte_pos = coefficient // 8
            bit_pos = coefficient % 8

            # Calc reversed coefficient based on byte pos and reversed bit pos
            reversed_coefficients.append(byte_pos * 8 + (7 - bit_pos))
        return reversed_coefficients

    @staticmethod
    def coefficients_to_poly(coefficients: list[int]) -> int:
        poly = 0
        # Step by step combine every coefficient into one poly
        for coefficient in coefficients:
            poly |= 1 << coefficient

        return poly

    @staticmethod
    def poly_to_coefficients(poly: int) -> list[int]:
        coefficients = []
        pos = 0
        # Check with bits are set and turned the set ones into coefficients
        while poly:
            if poly & 1:
                coefficients.append(pos)
            poly >>= 1
            pos += 1
        return coefficients

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
    def b64(self) -> str:
        pass
