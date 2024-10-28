from abc import ABC, abstractmethod


class Base(ABC):
    BYTE_LEN = 16

    @abstractmethod
    def coefficients(self) -> list[int]:
        pass

    @abstractmethod
    def poly(self) -> int:
        pass

    @abstractmethod
    def block(self) -> bytes:
        pass

    @abstractmethod
    def b64_block(self) -> str:
        pass
