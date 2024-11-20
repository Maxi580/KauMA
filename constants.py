from typing import Final

BLOCK_SIZE: Final[int] = 16
BRUTEFORCE_CHUNK_SIZE: Final[int] = 256
DEFAULT_TIMEOUT: Final[float] = 10.0

FIELD_SIZE: Final[int] = 128
REDUCTION_POLYNOM: Final[int] = (1 << 128) | (1 << 7) | (1 << 2) | (1 << 1) | 1
INVERSE_POWER: Final[int] = (1 << FIELD_SIZE) - 2
SQRT_POWER: Final[int] = 1 << (FIELD_SIZE - 1)

SEA_CONSTANT_BYTES: Final[bytes] = bytes.fromhex("c0ffeec0ffeec0ffeec0ffeec0ffee11")
