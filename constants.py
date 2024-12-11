from typing import Final

# Used in Actions
XEX_SEMANTIC: Final[str] = "xex"
ENCRYPT_MODE: Final[str] = "encrypt"
DECRYPT_MODE: Final[str] = "decrypt"
AES_128_ALGORITHM: Final[str] = "aes128"

BLOCK_SIZE: Final[int] = 16

BRUTEFORCE_CHUNK_SIZE: Final[int] = 256
DEFAULT_TIMEOUT: Final[float] = 10.0

SEA_CONSTANT_BYTES: Final[bytes] = bytes.fromhex("c0ffeec0ffeec0ffeec0ffeec0ffee11")
