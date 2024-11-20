from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from constants import SEA_CONSTANT_BYTES as CONSTANT_BYTES
from utils import xor_bytes


def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    return encryptor.update(plaintext) + encryptor.finalize()


def aes_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    return decryptor.update(ciphertext) + decryptor.finalize()


def sea_encrypt(key: bytes, plaintext: bytes) -> bytes:
    aes_encrypted = aes_encrypt(key, plaintext)

    sea_encrypted = xor_bytes(CONSTANT_BYTES, aes_encrypted)

    return sea_encrypted


def sea_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    sea_decrypted = xor_bytes(CONSTANT_BYTES, ciphertext)

    aes_decrypted = aes_decrypt(key, sea_decrypted)

    return aes_decrypted
